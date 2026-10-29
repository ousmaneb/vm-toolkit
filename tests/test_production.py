import sys
from datetime import date, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vmtoolkit import db
from vmtoolkit.backup import backup
from vmtoolkit.cli import app
from vmtoolkit.config import ConfigError, load_settings
from vmtoolkit.serve import due
from vmtoolkit.users import (MAX_FAILURES, WRONG, add_user, authenticate, bootstrap, check_password, hash_password,
                             set_password)

GOOD = "correct-horse-battery"


def test_passwords_are_salted_hashes():
    first, second = hash_password(GOOD), hash_password(GOOD)
    assert first != second and GOOD not in first
    assert check_password(GOOD, first) and not check_password("wrong", first)


def test_sign_in_and_lockout(conn):
    add_user(conn, "Alice", GOOD)
    assert authenticate(conn, "alice", GOOD) == (True, "")
    # The same message for an unknown user as for a wrong password.
    assert authenticate(conn, "nobody", GOOD) == (False, WRONG)
    for _ in range(MAX_FAILURES):
        assert authenticate(conn, "alice", "wrong-password") == (False, WRONG)
    ok, message = authenticate(conn, "alice", GOOD)
    assert not ok and message.startswith("Too many wrong passwords")
    set_password(conn, "alice", "another-good-password")  # also clears the lockout
    assert authenticate(conn, "alice", "another-good-password")[0]


@pytest.mark.parametrize("username, password", [("bob", "short"), ("bad name", GOOD), ("", GOOD)])
def test_weak_accounts_are_refused(conn, username, password):
    with pytest.raises(ConfigError):
        add_user(conn, username, password)


def test_first_account_from_environment_only_once(conn, monkeypatch):
    monkeypatch.setenv("VMT_ADMIN_USER", "admin")
    monkeypatch.setenv("VMT_ADMIN_PASSWORD", GOOD)
    assert bootstrap(conn).startswith("Created the first dashboard account, admin")
    monkeypatch.setenv("VMT_ADMIN_PASSWORD", "changed-in-the-env-later")
    assert bootstrap(conn) is None
    assert authenticate(conn, "admin", GOOD)[0]


def test_config_from_environment(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VMT_CONFIG_TOML", '[nessus]\nurl = "https://nessus.tailnet.test:8834"\n')
    monkeypatch.setenv("VMT_DATA_DIR", str(tmp_path / "volume"))
    s = load_settings()
    assert s.section("nessus")["url"] == "https://nessus.tailnet.test:8834"
    assert s.db_path == tmp_path / "volume" / "vmt.db"
    monkeypatch.setenv("VMT_CONFIG_TOML", "not = [valid")
    with pytest.raises(ConfigError, match="VMT_CONFIG_TOML is not valid TOML"):
        load_settings()


def test_nessus_proxy_and_ca_from_secrets(settings, monkeypatch):
    from vmtoolkit.nessus import NessusClient

    settings.raw["nessus"]["proxy"] = "http://localhost:1055"
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "fake-access")
    monkeypatch.setenv("NESSUS_SECRET_KEY", "fake-secret")
    monkeypatch.setenv("NESSUS_CA_CERT", "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----")
    client = NessusClient.from_settings(settings)
    assert client.session.proxies["https"] == "http://localhost:1055"
    ca = Path(client.session.verify)
    assert ca.read_text().startswith("-----BEGIN CERTIFICATE-----")
    if sys.platform != "win32":  # Windows has no Unix permission bits
        assert oct(ca.stat().st_mode)[-3:] == "600"


def test_daily_routine_timing():
    morning, evening = datetime(2099, 3, 2, 6, 59), datetime(2099, 3, 2, 19, 0)
    assert not due(morning, "07:00", None)
    assert due(evening, "07:00", None)  # catches up after a restart or a late deploy
    assert not due(evening, "07:00", date(2099, 3, 2))
    assert due(datetime(2099, 3, 3, 7, 0), "07:00", date(2099, 3, 2))


def test_backups_are_dated_and_pruned(settings):
    db.connect(settings.db_path).close()
    for day in range(1, 5):
        target, removed = backup(settings, keep=2, now=datetime(2099, 3, day))
    assert target.name == "vmt-2099-03-04.db" and len(removed) == 1
    assert sorted(p.name for p in (settings.data_dir / "backups").iterdir()) == ["vmt-2099-03-03.db", "vmt-2099-03-04.db"]


def test_no_demo_data_in_production(settings, monkeypatch):
    monkeypatch.setenv("VMT_ENV", "production")
    out = CliRunner().invoke(app, ["--config", str(settings.base_dir / "config.toml"), "fake-data"])
    assert out.exit_code != 0 and not (settings.data_dir / "fake.db").exists()


def test_dashboard_requires_sign_in_in_production(settings, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("VMT_ENV", "production")
    db.connect(settings.db_path).close()
    page = Path(__file__).parent.parent / "src" / "vmtoolkit" / "dashboard" / "app.py"
    monkeypatch.setattr("sys.argv", ["app.py", "--config", str(settings.base_dir / "config.toml")])
    at = testing.AppTest.from_file(str(page), default_timeout=60).run()
    assert at.title[0].value == "Sign in" and not at.metric
    at.text_input[0].input("nobody")
    at.text_input[1].input("wrong-password-123")
    at.button[0].click().run()
    assert at.error[0].value == WRONG and at.title[0].value == "Sign in"


def test_sessions_survive_reloads_and_end_cleanly(conn, monkeypatch):
    from vmtoolkit import users

    add_user(conn, "alice", GOOD)
    token = users.start_session(conn, "alice")
    assert users.session_user(conn, token) == "alice"
    assert token not in str(conn.execute("SELECT * FROM sessions").fetchall()[0][:])  # only a hash is stored
    assert users.session_user(conn, "made-up-token") is None and users.session_user(conn, None) is None
    users.end_session(conn, token)
    assert users.session_user(conn, token) is None

    token = users.start_session(conn, "alice")
    set_password(conn, "alice", "a-brand-new-password")  # a new password signs everyone out
    assert users.session_user(conn, token) is None

    token = users.start_session(conn, "alice")
    monkeypatch.setattr(users, "utcnow", lambda: "2999-01-01T00:00:00Z")
    assert users.session_user(conn, token) is None  # expired


def test_sign_in_throttle_per_address():
    from vmtoolkit.dashboard.auth import Throttle

    throttle = Throttle(limit=3, window=60)
    for t in (0, 1, 2):
        assert not throttle.blocked("198.51.100.7", now=t)
        throttle.failed("198.51.100.7", now=t)
    assert throttle.blocked("198.51.100.7", now=3)
    assert not throttle.blocked("198.51.100.8", now=3)
    assert not throttle.blocked("198.51.100.7", now=63)  # the window has passed


def test_client_address_behind_a_proxy(monkeypatch):
    from vmtoolkit.dashboard.auth import client_address

    # The client can put anything at the start of the header; the proxy appends the real address last.
    assert client_address({"X-Forwarded-For": "1.2.3.4, 198.51.100.7"}, "10.0.0.2") == "198.51.100.7"
    monkeypatch.setenv("VMT_PROXY_HOPS", "2")
    assert client_address({"X-Forwarded-For": "1.2.3.4, 198.51.100.7, 10.0.0.9"}, "10.0.0.2") == "198.51.100.7"
    assert client_address({}, "192.0.2.5") == "192.0.2.5"
