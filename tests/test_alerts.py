import dataclasses

import pytest
import requests
import responses

from vmtoolkit import alerts
from vmtoolkit.config import ConfigError

WEBHOOK = "https://hooks.slack.invalid/services/FAKE/FAKE/fake-secret-path"


@pytest.fixture
def lab(conn):
    """Two synthetic machines: one open finding with a KEV CVE and an EPSS jump, one fixed finding."""
    conn.executemany("INSERT INTO assets (id, name) VALUES (?, ?)", [(1, "fake-web-01.lab"), (2, "fake-db-01.lab")])
    conn.executemany(
        "INSERT INTO findings (id, fingerprint, asset_id, scanner, rule_id, title, severity, status) "
        "VALUES (?, ?, ?, 'nessus', ?, 'FAKE', 'high', ?)",
        [(1, "a", 1, "1", "open"), (2, "b", 2, "1", "open"), (3, "c", 2, "2", "fixed")],
    )
    conn.executemany("INSERT INTO finding_cves VALUES (?, ?)",
                     [(1, "CVE-2099-0001"), (2, "CVE-2099-0001"), (3, "CVE-2099-0009")])
    conn.executemany("INSERT INTO kev (cve, date_added, ransomware, required_action, first_seen_at) VALUES (?, ?, ?, ?, ?)",
                     [("CVE-2099-0001", "2099-01-10", "Known", "Apply updates.", "x"),
                      ("CVE-2099-0009", "2099-01-10", "Unknown", None, "x")])
    conn.executemany("INSERT INTO epss_history VALUES (?, ?, ?, ?)",
                     [("CVE-2099-0001", "2099-03-01", 0.05, 0.5), ("CVE-2099-0001", "2099-03-02", 0.40, 0.97)])
    conn.commit()
    return conn


def with_alerts(settings, **cfg):
    raw = {**settings.raw, "alerts": {"channels": ["console"], **cfg},
           "email": {"host": "smtp.invalid", "port": 587, "from": "a@example.invalid", "to": ["b@example.invalid"]}}
    return dataclasses.replace(settings, raw=raw)


def test_finds_kev_and_epss_jump_with_reasons(lab):
    found = alerts.find_alerts(lab, epss_jump=0.10)
    assert [a.key for a in found] == ["kev:CVE-2099-0001", "epss:CVE-2099-0001:2099-03-02"]
    assert "Open on: fake-db-01.lab, fake-web-01.lab" in found[0].message
    assert "ransomware" in found[0].message
    assert "from 0.050 (2099-03-01) to 0.400 (2099-03-02), a rise of 0.350" in found[1].message
    assert "threshold of 0.1" in found[1].message


def test_small_epss_change_and_fixed_findings_do_not_alert(lab):
    keys = [a.key for a in alerts.find_alerts(lab, epss_jump=0.5)]
    assert keys == ["kev:CVE-2099-0001"]  # CVE-2099-0009 is on KEV but only on a fixed finding


def test_console_sends_once_and_logs(lab, settings):
    s = with_alerts(settings)
    printed = []
    assert alerts.run_alerts(lab, s, echo=printed.append) == ["console: sent 2 alert(s)"]
    assert "2 new alert(s)" in printed[0]
    assert "CVE-2099-0001" in (s.data_dir / "alerts.log").read_text(encoding="utf-8")
    assert alerts.run_alerts(lab, s, echo=printed.append) == ["console: no new alerts"]


def test_dry_run_records_nothing(lab, settings):
    lines = alerts.run_alerts(lab, with_alerts(settings), dry_run=True)
    assert lines[0] == "console: would send 2 alert(s) (dry run)"
    assert lab.execute("SELECT count(*) FROM alerts_sent").fetchone()[0] == 0


@responses.activate
def test_slack_failure_is_retried_and_hides_webhook(lab, settings, monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", WEBHOOK)
    s = with_alerts(settings, channels=["slack"])
    responses.post(WEBHOOK, body=requests.exceptions.ConnectionError(f"Max retries exceeded with url: {WEBHOOK}"))
    lines = alerts.run_alerts(lab, s)
    assert lines == ["slack: failed (ConnectionError); will retry next run"]
    assert "fake-secret-path" not in "\n".join(lines)

    responses.replace(responses.POST, WEBHOOK, json={})
    assert alerts.run_alerts(lab, s) == ["slack: sent 2 alert(s)"]
    assert "CVE-2099-0001" in responses.calls[-1].request.body.decode()


def test_slack_without_webhook_is_a_config_error(lab, settings):
    with pytest.raises(ConfigError, match="SLACK_WEBHOOK_URL"):
        alerts.run_alerts(lab, with_alerts(settings, channels=["slack"]))


class FakeSMTP:
    sent = []

    def __init__(self, host, port, timeout):
        self.calls = [("connect", host, port)]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        FakeSMTP.sent.append(self.calls)

    def starttls(self):
        self.calls.append(("starttls",))

    def login(self, user, password):
        self.calls.append(("login", user))

    def send_message(self, msg):
        self.calls.append(("send", msg["To"], msg.get_content()))


def test_email(lab, settings, monkeypatch):
    monkeypatch.setattr(alerts.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("SMTP_USERNAME", "fake-user")
    monkeypatch.setenv("SMTP_PASSWORD", "fake-pass")
    FakeSMTP.sent.clear()
    assert alerts.run_alerts(lab, with_alerts(settings, channels=["email"])) == ["email: sent 2 alert(s)"]
    calls = FakeSMTP.sent[0]
    assert calls[:3] == [("connect", "smtp.invalid", 587), ("starttls",), ("login", "fake-user")]
    assert calls[3][1] == "b@example.invalid" and "CVE-2099-0001" in calls[3][2]


def test_channels_are_tracked_separately(lab, settings, monkeypatch):
    monkeypatch.setattr(alerts.smtplib, "SMTP", FakeSMTP)
    alerts.run_alerts(lab, with_alerts(settings), echo=lambda t: None)
    lines = alerts.run_alerts(lab, with_alerts(settings, channels=["console", "email"]), echo=lambda t: None)
    assert lines == ["console: no new alerts", "email: sent 2 alert(s)"]


def test_unknown_channel(lab, settings):
    with pytest.raises(ConfigError, match="pager"):
        alerts.run_alerts(lab, with_alerts(settings, channels=["pager"]))
