import logging

import pytest

from vmtoolkit.config import ConfigError, RedactSecrets, get_secret, load_settings


def test_defaults_without_config_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = load_settings()
    assert s.data_dir == tmp_path / "data"
    assert s.db_path == tmp_path / "data" / "vmt.db"
    assert s.section("import")["include_info"] is False


def test_relative_paths_resolve_against_config_folder(tmp_path):
    sub = tmp_path / "conf"
    sub.mkdir()
    (sub / "config.toml").write_text('[paths]\ndata_dir = "store"\n', encoding="utf-8")
    s = load_settings(sub / "config.toml")
    assert s.data_dir == sub.resolve() / "store"
    assert s.section("nessus")["url"] == "https://localhost:8834"


def test_missing_explicit_config_is_an_error(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(tmp_path / "nope.toml")


def test_invalid_toml_is_reported(tmp_path):
    (tmp_path / "config.toml").write_text("[paths\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_settings(tmp_path / "config.toml")


def test_env_file_is_loaded(tmp_path):
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    (tmp_path / ".env").write_text("NESSUS_ACCESS_KEY=fake-access-123\n", encoding="utf-8")
    load_settings(tmp_path / "config.toml")
    assert get_secret("NESSUS_ACCESS_KEY") == "fake-access-123"


def test_required_secret_missing():
    with pytest.raises(ConfigError, match="NESSUS_SECRET_KEY is not set"):
        get_secret("NESSUS_SECRET_KEY", required=True)


def test_secrets_are_redacted_in_logs(monkeypatch, caplog):
    monkeypatch.setenv("NESSUS_SECRET_KEY", "fake-secret-value-xyz")
    get_secret("NESSUS_SECRET_KEY")
    logger = logging.getLogger("redact-test")
    logger.addFilter(RedactSecrets())
    with caplog.at_level(logging.INFO):
        logger.info("header was %s", "secretKey=fake-secret-value-xyz")
    assert "fake-secret-value-xyz" not in caplog.text
    assert "secretKey=***" in caplog.text
