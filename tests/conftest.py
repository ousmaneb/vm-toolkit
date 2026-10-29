"""Shared fixtures. All hosts, IPs and findings here are synthetic (192.0.2.0/24 is a documentation range)."""

from pathlib import Path

import pytest

from vmtoolkit import db
from vmtoolkit import llm_provider
from vmtoolkit.config import load_settings

FIXTURES = Path(__file__).parent / "fixtures"
SECRET_VARS = ("NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY", "NESSUS_USERNAME", "NESSUS_PASSWORD", "NVD_API_KEY",
               "SLACK_WEBHOOK_URL", "SMTP_USERNAME", "SMTP_PASSWORD",
               "JIRA_EMAIL", "JIRA_API_TOKEN", "SN_USERNAME", "SN_PASSWORD", "LLM_API_KEY",
               "GITHUB_TOKEN")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in SECRET_VARS + ("VMT_CONFIG",):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def settings(tmp_path):
    (tmp_path / "config.toml").write_text(
        '[paths]\ndata_dir = "data"\n[nessus]\nurl = "https://nessus.test:8834"\n'
        f'[llm]\nprovider = "{llm_provider.NAME}"\nmodel = "test-model"\n[llm.prices]\n"test-model" = [4.0, 20.0]\n',
        encoding="utf-8"
    )
    return load_settings(tmp_path / "config.toml")


@pytest.fixture
def conn(settings):
    c = db.connect(settings.db_path)
    yield c
    c.close()

