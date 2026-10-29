"""Runs `vmt` commands for the dashboard's tool pages. Kept free of Streamlit so it can be tested directly."""

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from vmtoolkit.config import Settings

# What each .env key unlocks. A tool is ready when every key in one of its rows is set.
SECRETS = [
    ("Nessus connector (API keys)", ["NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY"]),
    ("Nessus connector (username and password)", ["NESSUS_USERNAME", "NESSUS_PASSWORD"]),
    ("Faster NVD lookups (optional)", ["NVD_API_KEY"]),
    ("Slack alerts", ["SLACK_WEBHOOK_URL"]),
    ("Email alerts", ["SMTP_USERNAME", "SMTP_PASSWORD"]),
    ("Jira tickets", ["JIRA_EMAIL", "JIRA_API_TOKEN"]),
    ("ServiceNow tickets", ["SN_USERNAME", "SN_PASSWORD"]),
    ("LLM features: extract --llm, triage, ask", ["LLM_API_KEY"]),
    ("Faster GitHub searches for monitor (optional)", ["GITHUB_TOKEN"]),
]


def secret_status() -> list[tuple[str, dict[str, bool]]]:
    """Which keys are set, by name only. Values are never read into the page."""
    return [(purpose, {name: bool(os.environ.get(name, "").strip()) for name in names})
            for purpose, names in SECRETS]


def database_choices(settings: Settings, current: Path) -> list[Path]:
    choices = [current, settings.data_dir / "vmt.db", *sorted(settings.data_dir.glob("*.db"))]
    seen, unique = set(), []
    for path in choices:
        key = path.resolve()
        if key not in seen:
            seen.add(key)
            unique.append(key)
    return unique


def base_command(settings: Settings, db_path: Path, offline: bool) -> list[str]:
    cmd = [sys.executable, "-m", "vmtoolkit"]
    config = settings.base_dir / "config.toml"
    if config.exists():
        cmd += ["--config", str(config)]
    cmd += ["--db", str(db_path)]
    if offline:
        cmd.append("--offline")
    return cmd


def run(cmd: list[str], cwd: Path, on_line: Callable[[str], None], user: str | None = None) -> int:
    env = dict(os.environ, NO_COLOR="1", TERM="dumb", COLUMNS="160", PYTHONUNBUFFERED="1")
    if user:
        env["VMT_USER"] = user  # so records like risk acceptances name the person, not the service account
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    try:
        for line in proc.stdout:
            on_line(line)
        return proc.wait()
    finally:
        # Streamlit stops the script when the user leaves the page; don't leave the command running unseen.
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def save_upload(folder: Path, name: str, data: bytes) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    # Keep only the file name: the deps checker recognises files by name, and the browser's name can't be trusted.
    name = Path(name).name
    path = folder / (name if name not in ("", ".", "..") else "upload")
    path.write_bytes(data)
    return path


def split_ids(text: str) -> list[str]:
    return [part for part in text.replace(",", " ").split() if part]
