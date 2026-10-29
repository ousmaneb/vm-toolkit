"""`vmt serve`: the container entry point. Runs the dashboard, and `vmt daily` (which ends with a backup) once a day.

One process for both, because the dashboard and the daily run must share the same data volume, and
most container platforms attach a volume to one service only.
"""

import logging
import signal
import subprocess
import sys
import time
from datetime import date, datetime
from pathlib import Path

from .config import Settings
from .schedule import parse_time

log = logging.getLogger(__name__)
CHECK_EVERY = 30  # seconds


# Set per mode, never at the top level: a top-level theme option stops the app following the system's
# light or dark setting.
_MODES = {
    "light": {"primaryColor": "#2F6FED", "backgroundColor": "#F7F9FC", "secondaryBackgroundColor": "#EDF1F7",
              "textColor": "#13233F", "borderColor": "#DCE3ED", "linkColor": "#2F6FED",
              "font": "IBM Plex Sans, sans-serif", "headingFont": "IBM Plex Sans, sans-serif",
              "sidebar.backgroundColor": "#0B1F3A", "sidebar.secondaryBackgroundColor": "#163463",
              "sidebar.textColor": "#DCE6F5", "sidebar.primaryColor": "#8FB3FF", "sidebar.borderColor": "#24457A"},
    "dark": {"primaryColor": "#5B8DF2", "linkColor": "#8FB3FF",
             "font": "IBM Plex Sans, sans-serif", "headingFont": "IBM Plex Sans, sans-serif",
             "sidebar.backgroundColor": "#0A1628", "sidebar.secondaryBackgroundColor": "#14294A",
             "sidebar.textColor": "#DCE6F5", "sidebar.primaryColor": "#8FB3FF", "sidebar.borderColor": "#1F3A66"},
}
THEME = [part for mode, opts in _MODES.items() for key, value in opts.items()
         for part in (f"--theme.{mode}.{key}", value)]


def dashboard_command(settings: Settings, port: int, host: str, db_path: Path | None = None) -> list[str]:
    app_path = Path(__file__).parent / "dashboard" / "app.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(app_path), "--server.port", str(port),
           "--server.address", host,
           # Headless skips Streamlit's first-run email prompt, which would otherwise block here.
           "--server.headless", "true", "--browser.gatherUsageStats", "false",
           # Fonts are served from dashboard/static, not a third-party font service.
           "--server.enableStaticServing", "true",
           "--client.toolbarMode", "minimal", *THEME, "--", "--db", str(db_path or settings.db_path)]
    if (settings.base_dir / "config.toml").exists():
        cmd += ["--config", str(settings.base_dir / "config.toml")]
    return cmd


def due(now: datetime, at: str, last_run: date | None) -> bool:
    """True once the clock passes `at` (HH:MM, local time) on a day the routine hasn't run yet."""
    hour, minute = parse_time(at)
    return now.date() != last_run and (now.hour, now.minute) >= (hour, minute)


def _vmt(settings: Settings, *args: str) -> int:
    cmd = [sys.executable, "-m", "vmtoolkit"]
    if (settings.base_dir / "config.toml").exists():
        cmd += ["--config", str(settings.base_dir / "config.toml")]
    return subprocess.call(cmd + list(args), cwd=settings.base_dir)


def serve(settings: Settings, port: int, host: str = "0.0.0.0") -> int:
    from . import db
    from .users import bootstrap

    conn = db.connect(settings.db_path)
    try:
        message = bootstrap(conn)
    finally:
        conn.close()
    if message:
        log.info(message)

    at = str(settings.section("daily").get("time", "07:00"))
    parse_time(at)
    marker = settings.data_dir / "last-daily-run"
    last_run = date.fromisoformat(marker.read_text().strip()) if marker.exists() else None

    dashboard = subprocess.Popen(dashboard_command(settings, port, host))
    log.info("Dashboard on %s:%s. Daily routine at %s local time.", host, port, at)

    def stop(signum, frame):
        dashboard.terminate()
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while dashboard.poll() is None:
        if due(datetime.now(), at, last_run):
            last_run = datetime.now().date()
            # Written first, so a crash mid-run doesn't start the run again in a loop after a restart.
            marker.write_text(last_run.isoformat())
            log.info("Starting the daily routine.")
            code = _vmt(settings, "daily")
            log.info("Daily routine finished with exit code %s.", code)
        time.sleep(CHECK_EVERY)
    log.error("The dashboard stopped (exit code %s).", dashboard.returncode)
    return dashboard.returncode or 1
