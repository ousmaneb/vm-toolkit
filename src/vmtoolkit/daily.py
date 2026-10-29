"""`vmt daily`: pull from Nessus, refresh threat data, re-rank, re-plan, alert, and write the weekly reports.

Each step runs as its own `vmt` command, so one step crashing can't take the others down, and the log
shows exactly what each printed.
"""

import os
import re
import sqlite3
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from .config import Settings
from .db import utcnow
from .report import report_path

WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
STEP_TIMEOUT = 2 * 60 * 60

# (name, vmt arguments). Only a Nessus failure stops the run: everything after it would just
# reprocess yesterday's data and report it as today's.
PULL = ("Pull from Nessus", ["nessus", "pull"])
PROCESS = [
    ("Enrich CVEs", ["enrich"]),
    ("Find duplicates", ["dedupe"]),
    ("Prioritize", ["prioritize", "--top", "10"]),
    ("Patch plan", ["plan"]),
    ("Deadline forecast", ["forecast", "--backtest-days", "0"]),
    ("Save history", ["history", "save"]),
]
MONITOR = ("GitHub and news", ["monitor"])
# KEV and EPSS were refreshed by Enrich a moment ago.
ALERT = ("Alerts", ["alert", "--no-refresh"])
REPORT = ("Weekly reports", ["report"])

Runner = Callable[[list[str]], tuple[int, str]]


def vmt_runner(settings: Settings) -> Runner:
    base = [sys.executable, "-m", "vmtoolkit"]
    config = settings.base_dir / "config.toml"
    if config.exists():
        base += ["--config", str(config)]
    base += ["--db", str(settings.db_path)]

    def run(args: list[str]) -> tuple[int, str]:
        try:
            done = subprocess.run(base + args, cwd=settings.base_dir, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=STEP_TIMEOUT,
                                  env=dict(os.environ, NO_COLOR="1", COLUMNS="160"))
        except subprocess.TimeoutExpired:
            return 1, f"Stopped after {STEP_TIMEOUT // 3600} hours.\n"
        return done.returncode, done.stdout + done.stderr

    return run


def report_due(settings: Settings, today: datetime) -> bool:
    weekday = str(settings.section("daily").get("report_weekday", "monday")).lower()
    if weekday in WEEKDAYS and today.weekday() == WEEKDAYS.index(weekday):
        return True
    # Catches a missed report day, for example when the computer was off.
    newest = report_path(settings, "ceo", today)
    pattern = re.compile(r"\d{4}-\d{2}-\d{2}" + re.escape(newest.name[10:]) + "$")
    dates = [datetime.strptime(p.name[:10], "%Y-%m-%d") for p in newest.parent.glob("*.pdf") if pattern.match(p.name)]
    return not dates or today.replace(tzinfo=None) - max(dates) >= timedelta(days=7)


def run_daily(conn: sqlite3.Connection, settings: Settings, run: Runner | None = None,
              now: datetime | None = None, echo=print) -> str:
    """Returns "ok" or "failed". Every step's output goes to data/logs/daily-<date>.log."""
    run = run or vmt_runner(settings)
    now = now or datetime.now().astimezone()
    cfg = settings.section("daily")
    log_path = settings.data_dir / "logs" / f"daily-{now:%Y-%m-%d}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with conn:
        run_id = conn.execute("INSERT INTO daily_runs (started_at, status, log_path) VALUES (?, 'running', ?)",
                              (utcnow(), str(log_path))).lastrowid

    failed: list[str] = []
    errors: list[str] = []

    def step(name: str, args: list[str]) -> str | None:
        """The step's output, or None if it failed."""
        echo(f"{name}...")
        code, output = run(args)
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"=== {datetime.now().astimezone():%Y-%m-%d %H:%M:%S} {name}: vmt {' '.join(args)}\n")
            log.write(output if output.endswith("\n") or not output else output + "\n")
            log.write(f"=== exit code {code}\n\n")
        if code != 0:
            failed.append(name)
            last = next((line for line in reversed(output.strip().splitlines()) if line.strip()), "no output")
            errors.append(f"{name}: {last}")
            echo(f"  failed: {last}")
            return None
        return output

    pulled = step(*PULL) is not None if cfg.get("nessus", True) else True
    if pulled:
        for name, args in PROCESS:
            step(name, args)
        if cfg.get("monitor", True):
            step(*MONITOR)
    else:
        echo("  Skipping the rest, so stale data isn't reported as today's.")

    status = "failed" if failed else "ok"
    message = ""
    if failed:
        message = (f"The automatic daily run on {now:%Y-%m-%d} had problems. " + " ".join(errors)
                   + (" Nothing after the Nessus pull ran." if not pulled else "")
                   + f" Details: {log_path}")
    # Recorded before the alert step, so the alert step sends the failure too.
    with conn:
        conn.execute("UPDATE daily_runs SET status = ?, failed_steps = ?, message = ? WHERE id = ?",
                     (status, ", ".join(failed), message, run_id))
    step(*ALERT)

    reports = ""
    if failed:
        echo("Weekly reports skipped: the data isn't fully up to date.")
    elif report_due(settings, now):
        output = step(*REPORT)
        if output:
            reports = ", ".join(line.split(": ", 1)[1] for line in output.splitlines()
                                if line.startswith(("CEO report: ", "CISO report: ")))
    status = "failed" if failed else "ok"
    with conn:
        conn.execute("UPDATE daily_runs SET status = ?, failed_steps = ?, finished_at = ?, reports = ? WHERE id = ?",
                     (status, ", ".join(failed), utcnow(), reports, run_id))
    echo(f"Daily run {status}. Log: {log_path}")
    return status


def recent_runs(conn: sqlite3.Connection, limit: int = 10) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM daily_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def log_tail(path: str | Path, lines: int = 200) -> str:
    path = Path(path)
    return "\n".join(path.read_text(encoding="utf-8").splitlines()[-lines:]) if path.exists() else ""
