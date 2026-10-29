"""Day-by-day history: headline numbers, and which rankings and plans were current on a given day.

Rankings and plans are saved by prioritize() and plan() themselves. This module saves the daily
snapshot of headline numbers, rebuilds snapshots for days before history was kept, and reads it all back.
"""

import sqlite3
from datetime import timedelta

from .config import Settings
from .db import parse_iso, utcnow
from .report import _kev, build, load_findings, snapshot


def save_snapshot(conn: sqlite3.Connection, settings: Settings) -> str:
    now = parse_iso(utcnow())
    d = build(conn, settings, days=1, now=now)
    day = now.strftime("%Y-%m-%d")
    with conn:
        conn.execute(
            """INSERT OR REPLACE INTO history_snapshots
               (day, taken_at, open, critical_high, overdue, known_exploited, new, fixed, on_time_rate,
                total_risk, status, status_reason, reconstructed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (day, utcnow(), d.now.open, d.now.critical_high, d.now.overdue, d.now.known_exploited, d.new, d.fixed,
             d.on_time_rate, d.total_risk, d.status, d.status_reason))
    return (f"Saved {day}: {d.now.open} open, {d.now.critical_high} critical or high, {d.now.overdue} past deadline, "
            f"{d.now.known_exploited} actively exploited. Status {d.status.upper()}.")


def backfill(conn: sqlite3.Connection, settings: Settings, days: int) -> str:
    """Rebuild counts for past days that have no snapshot. Days with a real snapshot are left alone."""
    sla = {k: int(v) for k, v in settings.section("sla_days").items()}
    findings, kev = load_findings(conn), _kev(conn)
    if not findings:
        return "No findings, so nothing to rebuild."
    first = min(f.first_seen for f in findings)
    have = {r[0] for r in conn.execute("SELECT day FROM history_snapshots")}
    # End of each day, so a day's snapshot includes everything found and fixed that day.
    today_end = parse_iso(utcnow()[:10] + "T23:59:59Z")
    rows = []
    for back in range(days, 0, -1):
        at = today_end - timedelta(days=back)
        day = at.strftime("%Y-%m-%d")
        if day in have or at < first:
            continue
        s = snapshot(findings, kev, sla, at)
        day_start = at - timedelta(days=1)
        new = sum(day_start < f.first_seen <= at for f in findings)
        fixed = sum(f.fixed_at is not None and day_start < f.fixed_at <= at for f in findings)
        rows.append((day, utcnow(), s.open, s.critical_high, s.overdue, s.known_exploited, new, fixed))
    with conn:
        conn.executemany(
            """INSERT INTO history_snapshots (day, taken_at, open, critical_high, overdue, known_exploited, new,
                                              fixed, reconstructed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""", rows)
    return (f"Rebuilt {len(rows)} past days from first-seen and fixed dates. Rebuilt days have counts only: the "
            "status, on-time rate and risk weren't recorded at the time.")


def snapshots(conn: sqlite3.Connection, days: int | None = None) -> list[sqlite3.Row]:
    if days is None:
        return conn.execute("SELECT * FROM history_snapshots ORDER BY day").fetchall()
    since = (parse_iso(utcnow()) - timedelta(days=days)).strftime("%Y-%m-%d")
    return conn.execute("SELECT * FROM history_snapshots WHERE day >= ? ORDER BY day", (since,)).fetchall()


def ranking_on(conn: sqlite3.Connection, day: str, limit: int = 10) -> list[sqlite3.Row]:
    """The ranking current on that day: the latest one saved on or before it."""
    return conn.execute(
        """SELECT h.day, h.rank, h.score, f.id AS finding, a.name AS machine, f.severity, f.title,
                  CASE WHEN f.fixed_at IS NOT NULL THEN substr(f.fixed_at, 1, 10) END AS fixed_on
           FROM priority_history h JOIN findings f ON f.id = h.finding_id JOIN assets a ON a.id = f.asset_id
           WHERE h.day = (SELECT max(day) FROM priority_history WHERE day <= ?)
           ORDER BY h.rank LIMIT ?""", (day, limit)).fetchall()


def plan_on(conn: sqlite3.Connection, day: str) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT * FROM plan_history WHERE day = (SELECT max(day) FROM plan_history WHERE day <= ?)
           ORDER BY rank""", (day,)).fetchall()
