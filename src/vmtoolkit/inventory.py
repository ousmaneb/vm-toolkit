"""The machine inventory: what each machine is, who owns it, how exposed it is, and when it was last scanned.

A machine that scans used to reach but no longer do is a blind spot: its findings look stable only
because nobody is looking. Those are flagged as stale and alerted on once.
"""

import sqlite3
from datetime import datetime

from .assets import asset_config
from .config import Settings
from .db import parse_iso, utcnow
from .report import is_open, is_overdue, load_findings


def stale_days(settings: Settings) -> int:
    return int(settings.section("coverage").get("stale_days", 14))


def machines(conn: sqlite3.Connection, settings: Settings, now: datetime | None = None) -> list[dict]:
    now = now or parse_iso(utcnow())
    sla = {k: int(v) for k, v in settings.section("sla_days").items()}
    counts: dict[str, dict[str, int]] = {}
    for f in load_findings(conn):
        if is_open(f, now):
            c = counts.setdefault(f.machine, {"open": 0, "critical_high": 0, "overdue": 0})
            c["open"] += 1
            c["critical_high"] += f.severity in ("critical", "high")
            c["overdue"] += is_overdue(f, sla, now)
    limit = stale_days(settings)
    out = []
    for r in conn.execute(
            """SELECT a.name, a.ip, a.os, max(s.finished_at) AS last_scanned
               FROM assets a LEFT JOIN scan_hosts h ON h.asset_id = a.id LEFT JOIN scans s ON s.id = h.scan_id
               GROUP BY a.id ORDER BY a.name"""):
        cfg = asset_config(settings, r["name"], r["ip"])
        last = parse_iso(r["last_scanned"]) if r["last_scanned"] else None
        days = (now - last).days if last else None
        out.append({
            "machine": r["name"], "ip": r["ip"], "os": r["os"], "importance": cfg.criticality,
            "internet_facing": cfg.internet_facing, "owner": cfg.owner, "team": cfg.team,
            "configured": cfg.matched is not None, **counts.get(r["name"], {"open": 0, "critical_high": 0, "overdue": 0}),
            "last_scanned": last, "days_since_scan": days, "stale": days is not None and days > limit,
        })
    return out


def stale_alerts(conn: sqlite3.Connection, settings: Settings) -> list[tuple[str, str]]:
    """(alert key, message) per machine that has stopped being scanned; sent once per gap."""
    out = []
    for m in machines(conn, settings):
        if m["stale"]:
            who = f" Owner: {m['owner']}." if m["owner"] else ""
            out.append((f"stale:{m['machine']}:{m['last_scanned']:%Y-%m-%d}",
                        f"{m['machine']} hasn't been scanned for {m['days_since_scan']} days (last scan "
                        f"{m['last_scanned']:%Y-%m-%d}). Its {m['open']} open findings may be out of date; check "
                        f"that it's still in a scan policy and reachable.{who}"))
    return out
