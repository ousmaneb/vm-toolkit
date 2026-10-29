"""Root causes: which teams, which software and which repeat problems keep the backlog where it is.

Built from the same counts as the dashboard and reports. A finding "came back" when a scan saw it, a
later scan of the same machine by the same scanner didn't, and a scan after that saw it again: the
usual sign of a fix applied to a running machine but not to the image or template it is rebuilt from.
"""

import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from statistics import median

from .assets import asset_config
from .config import Settings
from .db import parse_iso, utcnow
from .report import LOOKBACK_DAYS, _days, _plural, is_open, is_overdue, load_findings

NO_TEAM = "No team set"


def returns(conn: sqlite3.Connection) -> dict[int, int]:
    """Finding id -> how many times it came back after a scan of its machine stopped reporting it."""
    reached: dict[tuple[int, str], list[int]] = defaultdict(list)
    for r in conn.execute("""SELECT h.asset_id, s.scanner, s.id FROM scan_hosts h JOIN scans s ON s.id = h.scan_id
                             ORDER BY s.finished_at, s.id"""):
        reached[(r["asset_id"], r["scanner"])].append(r["id"])
    seen: dict[int, set[int]] = defaultdict(set)
    for r in conn.execute("SELECT finding_id, scan_id FROM observations"):
        seen[r["finding_id"]].add(r["scan_id"])
    out = {}
    for r in conn.execute("SELECT id, asset_id, scanner FROM findings WHERE severity != 'info'"):
        observed = seen.get(r["id"])
        if not observed:
            continue
        count, state = 0, None  # state: None before first sighting, then True (seen) / False (missed)
        for scan_id in reached.get((r["asset_id"], r["scanner"]), []):
            hit = scan_id in observed
            if hit and state is False:
                count += 1
            if hit or state is not None:
                state = hit
        if count:
            out[r["id"]] = count
    return out


def _software(row: sqlite3.Row) -> str:
    """The thing that has to change: the package when the scanner names one, otherwise its fix text."""
    if row["package"]:
        return row["package"]
    if row["solution"]:
        return re.sub(r"\s+", " ", row["solution"]).strip().rstrip(".")[:80]
    return row["title"][:80]


def analyse(conn: sqlite3.Connection, settings: Settings, now: datetime | None = None) -> dict:
    now = now or parse_iso(utcnow())
    sla = {k: int(v) for k, v in settings.section("sla_days").items()}
    since = now - timedelta(days=LOOKBACK_DAYS)
    findings = {f.id: f for f in load_findings(conn)}
    came_back = returns(conn)
    meta = {r["id"]: r for r in conn.execute(
        "SELECT f.id, f.package, f.solution, f.title, a.name AS machine, a.ip FROM findings f "
        "JOIN assets a ON a.id = f.asset_id")}
    teams_of: dict[str, str] = {}

    def team(machine: str) -> str:
        if machine not in teams_of:
            row = next((m for m in meta.values() if m["machine"] == machine), None)
            teams_of[machine] = asset_config(settings, machine, row["ip"] if row else None).team or NO_TEAM
        return teams_of[machine]

    teams: dict[str, dict] = defaultdict(lambda: {"machines": set(), "open": 0, "overdue": 0, "fixed": 0,
                                                  "on_time": 0, "fix_days": [], "returned": 0, "oldest": 0})
    software: dict[str, dict] = defaultdict(lambda: {"machines": set(), "open": 0, "overdue": 0,
                                                     "fixed": 0, "returned": 0})
    for fid, f in findings.items():
        t, s = teams[team(f.machine)], software[_software(meta[fid])]
        recent_fix = f.fixed_at is not None and since < f.fixed_at <= now
        if not (is_open(f, now) or recent_fix):
            continue
        t["machines"].add(f.machine)
        s["machines"].add(f.machine)
        if is_open(f, now):
            t["open"] += 1
            s["open"] += 1
            t["oldest"] = max(t["oldest"], int(_days(f.first_seen, now)))
            if is_overdue(f, sla, now):
                t["overdue"] += 1
                s["overdue"] += 1
        else:
            t["fixed"] += 1
            s["fixed"] += 1
            days = _days(f.first_seen, f.fixed_at)
            t["fix_days"].append(days)
            t["on_time"] += f.severity in sla and days <= sla[f.severity]
        if fid in came_back:
            t["returned"] += 1
            s["returned"] += 1

    total_overdue = sum(t["overdue"] for t in teams.values()) or 1
    team_rows = [{
        "team": name, "machines": len(t["machines"]), "open": t["open"], "overdue": t["overdue"],
        "share_of_overdue": t["overdue"] / total_overdue, "fixed_90d": t["fixed"],
        "on_time": t["on_time"] / t["fixed"] if t["fixed"] else None,
        "median_days_to_fix": median(t["fix_days"]) if t["fix_days"] else None,
        "oldest_open_days": t["oldest"], "came_back": t["returned"],
    } for name, t in teams.items() if t["machines"]]
    team_rows.sort(key=lambda r: (-r["overdue"], -r["open"], r["team"]))
    software_rows = [{"software": name, "machines": len(s["machines"]), "open": s["open"], "overdue": s["overdue"],
                      "fixed_90d": s["fixed"], "came_back": s["returned"]}
                     for name, s in software.items() if s["machines"]]
    software_rows.sort(key=lambda r: (-r["open"], -r["came_back"], r["software"]))
    repeat = sorted(({"finding": fid, "machine": findings[fid].machine, "title": findings[fid].title,
                      "severity": findings[fid].severity, "times": n, "open": is_open(findings[fid], now)}
                     for fid, n in came_back.items() if fid in findings),
                    key=lambda r: (-r["times"], r["finding"]))
    return {"teams": team_rows, "software": software_rows, "came_back": repeat}


def headlines(result: dict) -> list[str]:
    """Plain sentences about where the problems come from, for the reports and the dashboard."""
    out = []
    named = [t for t in result["teams"] if t["team"] != NO_TEAM]
    if named and named[0]["overdue"] >= 5 and named[0]["share_of_overdue"] >= 0.4:
        top = named[0]
        out.append(f"{top['team']} owns {top['share_of_overdue']:.0%} of the past-deadline problems "
                   f"({top['overdue']} of them).")
    if any(t["team"] == NO_TEAM for t in result["teams"]):
        unowned = next(t for t in result["teams"] if t["team"] == NO_TEAM)
        out.append(f"{_plural(unowned['machines'], 'machine')} {'has' if unowned['machines'] == 1 else 'have'} no "
                   f"team set, so {_plural(unowned['open'], 'open problem')} "
                   f"{'has' if unowned['open'] == 1 else 'have'} no clear owner.")
    if result["software"]:
        s = result["software"][0]
        out.append(f"The most common source is \"{s['software']}\": {s['open']} open problems on "
                   f"{s['machines']} machines.")
    back = [r for r in result["came_back"] if r["open"]]
    if back:
        out.append(f"{len(back)} open problems came back after being fixed, which usually means the fix reached "
                   "running machines but not the image or template they're rebuilt from.")
    return out
