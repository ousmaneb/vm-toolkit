"""Risk acceptance: a named approver agrees to leave a finding unfixed until a date.

While an acceptance is active the finding stays open and visible, but it doesn't count as past its
deadline, isn't forecast to miss one, and is left out of the patch plan and tickets. When it expires
it counts again, and an alert says so. Every count asks whether an acceptance was active on the day
being counted, so history and week-over-week comparisons stay correct.
"""

import sqlite3
from datetime import datetime, timedelta

from .config import ConfigError, Settings
from .db import parse_iso, to_iso, utcnow

WARN_DAYS = 7


def max_days(settings: Settings) -> int:
    return int(settings.section("acceptance").get("max_days", 365))


def accept(conn: sqlite3.Connection, settings: Settings, finding_ids: list[int], reason: str, approved_by: str,
           until: str, recorded_by: str) -> list[str]:
    """Record acceptances. `until` is a date (YYYY-MM-DD); the acceptance ends at the start of that day."""
    reason, approved_by = reason.strip(), approved_by.strip()
    if not reason or not approved_by:
        raise ConfigError("Accepting a risk needs a reason and the name of the person who approved it.")
    now = parse_iso(utcnow())
    try:
        expires = parse_iso(f"{until}T00:00:00Z")
    except ValueError:
        raise ConfigError(f"--until must be a date like 2026-12-31, not {until!r}") from None
    if expires <= now:
        raise ConfigError("The acceptance must end in the future.")
    if expires - now > timedelta(days=max_days(settings)):
        raise ConfigError(f"Acceptances can last at most {max_days(settings)} days ([acceptance] max_days). "
                          "Accept it again when it expires if the reason still holds.")
    lines = []
    with conn:
        for fid in finding_ids:
            row = conn.execute(
                """SELECT f.status, f.title, a.name AS machine,
                          EXISTS (SELECT 1 FROM finding_cves c JOIN kev k ON k.cve = c.cve WHERE c.finding_id = f.id)
                              AS kev
                   FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.id = ?""", (fid,)).fetchone()
            if row is None:
                raise ConfigError(f"Finding {fid} doesn't exist.")
            if row["status"] != "open":
                raise ConfigError(f"Finding {fid} is already {row['status']}; only open findings can be accepted.")
            # A new acceptance replaces any active one for the same finding.
            conn.execute("UPDATE risk_acceptances SET revoked_at = ?, revoked_by = ? WHERE finding_id = ? "
                         "AND revoked_at IS NULL AND expires_at > ?", (to_iso(now), recorded_by, fid, to_iso(now)))
            conn.execute(
                """INSERT INTO risk_acceptances (finding_id, reason, approved_by, recorded_by, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)""", (fid, reason, approved_by, recorded_by, to_iso(now), to_iso(expires)))
            warning = " Warning: attackers are known to exploit this one (CISA KEV)." if row["kev"] else ""
            lines.append(f"Accepted finding {fid} ({row['title']} on {row['machine']}) until {until}, "
                         f"approved by {approved_by}.{warning}")
    return lines


def revoke(conn: sqlite3.Connection, acceptance_id: int, revoked_by: str) -> bool:
    with conn:
        return conn.execute("UPDATE risk_acceptances SET revoked_at = ?, revoked_by = ? WHERE id = ? AND "
                            "revoked_at IS NULL", (utcnow(), revoked_by, acceptance_id)).rowcount > 0


def periods(conn: sqlite3.Connection) -> dict[int, list[tuple[datetime, datetime]]]:
    """Finding id -> the (start, end) periods it was accepted for, ended early if revoked."""
    out: dict[int, list[tuple[datetime, datetime]]] = {}
    for r in conn.execute("SELECT finding_id, created_at, expires_at, revoked_at FROM risk_acceptances"):
        end = min(parse_iso(r["expires_at"]), parse_iso(r["revoked_at"])) if r["revoked_at"] \
            else parse_iso(r["expires_at"])
        out.setdefault(r["finding_id"], []).append((parse_iso(r["created_at"]), end))
    return out


def accepted_at(spans: list[tuple[datetime, datetime]] | None, at: datetime) -> bool:
    return any(start <= at < end for start, end in spans or [])


def active_ids(conn: sqlite3.Connection, at: datetime | None = None) -> set[int]:
    at = at or parse_iso(utcnow())
    return {fid for fid, spans in periods(conn).items() if accepted_at(spans, at)}


def listing(conn: sqlite3.Connection, include_ended: bool = False) -> list[dict]:
    now = parse_iso(utcnow())
    rows = conn.execute(
        """SELECT r.*, f.title, f.severity, f.status AS finding_status, a.name AS machine,
                  EXISTS (SELECT 1 FROM finding_cves c JOIN kev k ON k.cve = c.cve WHERE c.finding_id = f.id) AS kev
           FROM risk_acceptances r JOIN findings f ON f.id = r.finding_id JOIN assets a ON a.id = f.asset_id
           ORDER BY r.expires_at""").fetchall()
    out = []
    for r in rows:
        expires = parse_iso(r["expires_at"])
        if r["revoked_at"]:
            state = "revoked"
        elif r["finding_status"] != "open":
            state = "fixed"
        elif expires <= now:
            state = "expired"
        elif expires - now <= timedelta(days=WARN_DAYS):
            state = "expiring"
        else:
            state = "active"
        if include_ended or state in ("active", "expiring"):
            out.append({**dict(r), "state": state, "days_left": max((expires - now).days, 0)})
    return out


def expiry_alerts(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """(alert key, message) for acceptances about to expire or just expired, on findings still open."""
    out = []
    for r in listing(conn, include_ended=True):
        where = f"finding {r['finding_id']} ({r['title']}, {r['severity']}) on {r['machine']}"
        if r["state"] == "expiring":
            out.append((f"accept-expiring:{r['id']}",
                        f"The risk acceptance for {where} ends on {r['expires_at'][:10]}. Fix it or have "
                        f"{r['approved_by']} renew the acceptance; after that it counts toward deadlines again."))
        elif r["state"] == "expired" and parse_iso(utcnow()) - parse_iso(r["expires_at"]) <= timedelta(days=WARN_DAYS):
            out.append((f"accept-expired:{r['id']}",
                        f"The risk acceptance for {where} expired on {r['expires_at'][:10]}. It counts toward "
                        "deadlines, the patch plan and tickets again."))
    return out
