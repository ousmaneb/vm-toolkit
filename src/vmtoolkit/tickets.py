"""Turn the patch plan into grouped remediation tickets: files by default, optionally Jira or ServiceNow."""

import hashlib
import json
import os
import sqlite3
from datetime import timedelta
from pathlib import Path

import requests

from .acceptance import active_ids
from .assets import asset_config
from .config import ConfigError, Settings, get_secret
from .db import parse_iso, utcnow
from .plan import Fix, plan

# Priority from the highest finding score in the ticket.
PRIORITY_THRESHOLDS = [("P1", 70), ("P2", 40), ("P3", 15), ("P4", 0)]
SN_URGENCY = {"P1": "1", "P2": "2", "P3": "2", "P4": "3"}


class TicketError(Exception):
    pass


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def tickets_dir(settings: Settings) -> Path:
    # Named after the database, so tickets made from fake.db never mix with real ones.
    return settings.db_path.with_name(f"{settings.db_path.stem}-tickets")


def ticket_id(fix_key: str) -> str:
    return "VMT-" + hashlib.sha256(fix_key.encode("utf-8")).hexdigest()[:8]


def _owner(settings: Settings, machine: str) -> str | None:
    cfg = asset_config(settings, machine)
    return " · ".join(filter(None, [cfg.owner, cfg.team])) or None


def _details(conn: sqlite3.Connection, fix: Fix, sla: dict[str, int], settings: Settings) -> dict:
    ids = [f["id"] for f in fix.findings]
    rows = conn.execute(
        f"""SELECT f.id, f.severity, f.title, f.first_seen, f.installed_version, f.package, a.name AS machine,
                   p.rank, p.score,
                   (SELECT group_concat(cve, ', ') FROM finding_cves c WHERE c.finding_id = f.id) AS cves
            FROM findings f JOIN assets a ON a.id = f.asset_id JOIN priorities p ON p.finding_id = f.id
            WHERE f.id IN ({','.join('?' * len(ids))}) ORDER BY p.rank""",
        ids,
    ).fetchall()
    top = rows[0]
    priority = next(label for label, floor in PRIORITY_THRESHOLDS if top["score"] >= floor)
    floor = dict(PRIORITY_THRESHOLDS)[priority]
    why_priority = (f"{priority} because its highest-scoring finding ({top['title']} on "
                    f"{top['machine']}) scores {top['score']:.1f}; {priority} covers scores of {floor} and up.")

    due, due_reason = None, "no deadline: none of its findings has a first-seen date"
    for r in rows:
        if r["first_seen"] and r["severity"] in sla:
            deadline = parse_iso(r["first_seen"]) + timedelta(days=sla[r["severity"]])
            if due is None or deadline < due:
                due = deadline
                due_reason = (f"the earliest deadline among its findings: a {r['severity']} finding first seen "
                              f"{r['first_seen'][:10]} plus {sla[r['severity']]} days ([sla_days] in config.toml)")
    return {
        "id": ticket_id(fix.key), "fix_key": fix.key, "title": fix.action, "priority": priority,
        "why_priority": why_priority, "due_date": due.strftime("%Y-%m-%d") if due else None,
        "due_reason": due_reason, "plan_rank": fix.rank, "risk": round(fix.risk, 1),
        "risk_share": round(fix.share, 3), "notes": fix.notes, "machines": sorted(fix.machines),
        "owners": {m: _owner(settings, m) for m in sorted(fix.machines) if _owner(settings, m)},
        "findings": [dict(r) for r in rows],
    }


def render_markdown(t: dict, status: str, status_note: str | None) -> str:
    overdue = t["due_date"] and t["due_date"] < utcnow()[:10] and status == "open"
    lines = [
        f"# {t['id']}: {t['title']}",
        "",
        f"- Status: {status}" + (f" ({status_note})" if status_note else ""),
        f"- Priority: {t['priority']}",
        f"- Due: {t['due_date'] or 'none'}" + (" (OVERDUE)" if overdue else ""),
        f"- Plan position: fix {t['plan_rank']}, removes {t['risk_share']:.0%} of current risk",
        "",
        "## Why this priority and due date",
        "",
        f"- {t['why_priority']}",
        f"- Due {t['due_date'] or 'date not set'}: {t['due_reason']}.",
        "",
        "## Affected machines",
        "",
        *[f"- {m} ({plural(sum(f['machine'] == m for f in t['findings']), 'finding')})"
          + (f", owner: {t['owners'][m]}" if m in t.get("owners", {}) else "") for m in t["machines"]],
        "",
        "## Findings",
        "",
        "| Rank | Score | Machine | Severity | Finding | CVEs | First seen |",
        "|---|---|---|---|---|---|---|",
        *[f"| {f['rank']} | {f['score']:.1f} | {f['machine']} | {f['severity']} | {f['title']} | "
          f"{f['cves'] or ''} | {(f['first_seen'] or '')[:10]} |" for f in t["findings"]],
        "",
        "## Fix",
        "",
        t["title"],
        *[f"\nNote: {n}." for n in t["notes"]],
        "",
        "## How to verify",
        "",
        "Rescan the affected machines (`vmt nessus pull` or `vmt import`), then run `vmt tickets` again. "
        "This ticket is resolved automatically once no finding listed above is reported.",
        "",
    ]
    return "\n".join(lines)


def render_text(t: dict, status: str) -> str:
    """Plain text for Jira and ServiceNow, which don't render Markdown tables."""
    lines = [f"{t['id']} ({status}) - generated by vmtoolkit", "",
             f"Priority {t['priority']}: {t['why_priority']}",
             f"Due {t['due_date'] or 'not set'}: {t['due_reason']}.", "",
             "Fix: " + t["title"], *[f"Note: {n}." for n in t["notes"]], "",
             "Affected machines: " + ", ".join(f"{m} ({t['owners'][m]})" if m in t.get("owners", {}) else m
                                               for m in t["machines"]), "", "Findings:"]
    # No ranks or plan position here: they shift whenever another fix lands, and this text decides
    # whether Jira or ServiceNow need an update.
    lines += [f"- score {f['score']:.1f}: {f['title']} on {f['machine']} ({f['severity']})"
              + (f" [{f['cves']}]" if f["cves"] else "") for f in t["findings"]]
    lines += ["", "Rescan, then run `vmt tickets`; this ticket is resolved once none of these findings is reported."]
    return "\n".join(lines)


def _write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".part")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def generate(conn: sqlite3.Connection, settings: Settings, max_fixes: int | None = None) -> list[str]:
    """Create or update ticket files for every fix in the plan, and resolve tickets whose fix is done."""
    sla = {k: int(v) for k, v in settings.section("sla_days").items()}
    chosen, rest, _ = plan(conn, settings, target=None if max_fixes else 1.0, max_fixes=max_fixes)
    out_dir = tickets_dir(settings)
    out_dir.mkdir(parents=True, exist_ok=True)
    now = utcnow()
    counts = {"created": 0, "updated": 0, "unchanged": 0, "resolved": 0, "reopened": 0}
    current = set()

    for fix in chosen:
        t = _details(conn, fix, sla, settings)
        current.add(t["id"])
        body = render_markdown(t, "open", None)
        digest = hashlib.sha256(render_text(t, "open").encode("utf-8")).hexdigest()
        old = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (t["id"],)).fetchone()
        if old is None:
            conn.execute(
                """INSERT INTO tickets (ticket_id, fix_key, title, priority, due_date, content_hash,
                                        created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (t["id"], fix.key, t["title"], t["priority"], t["due_date"], digest, now, now))
            counts["created"] += 1
        else:
            if old["status"] == "resolved":
                counts["reopened"] += 1
            elif old["content_hash"] == digest:
                counts["unchanged"] += 1
            else:
                counts["updated"] += 1
            conn.execute(
                """UPDATE tickets SET title = ?, priority = ?, due_date = ?, content_hash = ?, status = 'open',
                       status_note = NULL, resolved_at = NULL,
                       updated_at = CASE WHEN content_hash = ? AND status = 'open' THEN updated_at ELSE ? END
                   WHERE ticket_id = ?""",
                (t["title"], t["priority"], t["due_date"], digest, digest, now, t["id"]))
        conn.execute("DELETE FROM ticket_items WHERE ticket_id = ?", (t["id"],))
        conn.executemany("INSERT INTO ticket_items (ticket_id, finding_id) VALUES (?, ?)",
                         [(t["id"], f["id"]) for f in t["findings"]])
        _write(out_dir / f"{t['id']}.md", body)
        _write(out_dir / f"{t['id']}.json", json.dumps({**t, "status": "open"}, indent=2, default=str))

    skipped = {ticket_id(f.key) for f in rest}
    accepted = active_ids(conn)
    for old in conn.execute("SELECT * FROM tickets WHERE status = 'open'").fetchall():
        if old["ticket_id"] in current or old["ticket_id"] in skipped:
            continue
        items = conn.execute(
            """SELECT f.id, f.status FROM ticket_items i JOIN findings f ON f.id = i.finding_id
               WHERE i.ticket_id = ?""", (old["ticket_id"],)).fetchall()
        states = [r["status"] for r in items]
        still_open = {r["id"] for r in items if r["status"] == "open"}
        if states and all(s == "fixed" for s in states):
            note = f"all {plural(len(states), 'finding')} fixed"
        elif still_open and still_open <= accepted:
            note = "its open findings are accepted risks (see vmt accept list)"
        else:
            note = "no longer in the plan: its findings were fixed, merged as duplicates or removed"
        conn.execute("UPDATE tickets SET status = 'resolved', status_note = ?, resolved_at = ?, updated_at = ? "
                     "WHERE ticket_id = ?", (note, now, now, old["ticket_id"]))
        md, js = out_dir / f"{old['ticket_id']}.md", out_dir / f"{old['ticket_id']}.json"
        if md.exists():
            text = md.read_text(encoding="utf-8").replace("- Status: open", f"- Status: resolved {now[:10]} ({note})", 1)
            _write(md, text)
        if js.exists():
            data = json.loads(js.read_text(encoding="utf-8"))
            _write(js, json.dumps({**data, "status": "resolved", "status_note": note, "resolved_at": now}, indent=2))
        counts["resolved"] += 1
    conn.commit()

    lines = [f"Tickets in {out_dir}: " + ", ".join(f"{v} {k}" for k, v in counts.items())]
    if rest and max_fixes:
        lines.append(f"{len(rest)} lower-risk fixes have no ticket because of --max-fixes {max_fixes}.")
    return lines


def _ticket_payload(row: sqlite3.Row, settings: Settings) -> str:
    data = json.loads((tickets_dir(settings) / f"{row['ticket_id']}.json").read_text(encoding="utf-8"))
    return render_text(data, row["status"])


def push_jira(conn: sqlite3.Connection, settings: Settings, session=None) -> list[str]:
    cfg = settings.section("jira")
    if not cfg.get("url") or not cfg.get("project"):
        raise ConfigError("Set [jira] url and project in config.toml to push tickets to Jira.")
    session = session or requests.Session()
    session.auth = (get_secret("JIRA_EMAIL", required=True), get_secret("JIRA_API_TOKEN", required=True))
    base = cfg["url"].rstrip("/") + "/rest/api/2/issue"
    lines = []
    for row in conn.execute("SELECT * FROM tickets ORDER BY ticket_id").fetchall():
        text = _ticket_payload(row, settings) if row["status"] == "open" else None
        if row["status"] == "open" and row["jira_key"] is None:
            resp = _send(session, "POST", base, json={"fields": {
                "project": {"key": cfg["project"]}, "issuetype": {"name": cfg.get("issue_type", "Task")},
                "summary": f"[{row['priority']}] {row['title']}"[:250], "description": text,
                "labels": ["vmtoolkit", row["priority"], row["ticket_id"]]}})
            key = resp.json()["key"]
            conn.execute("UPDATE tickets SET jira_key = ?, jira_hash = ? WHERE ticket_id = ?",
                         (key, row["content_hash"], row["ticket_id"]))
            lines.append(f"{row['ticket_id']}: created Jira {key}")
        elif row["status"] == "open" and row["jira_hash"] != row["content_hash"]:
            _send(session, "PUT", f"{base}/{row['jira_key']}", json={"fields": {
                "summary": f"[{row['priority']}] {row['title']}"[:250], "description": text}})
            conn.execute("UPDATE tickets SET jira_hash = ? WHERE ticket_id = ?", (row["content_hash"], row["ticket_id"]))
            lines.append(f"{row['ticket_id']}: updated Jira {row['jira_key']}")
        elif row["status"] == "resolved" and row["jira_key"] and row["jira_hash"] != "resolved":
            # Workflows differ between Jira projects, so the issue is commented on rather than transitioned.
            _send(session, "POST", f"{base}/{row['jira_key']}/comment",
                  json={"body": f"vmtoolkit: resolved on {row['resolved_at'][:10]} ({row['status_note']}). "
                                "You can close this issue."})
            conn.execute("UPDATE tickets SET jira_hash = 'resolved' WHERE ticket_id = ?", (row["ticket_id"],))
            lines.append(f"{row['ticket_id']}: commented on Jira {row['jira_key']} that it is resolved")
        conn.commit()
    return lines or ["Jira: nothing to send."]


def push_servicenow(conn: sqlite3.Connection, settings: Settings, session=None) -> list[str]:
    cfg = settings.section("servicenow")
    if not cfg.get("instance"):
        raise ConfigError("Set [servicenow] instance (e.g. https://dev12345.service-now.com) in config.toml.")
    session = session or requests.Session()
    session.auth = (get_secret("SN_USERNAME", required=True), get_secret("SN_PASSWORD", required=True))
    session.headers["Accept"] = "application/json"
    base = cfg["instance"].rstrip("/") + "/api/now/table/" + cfg.get("table", "incident")
    lines = []
    for row in conn.execute("SELECT * FROM tickets ORDER BY ticket_id").fetchall():
        text = _ticket_payload(row, settings) if row["status"] == "open" else None
        fields = {"short_description": f"[{row['priority']}] {row['title']}"[:160], "description": text,
                  "urgency": SN_URGENCY[row["priority"]], "impact": SN_URGENCY[row["priority"]]}
        if row["status"] == "open" and row["servicenow_sys_id"] is None:
            result = _send(session, "POST", base, json={**fields, "correlation_id": row["ticket_id"]}).json()["result"]
            conn.execute("UPDATE tickets SET servicenow_sys_id = ?, servicenow_number = ?, servicenow_hash = ? "
                         "WHERE ticket_id = ?",
                         (result["sys_id"], result.get("number"), row["content_hash"], row["ticket_id"]))
            lines.append(f"{row['ticket_id']}: created ServiceNow {result.get('number', result['sys_id'])}")
        elif row["status"] == "open" and row["servicenow_hash"] != row["content_hash"]:
            _send(session, "PATCH", f"{base}/{row['servicenow_sys_id']}", json=fields)
            conn.execute("UPDATE tickets SET servicenow_hash = ? WHERE ticket_id = ?",
                         (row["content_hash"], row["ticket_id"]))
            lines.append(f"{row['ticket_id']}: updated ServiceNow {row['servicenow_number']}")
        elif row["status"] == "resolved" and row["servicenow_sys_id"] and row["servicenow_hash"] != "resolved":
            _send(session, "PATCH", f"{base}/{row['servicenow_sys_id']}", json={
                "state": str(cfg.get("resolved_state", 6)), "close_code": cfg.get("close_code", "Solution provided"),
                "close_notes": f"vmtoolkit: {row['status_note']}."})
            conn.execute("UPDATE tickets SET servicenow_hash = 'resolved' WHERE ticket_id = ?", (row["ticket_id"],))
            lines.append(f"{row['ticket_id']}: resolved ServiceNow {row['servicenow_number']}")
        conn.commit()
    return lines or ["ServiceNow: nothing to send."]


def _send(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    try:
        resp = session.request(method, url, timeout=30, **kwargs)
    except requests.RequestException as e:
        raise TicketError(f"{method} {url} failed: {type(e).__name__}") from None
    if resp.status_code >= 400:
        raise TicketError(f"{method} {url} returned HTTP {resp.status_code}: {resp.text[:300]}")
    return resp
