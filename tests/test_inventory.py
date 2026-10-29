from datetime import datetime, timedelta, timezone

from vmtoolkit.acceptance import accept
from vmtoolkit.alerts import run_alerts
from vmtoolkit.db import to_iso
from vmtoolkit.inventory import machines, stale_alerts

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def seed(conn, name, asset_id, last_scan_days_ago, findings):
    """One machine, one scan that reached it, and (id, severity, first_seen_days_ago) findings."""
    conn.execute("INSERT INTO assets (id, name, is_fake) VALUES (?, ?, 1)", (asset_id, name))
    when = to_iso(NOW - timedelta(days=last_scan_days_ago))
    scan_id = conn.execute(
        "INSERT INTO scans (scanner, source_id, run_id, finished_at, imported_at, is_fake) VALUES ('nessus', ?, '1', ?, ?, 1)",
        (name, when, when)).lastrowid
    conn.execute("INSERT INTO scan_hosts (scan_id, asset_id) VALUES (?, ?)", (scan_id, asset_id))
    for fid, severity, days_ago in findings:
        first = to_iso(NOW - timedelta(days=days_ago))
        conn.execute(
            """INSERT INTO findings (id, fingerprint, asset_id, scanner, rule_id, title, severity, status,
                                     first_seen, last_seen, is_fake)
               VALUES (?, ?, ?, 'nessus', ?, ?, ?, 'open', ?, ?, 1)""",
            (fid, f"fp{fid}", asset_id, str(fid), f"FAKE {fid}", severity, first, first))
    conn.commit()


def configure(settings):
    settings.raw["assets"] = {"fake-web-01": {"criticality": "high", "internet_facing": True,
                                              "owner": "alice@example.com", "team": "Web"}}


def test_inventory_shows_settings_counts_and_coverage(conn, settings):
    configure(settings)
    seed(conn, "fake-web-01", 1, 2, [(1, "critical", 40), (2, "low", 3)])
    seed(conn, "fake-old-02", 2, 30, [(3, "high", 60)])
    rows = {m["machine"]: m for m in machines(conn, settings)}
    web, old = rows["fake-web-01"], rows["fake-old-02"]
    assert (web["importance"], web["internet_facing"], web["owner"], web["team"]) == ("high", True, "alice@example.com", "Web")
    assert (web["open"], web["critical_high"], web["overdue"], web["stale"]) == (2, 1, 1, False)
    assert (old["importance"], old["owner"], old["stale"], old["days_since_scan"]) == ("medium", None, True, 30)


def test_accepted_findings_are_not_overdue_in_the_inventory(conn, settings):
    seed(conn, "fake-web-01", 1, 2, [(1, "critical", 40)])
    accept(conn, settings, [1], "isolated", "CISO", (NOW + timedelta(days=30)).strftime("%Y-%m-%d"), "alice")
    assert machines(conn, settings)[0]["overdue"] == 0


def test_stale_machines_alert_once(conn, settings):
    seed(conn, "fake-old-02", 2, 30, [(3, "high", 60)])
    [(key, message)] = stale_alerts(conn, settings)
    assert "fake-old-02 hasn't been scanned for 30 days" in message
    assert run_alerts(conn, settings, echo=lambda *_: None) == ["console: sent 1 alert(s)"]
    again = run_alerts(conn, settings, echo=lambda *_: None)
    assert again == ["console: no new alerts"]


def test_tickets_name_the_owner(conn, settings):
    from vmtoolkit.prioritize import prioritize
    from vmtoolkit.tickets import tickets_dir, generate

    configure(settings)
    seed(conn, "fake-web-01", 1, 2, [(1, "critical", 40)])
    prioritize(conn, settings)
    generate(conn, settings)
    text = next(tickets_dir(settings).glob("*.md")).read_text()
    assert "fake-web-01 (1 finding), owner: alice@example.com · Web" in text
