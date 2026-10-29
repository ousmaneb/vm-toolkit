from datetime import datetime, timedelta, timezone

from vmtoolkit.db import to_iso
from vmtoolkit.insights import NO_TEAM, analyse, headlines, returns

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def machine(conn, asset_id, name):
    conn.execute("INSERT INTO assets (id, name, is_fake) VALUES (?, ?, 1)", (asset_id, name))


def scan(conn, scan_id, days_ago, reached):
    when = to_iso(NOW - timedelta(days=days_ago))
    conn.execute("INSERT INTO scans (id, scanner, source_id, run_id, finished_at, imported_at, is_fake) "
                 "VALUES (?, 'nessus', 'x', ?, ?, ?, 1)", (scan_id, str(scan_id), when, when))
    conn.executemany("INSERT INTO scan_hosts (scan_id, asset_id) VALUES (?, ?)", [(scan_id, a) for a in reached])


def finding(conn, fid, asset_id, severity, first_days_ago, package, seen_in, fixed_days_ago=None):
    first = to_iso(NOW - timedelta(days=first_days_ago))
    fixed = to_iso(NOW - timedelta(days=fixed_days_ago)) if fixed_days_ago is not None else None
    conn.execute(
        """INSERT INTO findings (id, fingerprint, asset_id, scanner, rule_id, title, severity, status, package,
                                 first_seen, last_seen, fixed_at, is_fake)
           VALUES (?, ?, ?, 'nessus', ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
        (fid, f"fp{fid}", asset_id, str(fid), f"FAKE {fid}", severity, "fixed" if fixed else "open", package,
         first, first, fixed))
    conn.executemany("INSERT INTO observations (finding_id, scan_id) VALUES (?, ?)", [(fid, s) for s in seen_in])


def test_came_back_needs_a_scan_that_reached_the_machine_and_missed_it(conn):
    machine(conn, 1, "fake-web-01")
    machine(conn, 2, "fake-db-02")
    scan(conn, 1, 30, [1, 2])
    scan(conn, 2, 20, [1])        # reached web-01 only
    scan(conn, 3, 10, [1, 2])
    finding(conn, 1, 1, "high", 30, "openssl", seen_in=[1, 3])   # seen, missed by scan 2, seen again
    finding(conn, 2, 2, "high", 30, "openssl", seen_in=[1, 3])   # scan 2 never reached db-02: not a return
    finding(conn, 3, 1, "low", 30, "zlib", seen_in=[1, 2, 3])    # always seen
    conn.commit()
    assert returns(conn) == {1: 1}


def test_breakdown_by_team_and_software(conn, settings):
    settings.raw["assets"] = {"fake-web-*": {"team": "Web"}}
    for asset_id, name in ((1, "fake-web-01"), (2, "fake-web-02"), (3, "fake-db-03")):
        machine(conn, asset_id, name)
    scan(conn, 1, 60, [1, 2, 3])
    for fid, asset_id in ((1, 1), (2, 1), (3, 2), (4, 2), (5, 2), (6, 3)):
        finding(conn, fid, asset_id, "critical", 60, "openssl" if fid < 6 else "zlib", seen_in=[1])
    finding(conn, 7, 3, "high", 40, "zlib", seen_in=[1], fixed_days_ago=30)  # fixed in 10 days, on time
    conn.commit()
    result = analyse(conn, settings)
    teams = {t["team"]: t for t in result["teams"]}
    assert (teams["Web"]["machines"], teams["Web"]["open"], teams["Web"]["overdue"]) == (2, 5, 5)
    assert teams["Web"]["share_of_overdue"] == 5 / 6
    assert (teams[NO_TEAM]["fixed_90d"], teams[NO_TEAM]["on_time"]) == (1, 1.0)
    assert result["software"][0]["software"] == "openssl" and result["software"][0]["open"] == 5
    lines = headlines(result)
    assert lines[0] == "Web owns 83% of the past-deadline problems (5 of them)."
    assert "1 machine has no team set, so 1 open problem has no clear owner." in lines
