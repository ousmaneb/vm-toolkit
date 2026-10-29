from vmtoolkit.history import backfill, plan_on, ranking_on, save_snapshot, snapshots
from vmtoolkit.plan import plan
from vmtoolkit.prioritize import prioritize


def add(conn, fid, severity, first, fixed=None):
    conn.execute("INSERT OR IGNORE INTO assets (id, name, is_fake) VALUES (1, 'fake-web-01', 1)")
    conn.execute(
        """INSERT INTO findings (id, fingerprint, asset_id, scanner, rule_id, title, severity, status, package,
                                 fixed_version, first_seen, last_seen, fixed_at, is_fake)
           VALUES (?, ?, 1, 'trivy', ?, ?, ?, ?, 'fakepkg', '2.0', ?, ?, ?, 1)""",
        (fid, f"fp{fid}", str(fid), f"FAKE {fid}", severity, "fixed" if fixed else "open", first, first, fixed))


def test_rankings_and_plans_are_kept_by_day(conn, settings):
    add(conn, 1, "high", "2020-01-01T00:00:00Z")
    conn.commit()
    prioritize(conn, settings)
    plan(conn, settings)
    day = conn.execute("SELECT day FROM priority_history").fetchone()[0]
    # Running again the same day replaces that day's copy instead of adding a second one.
    prioritize(conn, settings)
    assert conn.execute("SELECT count(*) FROM priority_history").fetchone()[0] == 1
    assert [r["finding"] for r in ranking_on(conn, day)] == [1]
    assert [r["rank"] for r in plan_on(conn, day)] == [1]
    # Asking about a later day gives the latest ranking saved on or before it.
    assert [r["finding"] for r in ranking_on(conn, "2999-01-01")] == [1]
    assert ranking_on(conn, "2000-01-01") == []


def test_snapshot_and_backfill(conn, settings):
    import datetime
    today = datetime.datetime.now(datetime.timezone.utc).date()
    ago = lambda n: (today - datetime.timedelta(days=n)).strftime("%Y-%m-%dT12:00:00Z")  # noqa: E731
    add(conn, 1, "critical", ago(20))  # past its 15-day deadline
    add(conn, 2, "low", ago(5), fixed=ago(2))
    conn.commit()
    assert save_snapshot(conn, settings).startswith(f"Saved {today}: 1 open")
    backfill(conn, settings, 30)
    rows = {r["day"]: r for r in snapshots(conn)}
    # Nothing before the first finding; a real snapshot isn't overwritten by a rebuilt one.
    assert min(rows) == (today - datetime.timedelta(days=20)).strftime("%Y-%m-%d")
    assert rows[str(today)]["reconstructed"] == 0 and rows[str(today)]["status"] == "red"
    four_days_ago = rows[(today - datetime.timedelta(days=4)).strftime("%Y-%m-%d")]
    assert (four_days_ago["open"], four_days_ago["reconstructed"], four_days_ago["status"]) == (2, 1, None)
    assert rows[(today - datetime.timedelta(days=2)).strftime("%Y-%m-%d")]["fixed"] == 1
