import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from vmtoolkit import db
from vmtoolkit.alerts import deadline_alerts
from vmtoolkit.fakedata import generate
from vmtoolkit.forecast import Survival, backtest, forecast

NOW = datetime(2099, 6, 1, tzinfo=timezone.utc)


def test_kaplan_meier_by_hand():
    # Fixed at 2, 4, 6; still open at 3 and 5.
    s = Survival([2, 3, 4, 5, 6], [True, False, True, False, True])
    assert s(1) == 1.0
    assert s(2) == pytest.approx(4 / 5)              # 1 of 5 fixed
    assert s(4) == pytest.approx(4 / 5 * 2 / 3)      # 1 of the 3 still at risk
    assert s(6) == 0.0
    assert s.median() == 6  # S(4) = 0.533 is still above one half


def test_open_findings_make_fixes_look_slower_than_the_naive_average():
    # Five fixed after 5-25 days, five still open after 100 days.
    durations = [5, 10, 15, 20, 25] + [100] * 5
    fixed = [True] * 5 + [False] * 5
    naive_median = 15  # middle of the fixed ones only
    km = Survival(durations, fixed).median()
    assert km == 25 and km > naive_median


def add(conn, fid, severity, first_days_ago, fixed_days_ago=None, machine="fake-h1"):
    conn.execute("INSERT OR IGNORE INTO assets (name) VALUES (?)", (machine,))
    asset = conn.execute("SELECT id FROM assets WHERE name = ?", (machine,)).fetchone()[0]
    first = db.to_iso(NOW - timedelta(days=first_days_ago))
    fixed = db.to_iso(NOW - timedelta(days=fixed_days_ago)) if fixed_days_ago is not None else None
    conn.execute(
        """INSERT INTO findings (id, fingerprint, asset_id, scanner, rule_id, title, severity, status,
                                 first_seen, fixed_at) VALUES (?, ?, ?, 'nessus', ?, ?, ?, ?, ?, ?)""",
        (fid, f"fp{fid}", asset, str(fid), f"FAKE {fid}", severity, "fixed" if fixed else "open", first, fixed))


def test_forecast_probability_and_reason(conn, settings):
    # History: 20 high findings, each fixed after exactly 40 days (deadline is 30).
    for i in range(20):
        add(conn, i + 1, "high", 200 + i, 160 + i)
    add(conn, 100, "high", 10)          # 10 days old, due in 20 days: history says nobody makes it
    add(conn, 101, "high", 45)          # already overdue
    add(conn, 102, "critical", 3)       # no critical history: falls back to all severities
    conn.commit()
    results = {f.finding_id: f for f in forecast(conn, settings, as_of=NOW)}
    f = results[100]
    assert f.p_on_time == 0.0 and f.at_risk
    assert "Based on 20 past fixes of high findings on fake-h1" in f.reason
    assert "0% were fixed by day 30" in f.reason and "half of them were fixed by day 40" in f.reason
    assert results[101].p_on_time is None and results[101].reason.startswith("Already overdue: open 45 days")
    assert "findings of every severity" in results[102].reason


def test_not_enough_history(conn, settings):
    add(conn, 1, "high", 5)
    conn.commit()
    (f,) = forecast(conn, settings, as_of=NOW)
    assert f.p_on_time is None and "fewer than 10 past fixes" in f.reason


def test_deadline_alerts_only_for_critical_and_high(conn, settings, monkeypatch):
    for i in range(20):
        add(conn, i + 1, "high", 200 + i, 160 + i)
        add(conn, 50 + i, "low", 400 + i, 0)
    add(conn, 100, "high", 10)
    conn.commit()
    monkeypatch.setattr("vmtoolkit.forecast.utcnow", lambda: db.to_iso(NOW))
    keys = [a.key for a in deadline_alerts(conn, settings)]
    assert keys == [f"deadline:100:{(NOW + timedelta(days=20)):%Y-%m-%d}"]


def test_backtest_on_fake_data(tmp_path, settings):
    path = tmp_path / "fake.db"
    generate(path, tmp_path / "vmt.db", machines=30, days=365, end=NOW)
    conn = db.connect(path)
    text = backtest(conn, settings, days_back=120, now=NOW)
    conn.close()
    assert text.startswith("Backtest: forecasts made as of 2099-02-01")
    assert "Brier score" in text and "actually were" in text


def test_dev_machines_forecast_slower_in_fake_data(tmp_path, settings):
    path = tmp_path / "fake.db"
    generate(path, tmp_path / "vmt.db", machines=40, days=365, end=NOW)
    conn = db.connect(path)
    from vmtoolkit.forecast import _history
    history = _history(conn, NOW)
    conn.close()

    def median(role):
        rows = [h for h in history if h["severity"] == "medium" and f"-{role}-" in h["machine"]]
        return Survival([h["days"] for h in rows], [h["fixed"] for h in rows]).median()

    assert median("dev") > median("db")


def test_falls_back_to_machines_of_the_same_importance(conn, settings):
    cfg = dataclasses.replace(settings, raw={**settings.raw, "assets": {"fake-dev-*": {"criticality": "low"}}})
    for i in range(12):
        add(conn, i + 1, "high", 200 + i, 160 + i, machine=f"fake-dev-{i:02d}")
    add(conn, 100, "high", 10, machine="fake-dev-99")
    conn.commit()
    f = next(f for f in forecast(conn, cfg, as_of=NOW) if f.finding_id == 100)
    assert "12 past fixes of high findings on low-importance machines" in f.reason
