from datetime import datetime, timezone
from pathlib import Path

import pytest

pd = pytest.importorskip("pandas")

from vmtoolkit import db  # noqa: E402
from vmtoolkit.dashboard import metrics  # noqa: E402
from vmtoolkit.fakedata import generate  # noqa: E402
from vmtoolkit.prioritize import prioritize  # noqa: E402

NOW = datetime(2099, 3, 1, tzinfo=timezone.utc)
SLA = {"critical": 15, "high": 30, "medium": 90, "low": 180}


@pytest.fixture
def small_db(tmp_path):
    """Four synthetic findings with hand-picked dates so every number can be checked by hand."""
    path = tmp_path / "t.db"
    conn = db.connect(path)
    conn.execute("INSERT INTO assets (id, name, is_fake) VALUES (1, 'fake-web-01', 1)")
    rows = [
        # id, severity, status, first_seen, fixed_at
        (1, "critical", "open", "2099-02-01T00:00:00Z", None),    # 28 days old, 13 overdue
        (2, "high", "open", "2099-02-20T00:00:00Z", None),        # 9 days old, on time
        (3, "high", "fixed", "2099-01-01T00:00:00Z", "2099-01-11T00:00:00Z"),  # fixed in 10 days
        (4, "medium", "fixed", "2098-12-01T00:00:00Z", "2099-01-30T00:00:00Z"),  # fixed in 60 days
        (5, "info", "open", "2098-01-01T00:00:00Z", None),        # ignored everywhere
    ]
    for fid, sev, status, first, fixed in rows:
        conn.execute(
            """INSERT INTO findings (id, fingerprint, asset_id, scanner, rule_id, title, severity, status,
                                     first_seen, last_seen, fixed_at, is_fake)
               VALUES (?, ?, 1, 'nessus', ?, ?, ?, ?, ?, ?, ?, 1)""",
            (fid, f"fp{fid}", str(fid), f"FAKE {fid}", sev, status, first, first, fixed),
        )
    conn.commit()
    conn.close()
    ro = metrics.connect_readonly(path)
    yield ro
    ro.close()


def test_open_by_severity(small_db):
    df = metrics.load_findings(small_db)
    assert metrics.open_by_severity(df).set_index("severity")["open"].to_dict() == \
        {"critical": 1, "high": 1, "medium": 0, "low": 0}


def test_overdue_explains_why(small_db):
    late = metrics.overdue(metrics.load_findings(small_db), SLA, NOW)
    assert len(late) == 1
    row = late.iloc[0]
    assert (row.severity, row.age_days, row.days_overdue) == ("critical", 28, 13)
    assert row.why == "critical findings must be fixed within 15 days; this one has been open 28 days"


def test_time_to_fix(small_db):
    fix = metrics.time_to_fix(metrics.load_findings(small_db)).set_index("severity")
    assert fix.loc["high", "mean_days"] == 10.0 and fix.loc["medium", "mean_days"] == 60.0
    assert fix.loc["critical", "fixed"] == 0


def test_age_buckets(small_db):
    ages = metrics.age_buckets(metrics.load_findings(small_db), NOW)
    nonzero = ages[ages.open > 0]
    assert set(zip(nonzero.severity.astype(str), nonzero.age.astype(str))) == \
        {("critical", "0-30 days"), ("high", "0-30 days")}


def test_trend_counts_open_new_and_fixed(small_db):
    weekly = metrics.trend(metrics.load_findings(small_db), NOW)
    assert weekly["new"].sum() == 4 and weekly["fixed"].sum() == 2
    assert weekly.iloc[-1]["open"] == 2


def test_database_is_opened_read_only(small_db):
    import sqlite3
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        small_db.execute("DELETE FROM findings")


def test_missing_database(tmp_path):
    with pytest.raises(FileNotFoundError, match="vmt fake-data"):
        metrics.connect_readonly(tmp_path / "nope.db")


def test_app_renders_with_fake_data_banner(tmp_path, monkeypatch, settings):
    testing = pytest.importorskip("streamlit.testing.v1")
    generate(tmp_path / "fake.db", tmp_path / "vmt.db", machines=4, days=60)
    app = Path(metrics.__file__).parent / "app.py"
    monkeypatch.setattr("sys.argv", ["app.py", "--db", str(tmp_path / "fake.db")])
    at = testing.AppTest.from_file(str(app), default_timeout=60).run()
    assert not at.exception
    assert "FAKE DATA" in at.warning[0].value
    assert at.title[0].value == "Vulnerability management"
    assert [m.label for m in at.metric] == ["Open findings", "Critical or high", "Overdue", "Known exploited"]


def test_dashboard_page(tmp_path, monkeypatch, settings):
    testing = pytest.importorskip("streamlit.testing.v1")
    generate(tmp_path / "fake.db", tmp_path / "vmt.db", machines=4, days=60)
    conn = db.connect(tmp_path / "fake.db")
    prioritize(conn, settings)
    conn.close()
    monkeypatch.setattr("sys.argv", ["page", str(tmp_path / "fake.db")])
    at = testing.AppTest.from_string(
        "import sys\nfrom pathlib import Path\nfrom vmtoolkit.config import load_settings\n"
        "from vmtoolkit.dashboard.app import overview\noverview(load_settings(db=Path(sys.argv[1])))\n",
        default_timeout=60).run()
    assert not at.exception
    assert [m.label for m in at.metric] == ["Open findings", "Critical + high open", "Overdue", "Average days to fix"]
    assert [t.label for t in at.tabs][:2] == ["Open findings", "Top priorities"]
    assert len(at.dataframe) >= 3  # priorities, overdue, time to fix
    assert at.dataframe[0].value.iloc[0]["rank"] == 1


def test_next_step_follows_the_workflow():
    from vmtoolkit.dashboard.home import next_step
    base = {"findings": 5, "machines": 1, "unenriched": 0, "prioritized": 5, "planned": 2, "known_exploited": 0}
    assert next_step(None)[2] == "import"
    assert next_step({**base, "findings": 0})[2] == "import"
    assert next_step({**base, "unenriched": 3})[2] == "enrich"
    assert next_step({**base, "prioritized": 0})[2] == "prioritize"
    assert next_step({**base, "planned": 0})[2] == "plan"
    assert next_step(base)[2] == "dashboard"


def test_progress_counts(small_db):
    p = metrics.progress(small_db)
    assert p["findings"] == 5 and p["machines"] == 1 and p["prioritized"] == 0 and p["known_exploited"] == 0


def test_home_page_on_an_empty_database(tmp_path, monkeypatch):
    """A fresh production deploy starts with no findings at all."""
    testing = pytest.importorskip("streamlit.testing.v1")
    db.connect(tmp_path / "vmt.db").close()
    app = Path(metrics.__file__).parent / "app.py"
    monkeypatch.setattr("sys.argv", ["app.py", "--db", str(tmp_path / "vmt.db")])
    at = testing.AppTest.from_file(str(app), default_timeout=60).run()
    assert not at.exception
    assert [m.value for m in at.metric] == ["0", "0", "0", "0"]
