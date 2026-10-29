from datetime import datetime, timezone

import pytest

from vmtoolkit import db
from vmtoolkit.alerts import open_cves
from vmtoolkit.fakedata import generate
from vmtoolkit.fp import mark, predict, unmark
from vmtoolkit.normalize import Finding, Host, ScanResult, store_scan
from vmtoolkit.prioritize import prioritize

BANNER = "FAKE: version read from the service banner; the vendor backports fixes"


def lab(conn):
    hosts = []
    for i in range(1, 5):
        hosts.append(Host(f"fake-web-0{i}", credentialed=False, findings=[
            Finding("7001", "FAKE Apache < 2.4.99", "high", cves=["CVE-2099-0001"], port=80, protocol="tcp",
                    evidence=f"{BANNER} (host {i})"),
            Finding("8001", "FAKE real issue", "critical", cves=["CVE-2099-0002"], port=22, protocol="tcp",
                    evidence="FAKE: installed package is older than the fix"),
        ]))
    store_scan(conn, ScanResult("nessus", "fake", "1", "2099-01-01T00:00:00Z", hosts=hosts))


def fid(conn, host, rule):
    return conn.execute("""SELECT f.id FROM findings f JOIN assets a ON a.id = f.asset_id
                           WHERE a.name = ? AND f.rule_id = ?""", (host, rule)).fetchone()[0]


def test_mark_unmark_and_unknown(conn):
    lab(conn)
    a = fid(conn, "fake-web-01", "7001")
    assert mark(conn, [a, 9999], real=False, reason="banner")[1] == "Finding 9999 doesn't exist."
    assert conn.execute("SELECT label, reason FROM fp_labels").fetchone()[:] == ("false_positive", "banner")
    mark(conn, [a], real=True, reason=None)
    assert conn.execute("SELECT label FROM fp_labels").fetchone()[0] == "real"
    assert unmark(conn, [a]) == [f"Finding {a}: mark removed."]


def test_marked_false_positives_leave_rankings_and_alerts(conn, settings):
    lab(conn)
    conn.execute("INSERT INTO kev (cve, date_added, first_seen_at) VALUES ('CVE-2099-0001', '2099-01-01', 'x')")
    ids = [fid(conn, f"fake-web-0{i}", "7001") for i in range(1, 5)]
    mark(conn, ids, real=False, reason="banner")
    ranked = prioritize(conn, settings)
    assert {r.title for r in ranked} == {"FAKE real issue"}
    assert "CVE-2099-0001" not in open_cves(conn)


def test_similarity_mode_flags_lookalikes_with_reason(conn, settings):
    lab(conn)
    mark(conn, [fid(conn, "fake-web-01", "7001"), fid(conn, "fake-web-02", "7001")], real=False, reason=None)
    flagged, note = predict(conn, settings)
    assert "2 false-positive marks so far" in note and "above 50%; nothing is hidden automatically" in note
    assert {p.machine for p in flagged} == {"fake-web-03", "fake-web-04"}
    p = flagged[0]
    assert p.method == "similarity" and p.probability == pytest.approx(0.93, abs=0.01)
    assert "You marked 2 finding(s) from the same nessus rule 7001" in p.reason
    assert "and none as real or fixed" in p.reason and "alike to finding" in p.reason
    # The unrelated finding is never flagged.
    assert all("real issue" not in p.title for p in flagged)


def test_conflicting_marks_lower_the_probability(conn, settings):
    lab(conn)
    mark(conn, [fid(conn, "fake-web-01", "7001")], real=False, reason=None)
    mark(conn, [fid(conn, "fake-web-02", "7001")], real=True, reason=None)
    flagged, _ = predict(conn, settings)
    # 1 false positive vs 1 real: (1 + 0.5) / (1 + 1 + 1) = 0.5, and the output matches both equally,
    # so nothing goes above the 50% threshold.
    assert flagged == []


def test_no_marks_yet(conn, settings):
    lab(conn)
    assert predict(conn, settings) == ([], "No findings are marked as false positives yet. Use `vmt fp mark <id>` first.")


def test_model_mode_on_fake_data(tmp_path, settings):
    pytest.importorskip("sklearn")
    path = tmp_path / "fake.db"
    generate(path, tmp_path / "vmt.db", machines=40, days=120, end=datetime(2099, 6, 1, tzinfo=timezone.utc))
    conn = db.connect(path)
    n_fp = conn.execute("SELECT count(*) FROM fp_labels WHERE label = 'false_positive' AND is_fake = 1").fetchone()[0]
    assert n_fp >= 30
    flagged, note = predict(conn, settings)
    assert note.startswith("Cross-validated on your") and "precision" in note
    assert flagged and all(p.method == "model" for p in flagged)
    # The generator's false-positive pattern is banner-based checks; the model should find those.
    banner = conn.execute("SELECT id FROM findings WHERE evidence LIKE '%service banner%'").fetchall()
    assert {p.finding_id for p in flagged[:10]} <= {r[0] for r in banner}
    assert "Pushed toward false positive by:" in flagged[0].reason
    conn.close()
