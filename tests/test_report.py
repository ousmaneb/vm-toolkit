from datetime import timedelta

import pytest

from vmtoolkit.db import parse_iso
from vmtoolkit.report import build, rate, report_path, snapshot

NOW = parse_iso("2099-03-01T00:00:00Z")


def add(conn, fid, severity, first, fixed=None, cve=None, fake=1):
    conn.execute("INSERT OR IGNORE INTO assets (id, name, is_fake) VALUES (1, 'fake-web-01', 1)")
    conn.execute(
        """INSERT INTO findings (id, fingerprint, asset_id, scanner, rule_id, title, severity, status,
                                 first_seen, last_seen, fixed_at, is_fake)
           VALUES (?, ?, 1, 'nessus', ?, ?, ?, ?, ?, ?, ?, ?)""",
        (fid, f"fp{fid}", str(fid), f"FAKE {fid}", severity, "fixed" if fixed else "open", first, first, fixed, fake))
    if cve:
        conn.execute("INSERT INTO finding_cves VALUES (?, ?)", (fid, cve))


@pytest.fixture
def lab(conn):
    add(conn, 1, "critical", "2099-02-01T00:00:00Z", cve="CVE-2099-0001")      # 28 days: past its 15-day deadline
    add(conn, 2, "high", "2099-02-26T00:00:00Z")                               # new this week
    add(conn, 3, "high", "2099-01-01T00:00:00Z", "2099-01-11T00:00:00Z")       # fixed in 10 days: on time
    add(conn, 4, "medium", "2098-12-01T00:00:00Z", "2099-02-27T00:00:00Z")     # fixed this week, 88 days: on time
    add(conn, 5, "low", "2099-01-01T00:00:00Z", "2099-02-25T00:00:00Z")        # fixed this week
    add(conn, 6, "info", "2099-01-01T00:00:00Z")                               # ignored
    conn.execute("INSERT INTO kev (cve, date_added, first_seen_at) VALUES ('CVE-2099-0001', '2099-02-20', "
                 "'2099-02-20T00:00:00Z')")
    conn.commit()
    return conn


def test_week_over_week_numbers(lab, settings):
    d = build(lab, settings, now=NOW)
    assert (d.now.open, d.now.critical_high, d.now.overdue, d.now.known_exploited) == (2, 2, 1, 1)
    # A week earlier finding 2 didn't exist yet, 4 and 5 were still open, and CVE-2099-0001 was already on KEV.
    assert (d.before.open, d.before.known_exploited) == (3, 1)
    assert (d.new, d.fixed) == (1, 2)
    assert d.on_time_rate == 1.0  # 3 fixes in the last 90 days, all within deadline
    assert d.fake


def test_known_exploited_past_deadline_is_red(lab, settings):
    d = build(lab, settings, now=NOW)
    assert d.status == "red"
    assert d.status_reason.startswith("1 vulnerability that attackers are known to exploit is past its fix deadline")
    assert any("1 actively exploited vulnerability past deadline" in a for a in d.attention)


def test_status_rules(lab, settings):
    d = build(lab, settings, now=NOW)
    for r in d.kev_open:
        r["overdue"] = False
    assert rate(d)[0] == "red"  # still a critical past deadline
    next(c for c in d.compliance if c["severity"] == "critical")["overdue"] = 0
    assert rate(d)[0] == "amber"
    d.now.overdue, d.on_time_rate = 0, 0.95
    assert rate(d) == ("green", "Nothing is past its deadline and recent fixes met their deadlines.")


def test_kev_counts_only_from_the_day_it_was_listed(lab):
    from vmtoolkit.report import _kev, load_findings
    findings, kev = load_findings(lab), _kev(lab)
    sla = {"critical": 15, "high": 30, "medium": 90, "low": 180}
    assert snapshot(findings, kev, sla, NOW - timedelta(days=10)).known_exploited == 0
    assert snapshot(findings, kev, sla, NOW).known_exploited == 1


def test_summary_reads_as_sentences(lab, settings):
    d = build(lab, settings, now=NOW)
    assert d.summary[0] == "There are 2 open vulnerabilities, 1 fewer than last week: 1 found and 2 fixed in the period."
    assert d.summary[1].startswith("1 of them is on CISA's list")


def test_report_path_names(settings, tmp_path):
    assert report_path(settings, "ceo", NOW).name == "2099-03-01-ceo.pdf"
    assert report_path(settings, "ceo", NOW, days=30).name == "2099-03-01-ceo-30d.pdf"
    other = type(settings)(raw=settings.raw, base_dir=settings.base_dir, db_override=tmp_path / "fake.db")
    assert report_path(other, "ciso", NOW).name == "2099-03-01-fake-ciso.pdf"


def test_pdfs_render(lab, settings, tmp_path):
    pytest.importorskip("reportlab")
    pypdf = pytest.importorskip("pypdf")
    from vmtoolkit.report_pdf import render

    d = build(lab, settings, now=NOW)
    ceo = render(d, "ceo", tmp_path / "ceo.pdf", "fake.db")
    ciso = render(d, "ciso", tmp_path / "ciso.pdf", "fake.db")
    ceo_pages, ciso_pages = pypdf.PdfReader(ceo).pages, pypdf.PdfReader(ciso).pages
    # A one-page summary and a page of plain-English advice; the CISO version adds the detail.
    assert len(ceo_pages) == 2 and len(ciso_pages) > 2
    text = ceo_pages[0].extract_text()
    assert "Status: RED" in text and "FAKE DATA" in text and "weekly summary" in text
    advice = ceo_pages[1].extract_text()
    assert "What this means for the business" in advice and "What we recommend" in advice
    assert "Terms used in this report" in advice
    assert "Deadline compliance" in "".join(p.extract_text() for p in ciso_pages)


def test_plain_english_advice(lab, settings):
    d = build(lab, settings, now=NOW)
    assert d.impact[0].startswith("Criminals are actively using 1 weakness that we still have. It shows up as 1 "
                                  "open problem on 1 computer.")
    assert d.impact[1].startswith("That problem is past our own fix deadline.")
    assert d.advice[0][0] == "Fix the 1 overdue actively exploited problem this week."
    assert any(q.startswith("Which of the actively exploited weaknesses") for q in d.questions)


def test_no_trend_claimed_without_earlier_data(conn, settings):
    add(conn, 1, "high", "2099-02-27T00:00:00Z")
    conn.commit()
    d = build(conn, settings, now=NOW)
    assert any(s.startswith("This is the first period with scan results") for s in d.impact)
    assert not any(a == "Stop the backlog growing." for a, _ in d.advice)


def test_monthly_report(lab, settings):
    d = build(lab, settings, days=30, now=NOW)
    assert d.days == 30 and d.summary[0].endswith("in the period.") and "30 days ago" in d.summary[0]
