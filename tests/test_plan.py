from typer.testing import CliRunner

from vmtoolkit.cli import app
from vmtoolkit.normalize import Finding, Host, ScanResult, store_scan
from vmtoolkit.plan import plan


def add(conn, host, findings, scanner="nessus"):
    store_scan(conn, ScanResult(scanner=scanner, source_id="fake", run_id=f"{scanner}-{host}",
                                finished_at="2099-01-01T00:00:00Z", hosts=[Host(host, findings=findings)]))


def kev(conn, *cves):
    conn.executemany("INSERT INTO kev (cve, date_added, first_seen_at) VALUES (?, '2099-01-01', 'x')",
                     [(c,) for c in cves])
    conn.commit()


def lab(conn):
    """Synthetic lab: one package upgrade covers three findings on two machines."""
    add(conn, "fake-app-01", [
        Finding("CVE-2099-0001", "FAKE fakessl a", "critical", cves=["CVE-2099-0001"], cvss_score=9.8,
                package="fakessl", installed_version="3.0.0", fixed_version="3.0.2"),
        Finding("CVE-2099-0002", "FAKE fakessl b", "high", cves=["CVE-2099-0002"], cvss_score=7.5,
                package="fakessl", installed_version="3.0.0", fixed_version="3.0.10"),
    ], scanner="trivy")
    add(conn, "fake-app-02", [
        Finding("CVE-2099-0001", "FAKE fakessl a", "critical", cves=["CVE-2099-0001"], cvss_score=9.8,
                package="fakessl", installed_version="3.0.0", fixed_version="3.0.2"),
    ], scanner="trivy")
    add(conn, "fake-web-01", [
        Finding("10", "FAKE web issue", "medium", cvss_score=5.0, solution="Upgrade FakeHTTPd to 2.4.99."),
        Finding("11", "FAKE web issue 2", "medium", cvss_score=5.0, solution="upgrade fakehttpd to 2.4.99"),
        Finding("12", "FAKE odd issue", "low", cvss_score=2.0),
    ])
    kev(conn, "CVE-2099-0001", "CVE-2099-0002")


def test_fixes_are_grouped_and_ordered_by_risk(conn, settings):
    lab(conn)
    chosen, rest, summary = plan(conn, settings, target=1.0)
    assert [f.action for f in chosen] == [
        "Upgrade fakessl to 3.0.10 or later",
        "Upgrade FakeHTTPd to 2.4.99.",
        "Remediate: FAKE odd issue (the scanner gave no fix steps)",
    ]
    ssl = chosen[0]
    assert len(ssl.findings) == 3 and ssl.machines == {"fake-app-01", "fake-app-02"}
    assert "3.0.10 is the highest, so it covers all of them" in ssl.explain()
    assert "Removes risk" in ssl.explain() and "#1 FAKE fakessl a" in ssl.explain()
    assert chosen[-1].cumulative == 1.0 and rest == []
    assert summary.startswith("These 3 fixes remove 100% of the total risk")


def test_default_target_stops_at_80_percent(conn, settings):
    lab(conn)
    chosen, rest, summary = plan(conn, settings)
    assert len(chosen) == 1 and chosen[0].cumulative >= 0.8
    assert len(rest) == 2 and "The other 2 fixes remove the remaining" in summary


def test_max_fixes_and_stored_plan(conn, settings):
    lab(conn)
    chosen, rest, _ = plan(conn, settings, max_fixes=2)
    assert len(chosen) == 2
    stored = conn.execute("SELECT fix_key, rank FROM plan_fixes ORDER BY rank").fetchall()
    assert [r["rank"] for r in stored] == [1, 2, 3]
    assert conn.execute("SELECT count(*) FROM plan_items WHERE fix_key = ?", (stored[0]["fix_key"],)).fetchone()[0] == 3


def test_empty(conn, settings):
    assert plan(conn, settings)[2] == "No open findings, so there is nothing to fix."


def test_cli(conn, settings):
    lab(conn)
    config = str(settings.base_dir / "config.toml")
    out = CliRunner().invoke(app, ["--config", config, "plan", "--target", "100"]).output
    assert "       3        2  Upgrade fakessl to 3.0.10 or later" in out
    assert "These 3 fixes remove 100%" in out
    explained = CliRunner().invoke(app, ["--config", config, "plan", "--explain", "2"]).output
    assert explained.startswith("Fix 2: Upgrade FakeHTTPd to 2.4.99.")
