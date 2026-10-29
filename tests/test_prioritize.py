import dataclasses

import pytest
from typer.testing import CliRunner

from vmtoolkit.cli import app
from vmtoolkit.normalize import Finding, Host, ScanResult, store_scan
from vmtoolkit.prioritize import prioritize


def add(conn, scanner, host, findings, ip=None):
    store_scan(conn, ScanResult(scanner=scanner, source_id=f"fake-{scanner}", run_id=host,
                                finished_at="2099-01-01T00:00:00Z", hosts=[Host(host, ip=ip, findings=findings)]))


def intel(conn, cve, epss=None, kev=False, exploit=False, cvss=None, vector=None):
    if epss is not None:
        conn.execute("INSERT INTO epss_history VALUES (?, '2099-01-01', ?, 0.5)", (cve, epss))
    if kev:
        conn.execute("INSERT INTO kev (cve, date_added, first_seen_at) VALUES (?, '2099-01-01', 'x')", (cve,))
    if exploit:
        conn.execute("INSERT INTO exploits VALUES (?, 'exploit-db', '99999', 'FAKE')", (cve,))
    if cvss is not None or vector:
        conn.execute("INSERT INTO cves (cve, cvss_score, attack_vector) VALUES (?, ?, ?)", (cve, cvss, vector))
    conn.commit()


@pytest.fixture
def cfg(settings):
    return dataclasses.replace(settings, raw={**settings.raw, "assets": {
        "fake-db-01": {"criticality": "critical", "internet_facing": True},
        "fake-dev-*": {"criticality": "low"},
    }})


def by_title(ranked):
    return {r.title: r for r in ranked}


def test_score_combines_factors_and_explains(conn, cfg):
    add(conn, "nessus", "fake-db-01", [Finding("1", "FAKE kev bug", "high", cves=["CVE-2099-0001"], cvss_score=9.0)])
    add(conn, "nessus", "fake-dev-01", [Finding("2", "FAKE epss bug", "critical", cves=["CVE-2099-0002"], cvss_score=10.0)])
    intel(conn, "CVE-2099-0001", epss=0.02, kev=True, vector="network")
    intel(conn, "CVE-2099-0002", epss=0.40)
    ranked = by_title(prioritize(conn, cfg))

    kev = ranked["FAKE kev bug"]
    assert (kev.rank, kev.score) == (1, 90.0)  # 100 x 1.0 x 0.9 x 1.0 x 1.0
    text = kev.explain()
    assert "CVE-2099-0001 is on CISA KEV" in text
    assert 'fake-db-01 is critical ([assets."fake-db-01"])' in text
    assert "internet-facing and attackable over the network" in text
    assert "Ranked first" in text

    dev = ranked["FAKE epss bug"]
    assert dev.score == 8.0  # 100 x 0.40 x 1.0 x 0.25 x 0.8
    assert '([assets."fake-dev-*"])' in dev.explain()
    assert "not internet-facing" in dev.explain()
    assert "Ranked below #1 because its score is lower (8.0 vs 90.0)" in dev.rank_reason


def test_public_exploit_floor_and_missing_data(conn, cfg):
    add(conn, "nessus", "fake-web-01", [
        Finding("1", "FAKE exploit bug", "medium", cves=["CVE-2099-0003"]),
        Finding("2", "FAKE no cve", "high"),
        Finding("3", "FAKE not enriched", "low", cves=["CVE-2099-0004"]),
    ])
    intel(conn, "CVE-2099-0003", epss=0.01, exploit=True, cvss=6.5)
    ranked = by_title(prioritize(conn, cfg))
    exploit = ranked["FAKE exploit bug"]
    assert exploit.likelihood == 0.5
    assert "raised to 0.50 because a public exploit exists (exploit-db 99999)" in exploit.explain()
    assert "CVSS 6.5 (NVD)" in exploit.explain()
    assert "not listed in config, so the default" in exploit.explain()
    no_cve = ranked["FAKE no cve"]
    assert no_cve.likelihood == 0.2 and "no CVE" in no_cve.explain()
    assert "typical for high" in no_cve.explain()
    assert "run `vmt enrich`" in ranked["FAKE not enriched"].explain()


def test_local_attack_vector_is_not_boosted_on_internet_facing_machine(conn, cfg):
    add(conn, "nessus", "fake-db-01", [Finding("1", "FAKE local", "high", cves=["CVE-2099-0005"], cvss_score=7.0)])
    intel(conn, "CVE-2099-0005", epss=0.5, vector="local")
    (r,) = prioritize(conn, cfg)
    assert r.exposure == 0.8 and "attack vector is local, not network" in r.explain()


def test_duplicates_counted_once_with_all_cves(conn, cfg):
    add(conn, "nessus", "fake-app-01", [Finding("1", "FAKE dup", "high", cves=["CVE-2099-0006"], port=443,
                                                protocol="tcp")], ip="192.0.2.40")
    add(conn, "openvas", "192.0.2.40", [Finding("x", "FAKE dup ov", "high", cves=["CVE-2099-0006", "CVE-2099-0007"],
                                                port=443, protocol="tcp")], ip="192.0.2.40")
    intel(conn, "CVE-2099-0007", kev=True)
    ranked = prioritize(conn, cfg)
    assert len(ranked) == 1
    assert ranked[0].on_kev  # KEV status came from the duplicate's extra CVE
    assert "also reported by" in ranked[0].explain()


def test_ties_and_fixed_findings(conn, cfg):
    store_scan(conn, ScanResult("nessus", "s", "1", "2099-01-01T00:00:00Z", hosts=[Host("fake-x", findings=[
        Finding("1", "FAKE older", "high"), Finding("2", "FAKE gone later", "high")])]))
    store_scan(conn, ScanResult("nessus", "s", "2", "2099-02-01T00:00:00Z", hosts=[Host("fake-x", findings=[
        Finding("1", "FAKE older", "high"), Finding("3", "FAKE newer", "high")])]))
    ranked = prioritize(conn, cfg)
    assert [r.title for r in ranked] == ["FAKE older", "FAKE newer"]  # the fixed one isn't ranked
    assert "first seen later (2099-02-01 vs 2099-01-01)" in ranked[1].rank_reason


def test_cli_table_and_explain(conn, settings):
    add(conn, "nessus", "fake-db-01", [Finding("1", "FAKE kev bug", "high", cves=["CVE-2099-0001"], cvss_score=9.0)])
    intel(conn, "CVE-2099-0001", kev=True)
    config = str(settings.base_dir / "config.toml")
    out = CliRunner().invoke(app, ["--config", config, "prioritize"]).output
    assert "FAKE kev bug  [KEV]" in out and "1 open findings ranked" in out
    explained = CliRunner().invoke(app, ["--config", config, "prioritize", "--explain", "1"]).output
    assert explained.startswith("#1 score 36.0")  # 100 x 1.0 x 0.9 x 0.5 x 0.8
    assert "isn't ranked" in CliRunner().invoke(app, ["--config", config, "prioritize", "--explain", "999"]).output
