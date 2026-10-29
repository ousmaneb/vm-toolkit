import dataclasses

import pytest

from vmtoolkit.assets import asset_config
from vmtoolkit.config import ConfigError
from vmtoolkit.dedupe import dedupe
from vmtoolkit.normalize import Finding, Host, ScanResult, store_scan


def scan(scanner, hosts, run="1", when="2099-01-01T00:00:00Z"):
    return ScanResult(scanner=scanner, source_id=f"fake-{scanner}", run_id=run, finished_at=when, hosts=hosts)


def with_assets(settings, assets):
    return dataclasses.replace(settings, raw={**settings.raw, "assets": assets})


def dup_rows(conn):
    return {r["finding_id"]: dict(r) for r in conn.execute("SELECT * FROM duplicates")}


def finding_id(conn, scanner, rule_id):
    return conn.execute("SELECT id FROM findings WHERE scanner = ? AND rule_id = ?", (scanner, rule_id)).fetchone()[0]


def test_shared_cve_across_scanners_on_same_ip(conn, settings):
    store_scan(conn, scan("nessus", [Host("fake-db-01.lab", ip="192.0.2.20", findings=[
        Finding("1001", "FAKE PostgreSQL overflow", "high", cves=["CVE-2099-0001"], port=5432, protocol="tcp")])]))
    store_scan(conn, scan("openvas", [Host("192.0.2.20", ip="192.0.2.20", findings=[
        Finding("1.3.6.1.fake", "FAKE Postgres vulnerability", "critical", cves=["CVE-2099-0001"], port=5432,
                protocol="tcp")])]))
    lines = dedupe(conn, settings)
    assert "Treated as one machine: fake-db-01.lab and 192.0.2.20 share IP 192.0.2.20." in lines
    rows = dup_rows(conn)
    # The critical OpenVAS report is kept as the primary; the high Nessus one is the duplicate.
    nessus = finding_id(conn, "nessus", "1001")
    assert list(rows) == [nessus]
    assert rows[nessus]["primary_id"] == finding_id(conn, "openvas", "1.3.6.1.fake")
    assert "both report CVE-2099-0001" in rows[nessus]["reason"]
    assert rows[nessus]["confidence"] == "high"
    assert lines[-1] == "1 of 2 findings are duplicates of another scanner's report."


def test_same_package_version_and_short_host_name(conn, settings):
    store_scan(conn, scan("trivy", [Host("fake-app-01", findings=[
        Finding("CVE-2099-0005", "FAKE fakessl issue", "high", cves=["CVE-2099-0005"], package="fakessl",
                installed_version="3.0.0")])]))
    store_scan(conn, scan("nessus", [Host("fake-app-01.lab", findings=[
        Finding("2001", "FAKE fakessl < 3.0.9 multiple issues", "high", package="fakessl",
                installed_version="3.0.0")])]))
    lines = dedupe(conn, settings)
    assert any("have the same host name fake-app-01" in line for line in lines)
    (row,) = dup_rows(conn).values()
    assert "both flag fakessl 3.0.0" in row["reason"]


def test_similar_titles_without_cves_need_same_port(conn, settings):
    store_scan(conn, scan("nessus", [Host("fake-web-01", ip="192.0.2.5", findings=[
        Finding("3001", "SSL Certificate Cannot Be Trusted", "medium", port=443, protocol="tcp"),
        Finding("3002", "SSH Weak Algorithms Supported", "low", port=22, protocol="tcp")])]))
    store_scan(conn, scan("openvas", [Host("192.0.2.5", ip="192.0.2.5", findings=[
        Finding("oid-1", "SSL Certificate cannot be trusted", "medium", port=443, protocol="tcp"),
        Finding("oid-2", "SSH Weak Algorithms Supported", "low", port=2222, protocol="tcp")])]))
    dedupe(conn, settings)
    (row,) = dup_rows(conn).values()
    assert row["confidence"] == "medium"
    assert "similar titles" in row["reason"] and "port 443/tcp" in row["reason"]


def test_same_scanner_and_different_machines_are_not_duplicates(conn, settings):
    f = Finding("1001", "FAKE", "high", cves=["CVE-2099-0001"], port=443, protocol="tcp")
    store_scan(conn, scan("nessus", [
        Host("fake-a", ip="192.0.2.1", findings=[f, dataclasses.replace(f, port=8443)]),
        Host("fake-b", ip="192.0.2.2", findings=[f])]))
    store_scan(conn, scan("openvas", [Host("192.0.2.3", ip="192.0.2.3", findings=[dataclasses.replace(f, rule_id="x")])]))
    dedupe(conn, settings)
    assert dup_rows(conn) == {}


def test_config_alias_links_machines(conn, settings):
    store_scan(conn, scan("nessus", [Host("fake-docker-01.lab", ip="192.0.2.9", findings=[
        Finding("1", "FAKE", "high", cves=["CVE-2099-0007"])])]))
    store_scan(conn, scan("trivy", [Host("fake-registry.lab/app:1.0", findings=[
        Finding("CVE-2099-0007", "FAKE", "high", cves=["CVE-2099-0007"], package="fakepkg")])]))
    dedupe(conn, settings)
    assert dup_rows(conn) == {}
    s = with_assets(settings, {"fake-docker-01.lab": {"aliases": ["fake-registry.lab/app:1.0"]}})
    lines = dedupe(conn, s)
    assert any('aliases in [assets."fake-docker-01.lab"]' in line for line in lines)
    assert len(dup_rows(conn)) == 1


def test_rerun_rebuilds_instead_of_piling_up(conn, settings):
    test_shared_cve_across_scanners_on_same_ip(conn, settings)
    dedupe(conn, settings)
    assert len(dup_rows(conn)) == 1


def test_asset_config_lookup(settings):
    s = with_assets(settings, {
        "fake-db-*": {"criticality": "high"},
        "fake-db-01.lab": {"criticality": "critical", "internet_facing": True, "aliases": ["192.0.2.20"]},
    })
    exact = asset_config(s, "fake-db-01.lab")
    assert (exact.criticality, exact.internet_facing, exact.weight) == ("critical", True, 1.0)
    assert asset_config(s, "192.0.2.20").matched == "fake-db-01.lab"
    assert asset_config(s, "FAKE-DB-02.lab").matched == "fake-db-*"
    default = asset_config(s, "fake-web-01")
    assert (default.criticality, default.matched) == ("medium", None)


def test_bad_criticality_is_a_config_error(settings):
    with pytest.raises(ConfigError, match="criticality must be one of"):
        asset_config(with_assets(settings, {"x": {"criticality": "urgent"}}), "x")
