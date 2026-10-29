import pytest
import responses
from typer.testing import CliRunner

from conftest import FIXTURES
from helpers import make_nessus
from vmtoolkit.cli import app
from vmtoolkit.nessus import NessusClient, pull, reimport
from vmtoolkit.normalize import store_scan
from vmtoolkit.parsers import detect_format, parse_file
from vmtoolkit.parsers.nessus import parse_nessus_file

OPENVAS = FIXTURES / "openvas_report.xml"
TRIVY = FIXTURES / "trivy_report.json"


def write_run(tmp_path, name, hosts, end_ts, **kw):
    path = tmp_path / name
    path.write_bytes(make_nessus(hosts, end_ts=end_ts, **kw))
    return path


def status_of(conn, rule_id):
    return conn.execute("SELECT * FROM findings WHERE rule_id = ?", (rule_id,)).fetchone()


def test_detect_format(tmp_path):
    nessus = write_run(tmp_path, "a.nessus", {"h": []}, 1)
    assert detect_format(nessus) == "nessus"
    assert detect_format(OPENVAS) == "openvas"
    assert detect_format(TRIVY) == "trivy"
    other = tmp_path / "x.json"
    other.write_text('{"hello": 1}', encoding="utf-8")
    with pytest.raises(ValueError, match="--format"):
        detect_format(other)


def test_openvas_parser():
    result = parse_file(OPENVAS)
    assert (result.scanner, result.name, result.run_id) == ("openvas", "FAKE lab GVM scan", "fake-report-0001")
    assert result.finished_at == "2026-10-01T10:45:12Z"
    hosts = {h.name: h for h in result.hosts}
    assert set(hosts) == {"fake-app-01.lab", "fake-clean-01.lab"}
    apache, tls = hosts["fake-app-01.lab"].findings
    assert (apache.severity, apache.port, apache.protocol, apache.cves) == ("critical", 443, "tcp", ["CVE-2099-1001"])
    assert apache.description == "Synthetic summary for tests."
    assert (tls.severity, tls.port) == ("medium", 0)
    assert hosts["fake-clean-01.lab"].findings[0].severity == "info"


def test_trivy_parser_and_host_override():
    result = parse_file(TRIVY, host="FAKE-Docker-01.lab")
    assert result.finished_at == "2026-10-02T08:30:00Z"
    host = result.hosts[0]
    assert host.name == "fake-docker-01.lab" and host.os == "debian 12.4"
    ssl, zlib, yaml = host.findings
    assert (ssl.severity, ssl.cvss_score, ssl.package, ssl.fixed_version) == ("critical", 9.1, "fakessl", "3.0.9")
    assert (zlib.severity, zlib.cvss_score, zlib.solution) == ("low", 5.5, None)
    assert yaml.cves == [] and yaml.rule_id == "GHSA-fake-0000-0001"


def test_bad_xml_is_a_clean_error(tmp_path):
    path = tmp_path / "broken.nessus"
    path.write_text("<NessusClientData_v2><Report>", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid XML"):
        parse_file(path)


def test_lifecycle_is_independent_of_import_order(tmp_path, conn):
    a = {"id": 1, "name": "FAKE A"}
    b = {"id": 2, "name": "FAKE B"}
    runs = [
        write_run(tmp_path, "1.nessus", {"fake-h1": [a, b]}, 1_790_000_000),
        write_run(tmp_path, "2.nessus", {"fake-h1": [a]}, 1_790_100_000),
        write_run(tmp_path, "3.nessus", {"fake-h1": [a, b]}, 1_790_200_000),
        write_run(tmp_path, "4.nessus", {"fake-h1": [a]}, 1_790_300_000),
    ]
    for path in reversed(runs):
        store_scan(conn, parse_nessus_file(path))
    b_row = status_of(conn, "2")
    # B came back in run 3 and was gone again in run 4, so it's fixed as of run 4.
    assert b_row["status"] == "fixed"
    assert b_row["first_seen"] == "2026-09-21T14:13:20Z"
    assert b_row["fixed_at"] == "2026-09-25T01:33:20Z"
    assert status_of(conn, "1")["status"] == "open"


def test_uncredentialed_scan_does_not_prove_a_fix(tmp_path, conn):
    item = {"id": 7, "name": "FAKE local check"}
    store_scan(conn, parse_nessus_file(write_run(tmp_path, "1.nessus", {"fake-h1": [item]}, 1_790_000_000)))
    store_scan(conn, parse_nessus_file(
        write_run(tmp_path, "2.nessus", {"fake-h1": []}, 1_790_100_000, credentialed=False)))
    row = status_of(conn, "7")
    assert row["status"] == "open"
    assert "not counted as fixed" in row["status_note"]


def test_host_not_in_later_scan_keeps_findings_open(tmp_path, conn):
    store_scan(conn, parse_nessus_file(write_run(tmp_path, "1.nessus", {"fake-h1": [{"id": 9}]}, 1_790_000_000)))
    store_scan(conn, parse_nessus_file(write_run(tmp_path, "2.nessus", {"fake-h2": []}, 1_790_100_000)))
    assert status_of(conn, "9")["status"] == "open"


def test_scanners_do_not_fix_each_others_findings(conn):
    store_scan(conn, parse_file(TRIVY, host="fake-app-01.lab"))
    store_scan(conn, parse_file(OPENVAS))
    statuses = {r["status"] for r in conn.execute("SELECT status FROM findings WHERE scanner = 'trivy'")}
    assert statuses == {"open"}


def test_cli_import(settings, tmp_path):
    nessus = write_run(tmp_path, "lab.nessus", {"fake-h1": [{"id": 1, "cves": ["CVE-2099-0001"]}]}, 1_790_000_000)
    runner = CliRunner()
    args = ["--config", str(settings.base_dir / "config.toml"), "import", str(nessus), str(OPENVAS), str(TRIVY),
            "--host", "fake-docker-01.lab"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "openvas FAKE lab GVM scan (run fake-report-0001): 2 hosts, 2 findings (2 new" in result.output
    again = runner.invoke(app, args)
    assert again.output.count("already imported") == 3


@responses.activate
def test_reimport_rebuilds_database_from_backups(settings, conn):
    url = "https://nessus.test:8834"
    responses.get(f"{url}/scans", json={"scans": [{"id": 5, "name": "FAKE weekly"}]})
    responses.get(f"{url}/scans/5", json={"info": {"name": "FAKE weekly"}, "history": [
        {"history_id": 1, "status": "completed", "creation_date": 1_789_999_000, "last_modification_date": 1_790_000_000},
    ]})
    responses.post(f"{url}/scans/5/export", json={"file": 1})
    responses.get(f"{url}/scans/5/export/1/status", json={"status": "ready"})
    responses.get(f"{url}/scans/5/export/1/download", body=make_nessus({"fake-h1": [{"id": 1}]}))
    pull(NessusClient(url, access_key="a", secret_key="b"), settings, conn)

    conn.execute("DELETE FROM scans")
    conn.execute("DELETE FROM findings")
    conn.commit()
    lines = reimport(settings, conn)
    assert lines == ["nessus FAKE weekly (run 1): 1 hosts, 1 findings (1 new, 0 now marked fixed)"]
