import json

import pytest
import requests
import responses

from helpers import make_nessus
from vmtoolkit.nessus import NessusClient, NessusError, pull, safe_name
from vmtoolkit.parsers.nessus import parse_nessus_file

URL = "https://nessus.test:8834"
KEYS = {"access_key": "fake-access", "secret_key": "fake-secret"}

RUN1 = make_nessus({"fake-web-01.lab": [
    {"id": 1001, "name": "FAKE OpenSSL issue", "cves": ["CVE-2099-0001"], "port": 443,
     "output": "Installed version : 1.0.0\nFixed version : 1.0.1"},
    {"id": 1002, "name": "FAKE SSH issue", "cves": ["CVE-2099-0002"], "port": 22},
    {"id": 1003, "name": "FAKE info item", "severity": 0},
]}, end_ts=1_790_000_000)
RUN2 = make_nessus({"fake-web-01.lab": [
    {"id": 1001, "name": "FAKE OpenSSL issue", "cves": ["CVE-2099-0001"], "port": 443},
]}, end_ts=1_790_600_000)


def client(**kw):
    return NessusClient(URL, sleep=lambda s: None, **{**KEYS, **kw})


@responses.activate
def test_api_keys_header():
    responses.get(f"{URL}/scans", json={"scans": [{"id": 5, "name": "FAKE"}]})
    assert client().list_scans() == [{"id": 5, "name": "FAKE"}]
    assert responses.calls[0].request.headers["X-ApiKeys"] == "accessKey=fake-access; secretKey=fake-secret"


@responses.activate
def test_username_password_login_and_logout():
    responses.post(f"{URL}/session", json={"token": "fake-token"})
    responses.get(f"{URL}/scans", json={"scans": None})
    responses.delete(f"{URL}/session", status=200)
    c = NessusClient(URL, username="fake-user", password="fake-pass")
    assert c.list_scans() == []
    assert responses.calls[1].request.headers["X-Cookie"] == "token=fake-token"
    c.close()
    assert responses.calls[-1].request.method == "DELETE"


def test_no_credentials():
    with pytest.raises(NessusError, match="No Nessus credentials"):
        NessusClient(URL)


@responses.activate
def test_401_message_does_not_leak_keys():
    responses.get(f"{URL}/scans", status=401)
    with pytest.raises(NessusError) as e:
        client().list_scans()
    assert "401" in str(e.value)
    assert "fake-secret" not in str(e.value)


@responses.activate
def test_tls_failure_gives_certificate_hint():
    responses.get(f"{URL}/scans", body=requests.exceptions.SSLError("certificate verify failed"))
    with pytest.raises(NessusError, match="ca_cert"):
        client().list_scans()


@responses.activate
def test_export_polls_until_ready():
    responses.post(f"{URL}/scans/5/export", json={"file": 77})
    responses.get(f"{URL}/scans/5/export/77/status", json={"status": "loading"})
    responses.get(f"{URL}/scans/5/export/77/status", json={"status": "ready"})
    responses.get(f"{URL}/scans/5/export/77/download", body=RUN1)
    assert client().export(5, 1) == RUN1
    assert responses.calls[0].request.params == {"history_id": "1"}
    assert json.loads(responses.calls[0].request.body) == {"format": "nessus"}


def test_parse_nessus_file(tmp_path):
    path = tmp_path / "r.nessus"
    path.write_bytes(RUN1)
    result = parse_nessus_file(path)
    assert result.scanner == "nessus" and result.name == "FAKE lab scan"
    host = result.hosts[0]
    assert host.name == "fake-web-01.lab" and host.ip == "192.0.2.10" and host.credentialed
    openssl = host.findings[0]
    assert openssl.severity == "high" and openssl.port == 443 and openssl.cvss_score == 7.5
    assert openssl.cves == ["CVE-2099-0001"]
    assert (openssl.installed_version, openssl.fixed_version) == ("1.0.0", "1.0.1")
    assert host.findings[2].severity == "info"


def test_safe_name_is_portable():
    assert safe_name('Lab: weekly <all>/"hosts"?') == "Lab_weekly_all_hosts"


def mock_two_runs(export_ok=True):
    responses.get(f"{URL}/scans", json={"scans": [{"id": 5, "name": "FAKE weekly"}]})
    history = [
        {"history_id": 2, "status": "completed", "creation_date": 1_790_599_000, "last_modification_date": 1_790_600_000},
        {"history_id": 1, "status": "completed", "creation_date": 1_789_999_000, "last_modification_date": 1_790_000_000},
        {"history_id": 3, "status": "aborted", "creation_date": 1_791_000_000},
    ]
    responses.get(f"{URL}/scans/5", json={"history": history, "hosts": [{"host_id": 1}]})
    if not export_ok:
        responses.post(f"{URL}/scans/5/export", status=403)
        return
    for hid, body in ((1, RUN1), (2, RUN2)):
        responses.post(f"{URL}/scans/5/export", json={"file": 100 + hid},
                       match=[responses.matchers.query_param_matcher({"history_id": str(hid)})])
        responses.get(f"{URL}/scans/5/export/{100 + hid}/status", json={"status": "ready"})
        responses.get(f"{URL}/scans/5/export/{100 + hid}/download", body=body)


@responses.activate
def test_pull_downloads_all_runs_and_tracks_fixes(settings, conn):
    mock_two_runs()
    lines = pull(client(), settings, conn)

    run_dir = settings.raw_dir / "nessus" / "5-FAKE_weekly"
    assert (run_dir / "1" / "report.nessus").read_bytes() == RUN1
    assert (run_dir / "2" / "scan.json").exists()
    assert any("aborted" in line for line in lines)

    rows = {r["rule_id"]: r for r in conn.execute("SELECT * FROM findings")}
    assert set(rows) == {"1001", "1002"}  # info finding skipped by default
    assert rows["1001"]["status"] == "open"
    assert rows["1001"]["first_seen"] == "2026-09-21T14:13:20Z"
    assert rows["1001"]["last_seen"] == "2026-09-28T12:53:20Z"
    assert rows["1002"]["status"] == "fixed"
    assert rows["1002"]["fixed_at"] == "2026-09-28T12:53:20Z"
    assert "not reported" in rows["1002"]["status_note"]
    assert conn.execute("SELECT count(*) FROM scans").fetchone()[0] == 2


@responses.activate
def test_pull_twice_does_not_redownload(settings, conn):
    mock_two_runs()
    pull(client(), settings, conn)
    exports = sum(1 for c in responses.calls if c.request.method == "POST")
    lines = pull(client(), settings, conn)
    assert sum(1 for c in responses.calls if c.request.method == "POST") == exports
    assert all("already imported" in line for line in lines if "aborted" not in line)


@responses.activate
def test_pull_falls_back_to_per_host_api(settings, conn):
    mock_two_runs(export_ok=False)
    responses.get(f"{URL}/scans/5/hosts/1", json={
        "info": {"host-ip": "192.0.2.20", "host-fqdn": "fake-db-01.lab", "Credentialed_Scan": "true"},
        "vulnerabilities": [{"plugin_id": 2001, "plugin_name": "FAKE DB issue", "severity": 4}],
    })
    responses.get(f"{URL}/scans/5/hosts/1/plugins/2001", json={
        "info": {"plugindescription": {"pluginattributes": {
            "description": "Synthetic", "solution": "Patch",
            "risk_information": {"cvss3_base_score": "9.8"},
            "ref_information": {"ref": [{"name": "cve", "values": {"value": ["CVE-2099-0003"]}}]},
        }}},
        "outputs": [{"plugin_output": "Installed version : 2.0", "ports": {"5432 / tcp / postgresql": []}}],
    })
    pull(client(), settings, conn)
    row = conn.execute("SELECT * FROM findings").fetchone()
    assert (row["severity"], row["port"], row["cvss_score"], row["installed_version"]) == ("critical", 5432, 9.8, "2.0")
    cve = conn.execute("SELECT cve FROM finding_cves").fetchone()[0]
    assert cve == "CVE-2099-0003"
    assert (settings.raw_dir / "nessus" / "5-FAKE_weekly" / "1" / "hosts" / "1.json").exists()
