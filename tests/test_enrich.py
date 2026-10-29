import dataclasses

import pytest
import responses

from vmtoolkit import enrich as en
from vmtoolkit.web import WebError, web_session

CVES = ["CVE-2099-0001", "CVE-2099-0002"]

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2099-0001", "vendorProject": "FakeVendor", "product": "FakeSSL",
     "vulnerabilityName": "FAKE overflow", "dateAdded": "2099-01-10", "dueDate": "2099-01-31",
     "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply updates."},
    {"cveID": "CVE-2099-9999", "dateAdded": "2099-02-01"},
]}
EPSS = {"data": [
    {"cve": "CVE-2099-0001", "epss": "0.91234", "percentile": "0.99", "date": "2099-03-01"},
    {"cve": "CVE-2099-0002", "epss": "0.00100", "percentile": "0.20", "date": "2099-03-01"},
]}


def nvd_item(cve, score=9.8, status="Analyzed"):
    return {"vulnerabilities": [{"cve": {
        "id": cve, "vulnStatus": status, "published": "2099-01-01T00:00:00.000",
        "descriptions": [{"lang": "es", "value": "Falso"}, {"lang": "en", "value": f"FAKE description of {cve}."}],
        "metrics": {
            "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0, "accessVector": "NETWORK"}}],
            "cvssMetricV31": [
                {"type": "Secondary", "cvssData": {"baseScore": 1.0, "attackVector": "LOCAL"}},
                {"type": "Primary", "cvssData": {"baseScore": score, "attackVector": "NETWORK",
                                                 "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
            ],
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}, {"lang": "en", "value": "NVD-CWE-noinfo"}]}],
    }}]}


EXPLOITDB_CSV = (
    "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes\n"
    "50001,exploits/fake/1.py,FAKE PoC for overflow,2099-01-02,tester,remote,linux,443,2099-01-02,,1,"
    "CVE-2099-0001;OSVDB-1\n"
    "50002,exploits/fake/2.py,FAKE unrelated,2099-01-02,tester,remote,linux,,2099-01-02,,1,CVE-2099-7777\n"
)
METASPLOIT = {
    "exploit_fake": {"type": "exploit", "fullname": "exploit/linux/fake/overflow", "name": "FAKE overflow RCE",
                     "references": ["CVE-2099-0001", "URL-https://example.invalid"]},
    "aux_fake": {"type": "auxiliary", "fullname": "auxiliary/scanner/fake", "references": ["CVE-2099-0002"]},
}


def mock_sources(nvd=True):
    responses.get(en.KEV_URL, json=KEV)
    responses.get(en.EPSS_URL, json=EPSS)
    if nvd:
        for cve in CVES:
            responses.get(en.NVD_URL, json=nvd_item(cve),
                          match=[responses.matchers.query_param_matcher({"cveId": cve})])
    responses.get(en.EXPLOITDB_URL, body=EXPLOITDB_CSV)
    responses.get(en.METASPLOIT_URL, json=METASPLOIT)


@pytest.fixture
def with_cves(conn):
    conn.execute("INSERT INTO assets (name) VALUES ('fake-h1')")
    conn.execute("""INSERT INTO findings (fingerprint, asset_id, scanner, rule_id, title, severity)
                    VALUES ('fp', 1, 'nessus', '1', 'FAKE', 'high')""")
    conn.executemany("INSERT INTO finding_cves VALUES (1, ?)", [(c,) for c in CVES])
    conn.commit()
    return conn


@responses.activate
def test_enrich_stores_everything(settings, with_cves):
    mock_sources()
    lines = en.enrich(with_cves, web_session(settings), sleep=lambda s: None)
    assert "Enriching 2 CVEs." in lines
    assert any("1 of your CVEs are on it" in line for line in lines)
    assert any("1 of your CVEs have a public exploit" in line for line in lines)

    c = with_cves.execute("SELECT * FROM cves WHERE cve = 'CVE-2099-0001'").fetchone()
    assert (c["cvss_score"], c["cvss_version"], c["attack_vector"], c["cwes"]) == (9.8, "3.1", "network", "CWE-787")
    assert c["description"] == "FAKE description of CVE-2099-0001."
    assert with_cves.execute("SELECT count(*) FROM kev").fetchone()[0] == 2
    assert with_cves.execute("SELECT epss FROM epss_history WHERE cve = 'CVE-2099-0001'").fetchone()[0] == 0.91234
    sources = {r["source"] for r in with_cves.execute("SELECT source FROM exploits")}
    assert sources == {"exploit-db", "metasploit"}  # auxiliary modules don't count


@responses.activate
def test_describe_cve_explains_in_words(settings, with_cves):
    mock_sources()
    en.enrich(with_cves, web_session(settings), sleep=lambda s: None)
    text = "\n".join(en.describe_cve(with_cves, "cve-2099-0001"))
    assert "CVSS 9.8 (v3.1, network attack vector)" in text
    assert "91.2% chance of exploitation activity in the next 30 days" in text
    assert "since 2099-01-10" in text and "ransomware" in text
    assert "exploit-db 50001 (FAKE PoC for overflow)" in text
    other = "\n".join(en.describe_cve(with_cves, "CVE-2099-0002"))
    assert "Not on the CISA" in other and "No public exploit found" in other


@responses.activate
def test_second_run_uses_cache(settings, with_cves):
    mock_sources()
    sleeps = []
    en.enrich(with_cves, web_session(settings), sleep=sleeps.append)
    calls = len(responses.calls)
    en.enrich(with_cves, web_session(settings), sleep=sleeps.append)
    assert len(responses.calls) == calls
    assert sleeps == [6.0]  # only between the two uncached NVD requests on the first run


@responses.activate
def test_offline_mode(settings, with_cves):
    mock_sources()
    en.enrich(with_cves, web_session(settings), sleep=lambda s: None)
    calls = len(responses.calls)
    offline = dataclasses.replace(settings, offline=True)
    en.enrich(with_cves, web_session(offline), sleep=lambda s: None)
    assert len(responses.calls) == calls
    with pytest.raises(WebError, match="Offline mode"):
        en.enrich(with_cves, web_session(offline), cves=["CVE-2099-5555"], sleep=lambda s: None)


@responses.activate
def test_nvd_api_key_sent_but_not_stored_in_cache(settings, with_cves):
    mock_sources()
    en.enrich(with_cves, web_session(settings), nvd_api_key="fake-nvd-key-0123456789", sleep=lambda s: None)
    nvd_call = next(c for c in responses.calls if c.request.url.startswith(en.NVD_URL))
    assert nvd_call.request.headers["apiKey"] == "fake-nvd-key-0123456789"
    assert b"fake-nvd-key-0123456789" not in settings.cache_path.read_bytes()


@responses.activate
def test_nvd_rate_limit_retries(settings, with_cves):
    responses.get(en.NVD_URL, status=403)
    responses.get(en.NVD_URL, json=nvd_item("CVE-2099-0001", status="Awaiting Analysis"))
    sleeps = []
    en.update_nvd(with_cves, web_session(settings), ["CVE-2099-0001"], sleep=sleeps.append)
    assert sleeps == [30]
    assert with_cves.execute("SELECT nvd_status FROM cves").fetchone()[0] == "Awaiting Analysis"


@responses.activate
def test_cve_missing_from_nvd(settings, with_cves):
    responses.get(en.NVD_URL, json={"vulnerabilities": []})
    en.update_nvd(with_cves, web_session(settings), ["CVE-2099-0404"], sleep=lambda s: None)
    assert "NVD has no record" in "\n".join(en.describe_cve(with_cves, "CVE-2099-0404"))


def test_no_cves_yet(settings, conn):
    assert en.enrich(conn, web_session(settings)) == ["No CVEs in the database yet. Import some scan results first."]


def test_percent_wording():
    assert en.top_pct(1.0) == "0.1%"
    assert en.top_pct(0.99) == "1.0%"
    assert en.pct_down(0.99996) == "99.9%"
