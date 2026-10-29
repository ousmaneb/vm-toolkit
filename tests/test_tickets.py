import dataclasses
import json

import pytest
import responses

from vmtoolkit.config import ConfigError
from vmtoolkit.normalize import Finding, Host, ScanResult, store_scan
from vmtoolkit.tickets import generate, push_jira, push_servicenow, ticket_id, tickets_dir

JIRA = "https://fake-jira.invalid"
SN = "https://fake-sn.invalid"


def scan(conn, run, when, ssl=True):
    findings = [Finding("20", "FAKE web issue", "medium", cvss_score=5.0, solution="Upgrade FakeHTTPd to 2.4.99.")]
    if ssl:
        findings.append(Finding("CVE-2099-0001", "FAKE fakessl overflow", "critical", cves=["CVE-2099-0001"],
                                cvss_score=9.8, package="fakessl", installed_version="3.0.0", fixed_version="3.0.2"))
    store_scan(conn, ScanResult("trivy", "fake", run, when, hosts=[Host("fake-app-01", credentialed=True,
                                                                         findings=findings)]))


@pytest.fixture
def lab(conn):
    scan(conn, "1", "2099-01-01T00:00:00Z")
    conn.execute("INSERT INTO kev (cve, date_added, first_seen_at) VALUES ('CVE-2099-0001', '2099-01-01', 'x')")
    conn.commit()
    return conn


def ssl_ticket():
    return ticket_id("package:fakessl")


def test_files_have_priority_due_date_and_reasons(lab, settings):
    lines = generate(lab, settings)
    assert lines[0].endswith("2 created, 0 updated, 0 unchanged, 0 resolved, 0 reopened")
    md = (tickets_dir(settings) / f"{ssl_ticket()}.md").read_text(encoding="utf-8")
    assert md.startswith(f"# {ssl_ticket()}: Upgrade fakessl to 3.0.2 or later")
    assert "- Priority: P3" in md  # score 100 x 1.0 x 0.98 x 0.5 x 0.8 = 39.2, under P2's 40
    assert "P3 because its highest-scoring finding (FAKE fakessl overflow on fake-app-01) scores 39.2" in md
    data = json.loads((tickets_dir(settings) / f"{ssl_ticket()}.json").read_text(encoding="utf-8"))
    assert data["due_date"] == "2099-01-16"
    assert "critical finding first seen 2099-01-01 plus 15 days" in data["due_reason"]
    assert "fake-app-01 (1 finding)" in md
    assert "| 1 | 39.2 | fake-app-01 | critical | FAKE fakessl overflow | CVE-2099-0001 | 2099-01-01 |" in md


def test_rerun_is_stable_and_fix_resolves_ticket(lab, settings):
    generate(lab, settings)
    assert generate(lab, settings)[0].endswith("0 created, 0 updated, 2 unchanged, 0 resolved, 0 reopened")
    scan(lab, "2", "2099-01-08T00:00:00Z", ssl=False)
    assert generate(lab, settings)[0].endswith("0 created, 0 updated, 1 unchanged, 1 resolved, 0 reopened")
    row = lab.execute("SELECT * FROM tickets WHERE ticket_id = ?", (ssl_ticket(),)).fetchone()
    assert (row["status"], row["status_note"]) == ("resolved", "all 1 finding fixed")
    md = (tickets_dir(settings) / f"{ssl_ticket()}.md").read_text(encoding="utf-8")
    assert "- Status: resolved" in md
    scan(lab, "3", "2099-01-15T00:00:00Z", ssl=True)
    assert generate(lab, settings)[0].endswith("1 reopened")


def test_max_fixes_does_not_resolve_skipped_tickets(lab, settings):
    generate(lab, settings)
    lines = generate(lab, settings, max_fixes=1)
    assert "0 resolved" in lines[0] and "1 lower-risk fixes have no ticket" in lines[1]


def jira_settings(settings):
    return dataclasses.replace(settings, raw={**settings.raw, "jira": {"url": JIRA, "project": "LAB"}})


@responses.activate
def test_jira_create_update_and_resolve(lab, settings, monkeypatch):
    monkeypatch.setenv("JIRA_EMAIL", "fake@example.invalid")
    monkeypatch.setenv("JIRA_API_TOKEN", "fake-token")
    s = jira_settings(settings)
    generate(lab, s)
    responses.post(f"{JIRA}/rest/api/2/issue", json={"key": "LAB-1"})
    responses.post(f"{JIRA}/rest/api/2/issue", json={"key": "LAB-2"})
    lines = push_jira(lab, s)
    assert len(lines) == 2 and all("created Jira" in line for line in lines)
    body = json.loads(responses.calls[0].request.body)
    assert body["fields"]["project"] == {"key": "LAB"} and "vmtoolkit" in body["fields"]["labels"]
    assert "Why" not in body["fields"]["description"] and "Priority P" in body["fields"]["description"]
    assert push_jira(lab, s) == ["Jira: nothing to send."]

    scan(lab, "2", "2099-01-08T00:00:00Z", ssl=False)
    generate(lab, s)
    key = lab.execute("SELECT jira_key FROM tickets WHERE ticket_id = ?", (ssl_ticket(),)).fetchone()[0]
    responses.post(f"{JIRA}/rest/api/2/issue/{key}/comment", json={})
    other = "LAB-1" if key == "LAB-2" else "LAB-2"
    responses.put(f"{JIRA}/rest/api/2/issue/{other}", status=204)
    lines = push_jira(lab, s)
    assert any(f"commented on Jira {key} that it is resolved" in line for line in lines)


@responses.activate
def test_servicenow_create_and_resolve(lab, settings, monkeypatch):
    monkeypatch.setenv("SN_USERNAME", "fake-user")
    monkeypatch.setenv("SN_PASSWORD", "fake-pass")
    s = dataclasses.replace(settings, raw={**settings.raw, "servicenow": {"instance": SN}})
    generate(lab, s)
    responses.post(f"{SN}/api/now/table/incident", json={"result": {"sys_id": "abc", "number": "INC0010001"}})
    responses.post(f"{SN}/api/now/table/incident", json={"result": {"sys_id": "def", "number": "INC0010002"}})
    push_servicenow(lab, s)
    first = json.loads(responses.calls[0].request.body)
    assert first["correlation_id"].startswith("VMT-") and first["urgency"] in ("1", "2", "3")

    scan(lab, "2", "2099-01-08T00:00:00Z", ssl=False)
    generate(lab, s)
    sys_id = lab.execute("SELECT servicenow_sys_id FROM tickets WHERE ticket_id = ?", (ssl_ticket(),)).fetchone()[0]
    other = "def" if sys_id == "abc" else "abc"
    responses.patch(f"{SN}/api/now/table/incident/{sys_id}", json={"result": {}})
    responses.patch(f"{SN}/api/now/table/incident/{other}", json={"result": {}})
    lines = push_servicenow(lab, s)
    resolve = next(json.loads(c.request.body) for c in responses.calls
                   if c.request.method == "PATCH" and c.request.url.endswith(sys_id))
    assert resolve["state"] == "6" and "all 1 finding fixed" in resolve["close_notes"]
    assert any("resolved ServiceNow" in line for line in lines)


def test_push_needs_config(lab, settings):
    generate(lab, settings)
    with pytest.raises(ConfigError, match=r"\[jira\] url"):
        push_jira(lab, settings)


def test_ticket_folder_follows_database(settings):
    assert tickets_dir(settings).name == "vmt-tickets"
    fake = dataclasses.replace(settings, db_override=settings.data_dir / "fake.db")
    assert tickets_dir(fake) == settings.data_dir / "fake-tickets"
