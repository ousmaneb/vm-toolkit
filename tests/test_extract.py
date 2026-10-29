import json
from types import SimpleNamespace

import pytest
import responses
from typer.testing import CliRunner

from conftest import FIXTURES
from vmtoolkit import extract as ex
from vmtoolkit.llm import LLMError, usage_line
from vmtoolkit.cli import app
from vmtoolkit.normalize import Finding, Host, ScanResult, store_scan

ADVISORY = FIXTURES / "advisory.html"


class FakeLLM:
    """Stands in for the AI provider's client; records the request and returns a canned response."""

    def __init__(self, payload=None, stop_reason="end_turn"):
        self.payload, self.stop_reason, self.calls = payload, stop_reason, []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        text = json.dumps(self.payload) if self.payload is not None else ""
        return SimpleNamespace(
            stop_reason=self.stop_reason, stop_details=SimpleNamespace(category="cyber"),
            content=[SimpleNamespace(type="text", text=text)], model=kwargs["model"],
            usage=SimpleNamespace(input_tokens=1200, output_tokens=300))


def test_html_to_text_skips_scripts_and_navigation():
    text, title = ex.load(str(ADVISORY), settings=None)
    assert title == "FAKE-SA-2099-01: FakeHTTPd security update"
    assert "CVE-2099-0000" not in text and "CVE-2099-9999" not in text
    assert "CVE-2099-1111" in text


def test_rule_based_extraction():
    text, title = ex.load(str(ADVISORY), settings=None)
    result = ex.extract_rules(text, str(ADVISORY), title)
    assert result.cves == ["CVE-2099-1111", "CVE-2099-2222"]
    values = {(i.cve, i.kind, i.value) for i in result.items}
    assert ("CVE-2099-1111", "affected", "2.4.0 through 2.4.58") in values
    assert ("CVE-2099-1111", "fixed", "2.4.59") in values
    assert ("CVE-2099-2222", "affected", "before 2.4.57") in values
    assert result.status("CVE-2099-2222")[0] == "exploited_in_the_wild"
    assert result.status("CVE-2099-1111")[0] == "public_poc"
    # "upgrade to 2.4.59 or later" names no CVE, so it goes to the CVE named just before it.
    assert any(i.cve == "CVE-2099-1111" and i.value == "2.4.59" and i.scope == "section" for i in result.items)
    assert not any(i.cve == "CVE-2099-2222" and i.kind == "fixed" for i in result.items)


def test_section_text_stays_with_its_cve():
    text = ("Vendor notes for this release.\n\nCVE-2099-0001: header overflow.\n\nAffects 1.0 through 1.4. "
            "This issue is known to be exploited in the wild.\n\nCVE-2099-0002: log injection.\n\n"
            "Affects 1.2 through 1.4. Fixed in 1.5.")
    result = ex.extract_rules(text, "x", "x")
    assert result.status("CVE-2099-0001")[0] == "exploited_in_the_wild"
    assert result.status("CVE-2099-0002")[0] == "not_stated"
    assert {i.value for i in result.items if i.cve == "CVE-2099-0002"} == {"1.2 through 1.4", "1.5"}


def test_not_known_exploited_beats_the_word_exploit():
    result = ex.extract_rules("CVE-2099-3333 is fixed in 1.2.3. We are not aware of any exploitation of "
                              "this issue.", "x", "x")
    assert result.status("CVE-2099-3333")[0] == "not_known_exploited"


def test_ai_extraction_drops_unquoted_and_invented_facts(settings):
    text, title = ex.load(str(ADVISORY), settings=None)
    payload = {"cves": [
        {"cve": "CVE-2099-1111", "facts": [
            {"kind": "fixed", "value": "2.4.59", "quote": "CVE-2099-1111 is fixed in version 2.4.59."},
            {"kind": "affected", "value": "2.4.0 - 2.4.58", "quote": "FakeHTTPd versions 2.4.0 through 2.4.58"},
            {"kind": "fixed", "value": "2.4.60", "quote": "fixed in version 2.4.60"},   # not in the text
        ]},
        {"cve": "CVE-2099-7777", "facts": [                                             # not in the text
            {"kind": "exploitation", "value": "exploited_in_the_wild", "quote": "exploited in the wild"}]},
    ]}
    llm = FakeLLM(payload)
    result, usage = ex.extract_llm(text, "advisory", title, llm, settings)
    assert {(i.kind, i.value) for i in result.items} == {("fixed", "2.4.59"), ("affected", "2.4.0 - 2.4.58")}
    assert result.dropped == 2
    call = llm.calls[0]
    assert call["model"] == "test-model" and call["fallbacks"] == "default"
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert "untrusted input" in call["system"] and call["messages"][0]["content"].startswith("<advisory>")
    assert usage == "LLM (test-model): 1,200 input + 300 output tokens, about $0.011."


def test_refusal_is_reported(settings):
    with pytest.raises(LLMError, match="declined this request \\(category: cyber\\)"):
        ex.extract_llm("CVE-2099-1 text", "x", "x", FakeLLM({"cves": []}, stop_reason="refusal"), settings)


def test_usage_line_notes_fallback(settings):
    resp = SimpleNamespace(model="fallback-model", usage=SimpleNamespace(input_tokens=10, output_tokens=5))
    assert "Answered by fallback-model after test-model declined" in usage_line(resp, settings)


@responses.activate
def test_cli_url_and_link_to_open_findings(conn, settings):
    store_scan(conn, ScanResult("nessus", "fake", "1", "2099-01-01T00:00:00Z", hosts=[Host("fake-web-01", findings=[
        Finding("1", "FAKE", "high", cves=["CVE-2099-2222"])])]))
    responses.get("https://advisories.invalid/fake-sa", body=ADVISORY.read_text(encoding="utf-8"),
                  content_type="text/html")
    out = CliRunner().invoke(app, ["--config", str(settings.base_dir / "config.toml"), "extract",
                                   "https://advisories.invalid/fake-sa"]).output
    assert "CVE-2099-2222  (open on: fake-web-01)" in out
    assert "exploitation: exploited in the wild" in out
    assert conn.execute("SELECT count(*) FROM advisory_items").fetchone()[0] > 0


def test_llm_needs_a_key(settings):
    out = CliRunner().invoke(app, ["--config", str(settings.base_dir / "config.toml"), "extract", str(ADVISORY), "--llm"])
    assert out.exit_code != 0


def test_single_affected_version():
    result = ex.extract_rules("CVE-2099-0005: path traversal. Affects: 2.4.49", "x", "x")
    assert [(i.kind, i.value) for i in result.items] == [("affected", "2.4.49")]


def test_label_paragraphs_and_comparison_ranges():
    text = "CVE-2099-0006 (critical): FAKE path traversal\n\nAffects\n\n>=2.4.7, <=2.4.51\n\nFixed in FakeHTTPd Server 2.4.52"
    values = {(i.kind, i.value) for i in ex.extract_rules(text, "x", "x").items}
    assert values == {("affected", "2.4.7 through 2.4.51"), ("fixed", "2.4.52")}
