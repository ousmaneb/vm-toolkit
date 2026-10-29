import dataclasses
import random
from datetime import date

import pytest

pytest.importorskip("sklearn")

from vmtoolkit.ml.classifier import DescriptionClassifier, evaluate, explain, labels, predict_mine  # noqa: E402
from vmtoolkit.normalize import Finding, Host, ScanResult, store_scan  # noqa: E402
from vmtoolkit.prioritize import prioritize  # noqa: E402

# Synthetic description patterns, one per (CWE, attack vector).
PATTERNS = [
    ("CWE-79", "NETWORK", "stored cross site scripting via crafted script in the comment field"),
    ("CWE-89", "NETWORK", "sql injection in the login parameter allows database queries"),
    ("CWE-787", "LOCAL", "out of bounds write in the kernel driver lets a local user crash"),
    ("CWE-1321", "PHYSICAL", "debug port on the board exposes firmware to someone with physical access"),
]


def rec(i, published, cwe, vector, text, cna_only=False):
    cvss = {"attackVector": vector}
    return {"cve": f"CVE-2099-{i:05d}", "published": published, "description": f"FAKE product {text} {i % 7}",
            "cvss_cna": cvss if cna_only else None, "cvss_nvd": None if cna_only else cvss,
            "cwe_cna": [cwe] if cna_only else [], "cwe_nvd": [] if cna_only else [cwe],
            "vendors_cna": [], "vendors_cpe": []}


@pytest.fixture(scope="module")
def records():
    rng = random.Random(3)
    out = []
    for i in range(1200):
        cwe, vector, text = rng.choice(PATTERNS)
        out.append(rec(i, f"{2097 + i % 3}-0{1 + i % 9}-01", cwe, vector, text, cna_only=i % 5 == 0))
    return out


def test_labels_prefer_nvd_then_issuer():
    r = rec(1, "2099-01-01", "CWE-79", "NETWORK", "x", cna_only=True)
    assert labels(r) == ("CWE-79", "NETWORK")
    r["cwe_nvd"], r["cvss_nvd"] = ["CWE-89"], {"attackVector": "LOCAL"}
    assert labels(r) == ("CWE-89", "LOCAL")


def test_learns_and_explains(records):
    model = DescriptionClassifier(min_df=1).fit(records)
    (p,) = model.predict(["FAKE product sql injection in the search parameter"])
    assert p["cwe"] == "CWE-89" and p["attack_vector"] == "NETWORK"
    text = explain(p)
    assert text.startswith("Predicted CWE-89") and ("'injection'" in text or "'sql'" in text)
    (q,) = model.predict(["debug port on the board gives physical access to firmware"])
    assert q["attack_vector"] == "PHYSICAL"


def test_evaluate_reports_against_baseline(records):
    ev = evaluate(records, date(2099, 1, 1), min_df=1)
    assert ev.train_size == sum(1 for r in records if r["published"] < "2099-01-01")
    assert ev.cwe_top1 > ev.cwe_baseline[1]
    assert ev.cwe_top3 >= ev.cwe_top1
    text = ev.report()
    assert "right within the top 3" in text and "always guessing" in text and "CWE-20" in text


def test_predictions_only_for_unanalysed_cves_and_feed_prioritize(records, conn, settings):
    model = DescriptionClassifier(min_df=1).fit(records)
    store_scan(conn, ScanResult("nessus", "fake", "1", "2099-01-01T00:00:00Z", hosts=[Host("fake-h1", findings=[
        Finding("1", "FAKE analysed", "high", cves=["CVE-2099-90001"]),
        Finding("2", "FAKE awaiting", "high", cves=["CVE-2099-90002"]),
        Finding("3", "FAKE no description", "high", cves=["CVE-2099-90003"]),
    ])]))
    conn.execute("INSERT INTO cves (cve, description, cwes, attack_vector, nvd_status) VALUES "
                 "('CVE-2099-90001', 'x', 'CWE-79', 'network', 'Analyzed')")
    conn.execute("INSERT INTO cves (cve, description, nvd_status) VALUES "
                 "('CVE-2099-90002', 'out of bounds write in the kernel driver lets a local user crash', "
                 "'Awaiting Analysis')")
    conn.commit()
    rows, missing = predict_mine(conn, model, "2099-02-01T00:00:00Z", "2099-02-02T00:00:00Z", {})
    assert [r["cve"] for r in rows] == ["CVE-2099-90002"] and missing == ["CVE-2099-90003"]
    assert rows[0]["attack_vector"] == "LOCAL" and rows[0]["vector_confidence"] >= 0.8

    # The attack vector only matters on internet-facing machines.
    facing = dataclasses.replace(settings, raw={**settings.raw, "assets": {"fake-h1": {"internet_facing": True}}})
    ranked = {r.title: r for r in prioritize(conn, facing)}
    reason = ranked["FAKE awaiting"].explain()
    assert "attack vector is local, not network (predicted from the description" in reason
    assert "predicted" not in ranked["FAKE analysed"].explain()
