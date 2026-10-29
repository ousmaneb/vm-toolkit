"""Add EPSS, CISA KEV, NVD and public-exploit data to every CVE in the database."""

import csv
import io
import logging
import math
import re
import sqlite3
import time

import requests

from .db import utcnow
from .web import WebError, fetch

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
METASPLOIT_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
EPSS_BATCH = 100
# NVD allows 5 requests per 30 seconds without a key and 50 with one.
NVD_DELAY = {False: 6.0, True: 0.6}


def my_cves(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("SELECT DISTINCT cve FROM finding_cves ORDER BY cve")]


def update_kev(conn: sqlite3.Connection, session: requests.Session) -> int:
    """Store the full KEV catalog. Returns how many entries were new to this database."""
    resp = fetch(session, "GET", KEV_URL)
    if resp.status_code != 200:
        raise WebError(f"CISA KEV feed returned HTTP {resp.status_code}")
    now = utcnow()
    known = {r[0] for r in conn.execute("SELECT cve FROM kev")}
    entries = resp.json().get("vulnerabilities", [])
    with conn:
        for v in entries:
            conn.execute(
                """INSERT INTO kev (cve, vendor, product, name, date_added, due_date, ransomware,
                                    required_action, first_seen_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(cve) DO UPDATE SET due_date = excluded.due_date,
                       ransomware = excluded.ransomware, required_action = excluded.required_action""",
                (v["cveID"].upper(), v.get("vendorProject"), v.get("product"), v.get("vulnerabilityName"),
                 v.get("dateAdded"), v.get("dueDate"), v.get("knownRansomwareCampaignUse"),
                 v.get("requiredAction"), now),
            )
    return sum(1 for v in entries if v["cveID"].upper() not in known)


def update_epss(conn: sqlite3.Connection, session: requests.Session, cves: list[str]) -> int:
    stored = 0
    for i in range(0, len(cves), EPSS_BATCH):
        batch = cves[i:i + EPSS_BATCH]
        resp = fetch(session, "GET", EPSS_URL, params={"cve": ",".join(batch)})
        if resp.status_code != 200:
            raise WebError(f"EPSS API returned HTTP {resp.status_code}")
        with conn:
            for row in resp.json().get("data", []):
                conn.execute(
                    "INSERT OR REPLACE INTO epss_history (cve, date, epss, percentile) VALUES (?, ?, ?, ?)",
                    (row["cve"].upper(), row["date"], float(row["epss"]), float(row["percentile"])),
                )
                stored += 1
    return stored


def _pick_cvss(metrics: dict) -> tuple[float | None, str | None, str | None, str | None]:
    """Prefer NVD's own CVSS v3.1 score, then other v3.x, v4.0 and finally v2."""
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                         ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        entries = sorted(entries, key=lambda m: m.get("type") != "Primary")
        if entries:
            data = entries[0]["cvssData"]
            vector = data.get("attackVector") or data.get("accessVector")
            return data.get("baseScore"), version, data.get("vectorString"), vector
    return None, None, None, None


def parse_nvd(item: dict) -> dict:
    cve = item["cve"]
    score, version, vector, attack_vector = _pick_cvss(cve.get("metrics") or {})
    cwes = sorted({d["value"] for w in cve.get("weaknesses") or [] for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    return {
        "cve": cve["id"].upper(), "description": description, "cvss_score": score,
        "cvss_version": version, "cvss_vector": vector,
        "attack_vector": attack_vector.lower() if attack_vector else None,
        "cwes": ",".join(cwes) or None, "published": cve.get("published"),
        "last_modified": cve.get("lastModified"), "nvd_status": cve.get("vulnStatus"),
    }


def update_nvd(conn: sqlite3.Connection, session: requests.Session, cves: list[str],
               api_key: str | None = None, sleep=time.sleep) -> int:
    headers = {"apiKey": api_key} if api_key else {}
    delay = NVD_DELAY[bool(api_key)]
    stored = 0
    for n, cve in enumerate(cves, start=1):
        for attempt in range(4):
            resp = fetch(session, "GET", NVD_URL, params={"cveId": cve}, headers=headers)
            if resp.status_code not in (403, 429, 503):
                break
            # NVD answers 403 when the rate limit is hit.
            log.warning("NVD rate limit hit, waiting 30 seconds (attempt %d of 4)", attempt + 1)
            sleep(30)
        if resp.status_code != 200:
            raise WebError(f"NVD returned HTTP {resp.status_code} for {cve}")
        items = resp.json().get("vulnerabilities") or []
        row = parse_nvd(items[0]) if items else {"cve": cve, "nvd_status": "Not in NVD"}
        row["nvd_fetched_at"] = utcnow()
        with conn:
            conn.execute(
                f"INSERT OR REPLACE INTO cves ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                list(row.values()),
            )
        stored += 1
        if not getattr(resp, "from_cache", False) and n < len(cves):
            sleep(delay)
        if n % 25 == 0:
            log.info("NVD: %d of %d CVEs done", n, len(cves))
    return stored


def update_exploits(conn: sqlite3.Connection, session: requests.Session, cves: list[str]) -> int:
    wanted = {c.upper() for c in cves}
    found: list[tuple[str, str, str, str]] = []

    resp = fetch(session, "GET", EXPLOITDB_URL)
    if resp.status_code != 200:
        raise WebError(f"Exploit-DB list returned HTTP {resp.status_code}")
    reader = csv.DictReader(io.StringIO(resp.text))
    if "codes" not in (reader.fieldnames or []):
        raise WebError("Exploit-DB CSV format changed: no 'codes' column")
    for row in reader:
        for cve in CVE_RE.findall(row.get("codes") or ""):
            if cve.upper() in wanted:
                found.append((cve.upper(), "exploit-db", row["id"], row.get("description")))

    resp = fetch(session, "GET", METASPLOIT_URL)
    if resp.status_code != 200:
        raise WebError(f"Metasploit module list returned HTTP {resp.status_code}")
    for module in resp.json().values():
        if module.get("type") != "exploit":
            continue
        for ref in module.get("references") or []:
            if ref.upper() in wanted:
                found.append((ref.upper(), "metasploit", module.get("fullname", ""), module.get("name")))

    with conn:
        conn.execute(f"DELETE FROM exploits WHERE cve IN ({','.join('?' * len(wanted))})", list(wanted))
        conn.executemany("INSERT OR IGNORE INTO exploits (cve, source, ref, title) VALUES (?, ?, ?, ?)", found)
    return len({f[0] for f in found})


def enrich(conn: sqlite3.Connection, session: requests.Session, cves: list[str] | None = None,
           nvd: bool = True, exploits: bool = True, nvd_api_key: str | None = None,
           sleep=time.sleep) -> list[str]:
    cves = [c.upper() for c in cves] if cves else my_cves(conn)
    if not cves:
        return ["No CVEs in the database yet. Import some scan results first."]
    lines = [f"Enriching {len(cves)} CVEs."]
    new_kev = update_kev(conn, session)
    on_kev = conn.execute(
        f"SELECT count(*) FROM kev WHERE cve IN ({','.join('?' * len(cves))})", cves).fetchone()[0]
    lines.append(f"KEV: catalog updated ({new_kev} entries new to this database); {on_kev} of your CVEs are on it.")
    lines.append(f"EPSS: {update_epss(conn, session, cves)} scores stored.")
    if nvd:
        if not nvd_api_key and len(cves) > 10:
            lines.append(f"NVD: no NVD_API_KEY set, so this takes about {len(cves) * 6 // 60 + 1} minutes "
                         "the first time (cached afterwards).")
        lines.append(f"NVD: {update_nvd(conn, session, cves, nvd_api_key, sleep)} CVEs updated.")
    if exploits:
        lines.append(f"Exploits: {update_exploits(conn, session, cves)} of your CVEs have a public exploit "
                     "in Exploit-DB or Metasploit.")
    return lines


def pct_down(value: float) -> str:
    # Rounding down keeps 0.99996 from reading as "100%", which EPSS never means.
    return f"{math.floor(value * 1000) / 10:.1f}%"


def top_pct(percentile: float) -> str:
    return f"{max(0.1, math.ceil(round((1 - percentile) * 1000, 6)) / 10):.1f}%"


def describe_cve(conn: sqlite3.Connection, cve: str) -> list[str]:
    """Explain everything known about a CVE in plain sentences."""
    cve = cve.upper()
    lines = [cve]
    info = conn.execute("SELECT * FROM cves WHERE cve = ?", (cve,)).fetchone()
    if info is None:
        lines.append("No NVD details stored yet (run `vmt enrich`).")
    elif info["nvd_status"] == "Not in NVD":
        lines.append("NVD has no record of this CVE.")
    else:
        if info["cvss_score"] is not None:
            av = f", {info['attack_vector']} attack vector" if info["attack_vector"] else ""
            lines.append(f"CVSS {info['cvss_score']} (v{info['cvss_version']}{av}).")
        else:
            lines.append(f"NVD has not scored this CVE yet (status: {info['nvd_status']}).")
        if info["cwes"]:
            lines.append(f"Weakness type: {info['cwes'].replace(',', ', ')}.")
        if info["description"]:
            lines.append(info["description"])

    epss = conn.execute("SELECT * FROM epss_history WHERE cve = ? ORDER BY date DESC LIMIT 1", (cve,)).fetchone()
    if epss:
        lines.append(f"EPSS {epss['epss']:.3f} on {epss['date']}: an estimated {pct_down(epss['epss'])} chance "
                     f"of exploitation activity in the next 30 days, in the top {top_pct(epss['percentile'])} "
                     "of all CVEs.")
    else:
        lines.append("No EPSS score stored.")

    kev = conn.execute("SELECT * FROM kev WHERE cve = ?", (cve,)).fetchone()
    if kev:
        ransomware = " Known to be used in ransomware campaigns." if kev["ransomware"] == "Known" else ""
        lines.append(f"On the CISA Known Exploited Vulnerabilities list since {kev['date_added']} "
                     f"(US federal fix deadline {kev['due_date']}).{ransomware}")
    else:
        lines.append("Not on the CISA Known Exploited Vulnerabilities list.")

    predicted = conn.execute("SELECT * FROM cve_predictions WHERE cve = ?", (cve,)).fetchone()
    if predicted:
        lines.append(f"Not from NVD - predicted by `vmt classify` (trained {predicted['model_trained'][:10]}): "
                     f"{predicted['explanation']}")

    model = conn.execute("SELECT * FROM exploit_predictions WHERE cve = ?", (cve,)).fetchone()
    if model:
        lines.append(f"Exploit model (trained {model['model_trained'][:10]}): {model['probability']:.1%} chance of "
                     f"being on KEV, judged from how it was described at publication. {model['explanation']}")

    rows = conn.execute("SELECT * FROM exploits WHERE cve = ? ORDER BY source, ref", (cve,)).fetchall()
    if rows:
        lines.append("Public exploit available: " + "; ".join(
            f"{r['source']} {r['ref']}" + (f" ({r['title']})" if r["title"] else "") for r in rows) + ".")
    else:
        lines.append("No public exploit found in Exploit-DB or Metasploit (that doesn't prove none exists).")
    return lines
