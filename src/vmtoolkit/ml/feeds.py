"""Download NVD's yearly JSON 2.0 feeds and EPSS daily archives, and extract model inputs.

Only fields that exist when a CVE is published are extracted, with the CNA's (the issuer's) own
data kept apart from what NVD adds later. Deliberately ignored, because they reveal or hint at
exploitation after the fact: cisaExploitAdd and the other cisa* fields, CISA's SSVC metrics
(which say "exploitation: active"), references (which gain "Exploit" tags), vulnStatus and
lastModified.
"""

import gzip
import json
import logging
import os
import re
from datetime import date
from pathlib import Path

import requests

from ..config import Settings
from ..web import WebError

log = logging.getLogger(__name__)

FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
META_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.meta"
EPSS_ARCHIVE_URL = "https://epss.empiricalsecurity.com/epss_scores-{day}.csv.gz"
CVSS_FIELDS = ["attackVector", "attackComplexity", "privilegesRequired", "userInteraction", "scope",
               "confidentialityImpact", "integrityImpact", "availabilityImpact"]


def _download(session: requests.Session, url: str, dest: Path) -> None:
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with session.get(url, stream=True, timeout=120) as resp:
            if resp.status_code != 200:
                raise WebError(f"{url} returned HTTP {resp.status_code}")
            with tmp.open("wb") as f:
                for chunk in resp.iter_content(1 << 20):
                    f.write(chunk)
    except requests.RequestException as e:
        raise WebError(f"Download of {url} failed: {type(e).__name__}") from None
    os.replace(tmp, dest)


def download_feeds(settings: Settings, years: list[int], session: requests.Session | None = None) -> list[Path]:
    """Fetch each year's feed unless the local copy matches NVD's .meta. Offline mode uses what's on disk."""
    folder = settings.raw_dir / "nvd-feeds"
    folder.mkdir(parents=True, exist_ok=True)
    session = session or requests.Session()
    paths = []
    for year in years:
        path, meta_path = folder / f"nvdcve-2.0-{year}.json.gz", folder / f"nvdcve-2.0-{year}.meta"
        if settings.offline:
            if not path.exists():
                raise WebError(f"Offline mode: {path.name} hasn't been downloaded yet.")
            paths.append(path)
            continue
        try:
            meta = session.get(META_URL.format(year=year), timeout=60)
        except requests.RequestException as e:
            raise WebError(f"Could not reach NVD feeds: {type(e).__name__}") from None
        if meta.status_code != 200:
            raise WebError(f"NVD feed metadata for {year} returned HTTP {meta.status_code}")
        # Compare bytes: NVD's .meta uses CRLF, which read_text would turn into LF and never match.
        if not (path.exists() and meta_path.exists() and meta_path.read_bytes() == meta.content):
            log.info("Downloading NVD feed for %d", year)
            _download(session, FEED_URL.format(year=year), path)
            meta_path.write_bytes(meta.content)
        paths.append(path)
    return paths


def _cvss(metric: dict) -> dict:
    data = metric["cvssData"]
    out = {field: data[field] for field in CVSS_FIELDS if data.get(field)}
    out["baseScore"] = data.get("baseScore")
    return out


def extract(cve: dict) -> dict | None:
    """One NVD feed record -> model inputs, keeping CNA-provided and NVD-added data separate."""
    if cve.get("vulnStatus") == "Rejected":
        return None
    cna = cve.get("sourceIdentifier")
    cvss_cna = cvss_nvd = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for metric in cve.get("metrics", {}).get(key, []):
            if metric.get("source") == cna and cvss_cna is None:
                cvss_cna = _cvss(metric)
            elif metric.get("type") == "Primary" and cvss_nvd is None:
                cvss_nvd = _cvss(metric)
    cwe_cna, cwe_nvd = set(), set()
    for weakness in cve.get("weaknesses", []):
        values = {d["value"] for d in weakness.get("description", []) if d.get("value", "").startswith("CWE-")}
        (cwe_cna if weakness.get("source") == cna else cwe_nvd).update(values)
    vendors_cna = {a["vendor"].strip().lower() for block in cve.get("affected", [])
                   for a in block.get("affectedData", []) if a.get("vendor") and a["vendor"].lower() != "n/a"}
    vendors_cpe = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4 and match.get("vulnerable"):
                    vendors_cpe.add(parts[3].lower())
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {
        "cve": cve["id"], "published": cve["published"][:10], "description": description,
        "cvss_cna": cvss_cna, "cvss_nvd": cvss_nvd,
        "cwe_cna": sorted(cwe_cna), "cwe_nvd": sorted(cwe_nvd),
        "vendors_cna": sorted(vendors_cna), "vendors_cpe": sorted(vendors_cpe),
    }


def load_records(paths: list[Path], cache_dir: Path) -> list[dict]:
    """Extract records from feed files, caching the result per feed so re-runs skip the 300 MB parse."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for path in paths:
        stamp = path.with_suffix("").with_suffix(".meta")
        key = re.sub(r"\W", "", stamp.read_text(encoding="utf-8").split("\n")[0]) if stamp.exists() else "nometa"
        cached = cache_dir / f"{path.name.split('.json')[0]}-{key[-20:]}.jsonl.gz"
        if cached.exists():
            with gzip.open(cached, "rt", encoding="utf-8") as f:
                records += [json.loads(line) for line in f]
            continue
        log.info("Reading %s", path.name)
        with gzip.open(path, "rt", encoding="utf-8") as f:
            feed = json.load(f)
        extracted = [r for r in (extract(v["cve"]) for v in feed.get("vulnerabilities", [])) if r]
        del feed
        tmp = cached.with_suffix(".part")
        with gzip.open(tmp, "wt", encoding="utf-8") as f:
            for r in extracted:
                f.write(json.dumps(r) + "\n")
        os.replace(tmp, cached)
        records += extracted
    return records


def epss_on(settings: Settings, day: date, session: requests.Session | None = None) -> dict[str, float]:
    """EPSS scores for every CVE as published on one day, from the EPSS daily archive."""
    folder = settings.raw_dir / "epss-archive"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"epss_scores-{day.isoformat()}.csv.gz"
    if not path.exists():
        if settings.offline:
            raise WebError(f"Offline mode: EPSS scores for {day} haven't been downloaded yet.")
        _download(session or requests.Session(), EPSS_ARCHIVE_URL.format(day=day.isoformat()), path)
    scores = {}
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.startswith(("#", "cve,")):
                continue
            cve, epss, _ = line.strip().split(",")
            scores[cve] = float(epss)
    return scores
