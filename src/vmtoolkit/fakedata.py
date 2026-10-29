"""Generate a year of FAKE scan history for trying out the dashboard and other history-hungry tools.

Everything generated is labelled: rows have is_fake = 1, machine names start with FAKE-,
IPs come from 192.0.2.0/24 (reserved for documentation), CVE IDs use the impossible year 2099,
and titles start with "FAKE:". It goes to its own database file, never the real one.
"""

import random
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import db
from .normalize import Finding, Host, ScanResult, store_scan

COMPONENTS = ["FakeSSL", "FakeHTTPd", "FakeSSH", "FakeDB", "FakeKernel", "FakeJava", "FakeCMS", "FakeSMB",
              "FakeMail", "FakeDNS"]
ISSUES = ["remote code execution", "privilege escalation", "information disclosure", "denial of service",
          "authentication bypass", "SQL injection", "cross-site scripting"]
ROLES = ["web", "db", "app", "dc", "file", "mon", "dev", "vpn"]
CWES = ["CWE-79", "CWE-89", "CWE-787", "CWE-20", "CWE-287", "CWE-22", "CWE-416", "CWE-502"]
SEVERITY_WEIGHTS = {"critical": 0.08, "high": 0.27, "medium": 0.45, "low": 0.20}
CVSS_RANGE = {"critical": (9.0, 10.0), "high": (7.0, 8.9), "medium": (4.0, 6.9), "low": (0.1, 3.9)}
# Average days to fix. Roughly 15% of findings never get fixed at all.
FIX_DAYS = {"critical": 12, "high": 35, "medium": 80, "low": 150}
NEVER_FIXED = 0.15
# Some machine roles get patched faster than others, so the forecaster has a pattern to find.
ROLE_SPEED = {"dc": 0.6, "db": 0.6, "dev": 2.5}
OFFLINE_CHANCE = 0.03


class FakeDataError(Exception):
    pass


def _check_target(path: Path, real_db: Path, force: bool) -> None:
    if path.resolve() == real_db.resolve():
        raise FakeDataError(f"Refusing to write fake data into your real database ({real_db}).")
    if not path.exists():
        return
    conn = db.connect(path)
    try:
        real_rows = conn.execute("SELECT count(*) FROM scans WHERE is_fake = 0").fetchone()[0]
    finally:
        conn.close()
    if real_rows:
        raise FakeDataError(f"{path} contains {real_rows} real scans; refusing to touch it.")
    if not force:
        raise FakeDataError(f"{path} already exists. Use --force to replace it.")
    path.unlink()


def _catalog(rng: random.Random, size: int) -> list[dict]:
    vulns = []
    for i in range(size):
        severity = rng.choices(list(SEVERITY_WEIGHTS), weights=list(SEVERITY_WEIGHTS.values()))[0]
        component, issue = rng.choice(COMPONENTS), rng.choice(ISSUES)
        vulns.append({
            "rule_id": str(900000 + i),
            "cve": f"CVE-2099-{10000 + i}",
            "severity": severity,
            "cvss": round(rng.uniform(*CVSS_RANGE[severity]), 1),
            "title": f"FAKE: {component} {issue}",
            "port": rng.choice([0, 22, 80, 443, 445, 3306, 5432, 8080]),
        })
    return vulns


def _enrichment(conn: sqlite3.Connection, rng: random.Random, vulns: list[dict], start: datetime, days: int) -> None:
    for v in vulns:
        conn.execute(
            """INSERT INTO cves (cve, description, cvss_score, cvss_version, attack_vector, cwes, nvd_status)
               VALUES (?, ?, ?, '3.1', ?, ?, 'FAKE')""",
            (v["cve"], f"{v['title']}. Synthetic CVE for demo data.", v["cvss"],
             rng.choice(["network", "network", "adjacent_network", "local"]), rng.choice(CWES)),
        )
        epss = rng.betavariate(0.4, 6) if v["severity"] in ("critical", "high") else rng.betavariate(0.3, 12)
        for week in range(0, days + 1, 7):
            if rng.random() < 0.02:
                epss = min(1.0, epss + rng.uniform(0.1, 0.4))  # occasional jump, like real EPSS
            epss = min(1.0, max(0.0001, epss * rng.uniform(0.9, 1.1)))
            conn.execute("INSERT INTO epss_history VALUES (?, ?, ?, ?)",
                         (v["cve"], (start + timedelta(days=week)).strftime("%Y-%m-%d"), round(epss, 5),
                          round(min(0.9999, epss ** 0.25), 4)))
        if rng.random() < (0.25 if v["severity"] == "critical" else 0.05):
            added = start + timedelta(days=rng.randint(0, days))
            conn.execute(
                """INSERT INTO kev (cve, vendor, product, name, date_added, due_date, ransomware,
                                    required_action, first_seen_at)
                   VALUES (?, 'FAKE vendor', ?, ?, ?, ?, ?, 'FAKE: apply updates', ?)""",
                (v["cve"], v["title"].split()[1], v["title"], added.strftime("%Y-%m-%d"),
                 (added + timedelta(days=21)).strftime("%Y-%m-%d"), rng.choice(["Known", "Unknown"]),
                 db.to_iso(added)),
            )
        if rng.random() < 0.10:
            conn.execute("INSERT INTO exploits VALUES (?, 'exploit-db', ?, ?)",
                         (v["cve"], str(rng.randint(90000, 99999)), f"FAKE exploit for {v['title']}"))
    conn.commit()


def _evidence(v: dict, fp_prone: bool) -> str:
    component = v["title"].split()[1]
    if fp_prone:
        return (f"FAKE: {component} version read from the service banner. The banner reports an old upstream "
                "version; the vendor backports security fixes without changing it.")
    return f"FAKE: installed {component} package version is older than the fixed version."


def _fp_marks(conn: sqlite3.Connection, rng: random.Random, fp_prone: set[str], end: datetime) -> None:
    """Fake user judgements: most banner-based findings marked false positive, some others confirmed real."""
    now = db.to_iso(end)
    rows = conn.execute("SELECT id, rule_id, status FROM findings").fetchall()
    marks = []
    for r in rows:
        if r["rule_id"] in fp_prone and rng.random() < 0.7:
            marks.append((r["id"], "false_positive", "FAKE: banner check, vendor backports fixes", now))
        elif r["rule_id"] not in fp_prone and r["status"] == "open" and rng.random() < 0.05:
            marks.append((r["id"], "real", "FAKE: confirmed by hand", now))
    conn.executemany(
        "INSERT INTO fp_labels (finding_id, label, reason, labeled_at, is_fake) VALUES (?, ?, ?, ?, 1)", marks)
    conn.commit()


def generate(path: Path, real_db: Path, machines: int = 40, days: int = 365, seed: int = 7,
             end: datetime | None = None, force: bool = False) -> str:
    if not 1 <= machines <= 250:
        raise FakeDataError("machines must be between 1 and 250 (they use 192.0.2.x addresses)")
    _check_target(path, real_db, force)
    rng = random.Random(seed)
    end = (end or datetime.now(timezone.utc)).replace(hour=2, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=days)
    vulns = _catalog(rng, max(60, machines * 6))
    # A few checks that misfire the way banner-based detections do on distros that backport fixes.
    fp_prone = {v["rule_id"] for v in rng.sample(vulns, 4)}

    hosts = []
    for i in range(machines):
        role = ROLES[i % len(ROLES)]
        timeline = []
        picked = rng.sample(vulns, rng.randint(15, 45))
        picked += [v for v in vulns if v["rule_id"] in fp_prone and v not in picked and rng.random() < 0.5]
        for v in picked:
            # Some findings already exist at the first scan; the rest show up during the year.
            appear = 0 if rng.random() < 0.3 else rng.randint(0, days)
            fix_after = rng.expovariate(1 / FIX_DAYS[v["severity"]]) * ROLE_SPEED.get(role, 1.0)
            never = rng.random() < NEVER_FIXED or v["rule_id"] in fp_prone
            fixed = None if never else appear + max(1, int(fix_after))
            timeline.append((v, appear, fixed))
        hosts.append((f"FAKE-{role}-{i + 1:02d}", f"192.0.2.{i + 1}", timeline))

    conn = db.connect(path)
    scans = 0
    try:
        for week, day in enumerate(range(0, days + 1, 7)):
            scan_hosts = []
            for name, ip, timeline in hosts:
                if rng.random() < OFFLINE_CHANCE:
                    continue  # host was down this week, so nothing on it can be marked fixed
                findings = [
                    Finding(rule_id=v["rule_id"], title=v["title"], severity=v["severity"], cves=[v["cve"]],
                            cvss_score=v["cvss"], port=v["port"], protocol="tcp" if v["port"] else "",
                            description="Synthetic finding for demo data.",
                            solution=f"FAKE: upgrade {v['title'].split()[1]} to the latest version",
                            evidence=_evidence(v, v["rule_id"] in fp_prone))
                    for v, appear, fixed in timeline if appear <= day and (fixed is None or day < fixed)
                ]
                scan_hosts.append(Host(name=name.lower(), ip=ip, os="FAKE OS", credentialed=True, findings=findings))
            finished = start + timedelta(days=day)
            store_scan(conn, ScanResult(
                scanner="nessus", source_id="fake-weekly", run_id=str(week), name="FAKE weekly scan",
                started_at=db.to_iso(finished - timedelta(hours=1)), finished_at=db.to_iso(finished),
                source_file="generated by vmt fake-data", hosts=scan_hosts,
            ), is_fake=True)
            scans += 1
        _enrichment(conn, rng, vulns, start, days)
        _fp_marks(conn, rng, fp_prone, end)
        findings = conn.execute("SELECT count(*), sum(status = 'open') FROM findings").fetchone()
    finally:
        conn.close()
    return (f"Wrote FAKE data to {path}: {machines} machines, {scans} weekly scans, {findings[0]} findings "
            f"({findings[1]} still open), {len(vulns)} CVEs with fake EPSS/KEV/exploit data. Seed {seed}.")
