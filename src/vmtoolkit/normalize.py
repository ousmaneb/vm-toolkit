"""The standard finding format every scanner parser produces, and how it is stored."""

import hashlib
import sqlite3
from dataclasses import dataclass, field

from .db import utcnow

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    cves: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    port: int = 0
    protocol: str = ""
    service: str | None = None
    package: str = ""
    installed_version: str | None = None
    fixed_version: str | None = None
    description: str | None = None
    solution: str | None = None
    evidence: str | None = None


@dataclass
class Host:
    name: str
    ip: str | None = None
    fqdn: str | None = None
    os: str | None = None
    credentialed: bool = False
    findings: list[Finding] = field(default_factory=list)


@dataclass
class ScanResult:
    scanner: str
    source_id: str
    run_id: str
    finished_at: str
    name: str | None = None
    started_at: str | None = None
    source_file: str | None = None
    hosts: list[Host] = field(default_factory=list)


@dataclass
class ImportSummary:
    scan: str
    skipped: bool = False
    hosts: int = 0
    findings: int = 0
    new_findings: int = 0
    fixed: int = 0

    def describe(self) -> str:
        if self.skipped:
            return f"{self.scan}: already imported, skipped"
        return (
            f"{self.scan}: {self.hosts} hosts, {self.findings} findings "
            f"({self.new_findings} new, {self.fixed} now marked fixed)"
        )


def fingerprint(scanner: str, asset_name: str, f: Finding) -> str:
    key = "|".join([scanner, asset_name, f.rule_id, str(f.port), f.protocol, f.package])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def _upsert_asset(conn: sqlite3.Connection, host: Host, is_fake: bool) -> int:
    conn.execute(
        """INSERT INTO assets (name, ip, fqdn, os, is_fake) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(name) DO UPDATE SET
               ip = COALESCE(excluded.ip, ip),
               fqdn = COALESCE(excluded.fqdn, fqdn),
               os = COALESCE(excluded.os, os)""",
        (host.name, host.ip, host.fqdn, host.os, int(is_fake)),
    )
    return conn.execute("SELECT id FROM assets WHERE name = ?", (host.name,)).fetchone()["id"]


def store_scan(
    conn: sqlite3.Connection, scan: ScanResult, include_info: bool = False, is_fake: bool = False
) -> ImportSummary:
    label = f"{scan.scanner} {scan.name or scan.source_id} (run {scan.run_id})"
    summary = ImportSummary(scan=label)
    exists = conn.execute(
        "SELECT 1 FROM scans WHERE scanner = ? AND source_id = ? AND run_id = ?",
        (scan.scanner, scan.source_id, scan.run_id),
    ).fetchone()
    if exists:
        summary.skipped = True
        return summary

    with conn:
        cur = conn.execute(
            """INSERT INTO scans (scanner, source_id, run_id, name, started_at, finished_at,
                                  imported_at, source_file, is_fake)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan.scanner, scan.source_id, scan.run_id, scan.name, scan.started_at,
             scan.finished_at, utcnow(), scan.source_file, int(is_fake)),
        )
        scan_id = cur.lastrowid
        asset_ids = []
        for host in scan.hosts:
            asset_id = _upsert_asset(conn, host, is_fake)
            asset_ids.append(asset_id)
            conn.execute(
                "INSERT OR REPLACE INTO scan_hosts (scan_id, asset_id, credentialed) VALUES (?, ?, ?)",
                (scan_id, asset_id, int(host.credentialed)),
            )
            summary.hosts += 1
            for f in host.findings:
                if f.severity == "info" and not include_info:
                    continue
                summary.findings += 1
                if _store_finding(conn, scan, scan_id, asset_id, host.name, f, is_fake):
                    summary.new_findings += 1

        for asset_id in set(asset_ids):
            summary.fixed += recompute_lifecycle(conn, asset_id, scan.scanner)
    return summary


def _store_finding(conn, scan: ScanResult, scan_id: int, asset_id: int, asset_name: str,
                   f: Finding, is_fake: bool) -> bool:
    fp = fingerprint(scan.scanner, asset_name, f)
    row = conn.execute("SELECT id, last_seen FROM findings WHERE fingerprint = ?", (fp,)).fetchone()
    details = (f.title, f.severity, f.cvss_score, f.service, f.installed_version, f.fixed_version,
               f.description, f.solution, f.evidence)
    if row is None:
        cur = conn.execute(
            """INSERT INTO findings (fingerprint, asset_id, scanner, rule_id, port, protocol, package,
                                     title, severity, cvss_score, service, installed_version,
                                     fixed_version, description, solution, evidence, is_fake)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (fp, asset_id, scan.scanner, f.rule_id, f.port, f.protocol, f.package, *details, int(is_fake)),
        )
        finding_id, is_new = cur.lastrowid, True
    else:
        finding_id, is_new = row["id"], False
        # Keep details from the most recent scan, since plugins and descriptions get updated.
        if row["last_seen"] is None or scan.finished_at >= row["last_seen"]:
            conn.execute(
                """UPDATE findings SET title = ?, severity = ?, cvss_score = ?, service = ?,
                       installed_version = ?, fixed_version = ?, description = ?, solution = ?,
                       evidence = ?
                   WHERE id = ?""",
                (*details, finding_id),
            )
    for cve in f.cves:
        conn.execute("INSERT OR IGNORE INTO finding_cves (finding_id, cve) VALUES (?, ?)",
                     (finding_id, cve.upper()))
    conn.execute("INSERT OR IGNORE INTO observations (finding_id, scan_id) VALUES (?, ?)",
                 (finding_id, scan_id))
    return is_new


def recompute_lifecycle(conn: sqlite3.Connection, asset_id: int, scanner: str) -> int:
    """Rebuild first_seen, last_seen and fixed_at for one host and scanner from scan history.

    Recomputing from all observations means scans can be imported in any order.
    Returns how many findings changed from open to fixed.
    """
    scans = conn.execute(
        """SELECT s.id, s.finished_at, sh.credentialed FROM scans s
           JOIN scan_hosts sh ON sh.scan_id = s.id
           WHERE sh.asset_id = ? AND s.scanner = ?
           ORDER BY s.finished_at""",
        (asset_id, scanner),
    ).fetchall()
    seen_in: dict[int, set[int]] = {}
    for row in conn.execute(
        """SELECT o.finding_id, o.scan_id FROM observations o
           JOIN findings f ON f.id = o.finding_id
           WHERE f.asset_id = ? AND f.scanner = ?""",
        (asset_id, scanner),
    ):
        seen_in.setdefault(row["finding_id"], set()).add(row["scan_id"])

    newly_fixed = 0
    for finding in conn.execute(
        "SELECT id, status FROM findings WHERE asset_id = ? AND scanner = ?", (asset_id, scanner)
    ).fetchall():
        seen = [s for s in scans if s["id"] in seen_in.get(finding["id"], set())]
        if not seen:
            continue
        last = seen[-1]
        later = [s for s in scans if s["finished_at"] > last["finished_at"]]
        # An uncredentialed scan can't see most local checks, so it can't prove a
        # finding from a credentialed scan is gone.
        proof = [s for s in later if s["credentialed"] >= last["credentialed"]]
        status, fixed_at, note = "open", None, None
        if proof:
            status, fixed_at = "fixed", proof[0]["finished_at"]
            note = f"Marked fixed: not reported by the scan finished {fixed_at[:10]}."
        elif later:
            note = ("Missing from later scans, but none of them were credentialed like the scan "
                    "that last found it, so it is not counted as fixed.")
        if status == "fixed" and finding["status"] != "fixed":
            newly_fixed += 1
        conn.execute(
            """UPDATE findings SET first_seen = ?, last_seen = ?, fixed_at = ?, status = ?,
                   status_note = ? WHERE id = ?""",
            (seen[0]["finished_at"], last["finished_at"], fixed_at, status, note, finding["id"]),
        )
    return newly_fixed
