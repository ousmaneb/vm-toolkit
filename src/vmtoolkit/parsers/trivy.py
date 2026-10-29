"""Parser for Trivy JSON reports (trivy image/fs/rootfs/vm ... --format json)."""

import hashlib
import json
from pathlib import Path

from ..db import from_epoch, normalize_timestamp
from ..normalize import Finding, Host, ScanResult

# Trivy's UNKNOWN means the source gave no rating. It is kept visible as "low" rather than
# dropped with info findings.
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low"}


def _cvss(vuln: dict) -> float | None:
    cvss = vuln.get("CVSS") or {}
    for source in ["nvd", *cvss]:
        score = (cvss.get(source) or {}).get("V3Score")
        if score:
            return float(score)
    return None


def parse_trivy_file(path: Path, host: str | None = None) -> ScanResult:
    """Parse a Trivy report. host attaches the findings to a machine instead of the artifact name."""
    data = path.read_bytes()
    report = json.loads(data)
    artifact = report.get("ArtifactName") or path.stem
    os_info = (report.get("Metadata") or {}).get("OS") or {}
    target = Host(
        name=(host or artifact).lower(),
        os=" ".join(filter(None, [os_info.get("Family"), os_info.get("Name")])) or None,
        # Trivy reads packages straight from the filesystem, which is the same visibility
        # a credentialed scan has.
        credentialed=True,
    )
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = vuln["VulnerabilityID"]
            target.findings.append(Finding(
                rule_id=vuln_id,
                title=vuln.get("Title") or f"{vuln_id} in {vuln.get('PkgName')}",
                severity=SEVERITY.get(vuln.get("Severity", "UNKNOWN"), "low"),
                cves=[vuln_id] if vuln_id.startswith("CVE-") else [],
                cvss_score=_cvss(vuln),
                package=vuln.get("PkgName", ""),
                installed_version=vuln.get("InstalledVersion"),
                fixed_version=vuln.get("FixedVersion"),
                description=vuln.get("Description"),
                solution=f"Upgrade {vuln.get('PkgName')} to {vuln['FixedVersion']}" if vuln.get("FixedVersion") else None,
                evidence=f"Found in {result.get('Target')}",
            ))
    created = report.get("CreatedAt")
    return ScanResult(
        scanner="trivy",
        source_id=artifact,
        run_id=hashlib.sha256(data).hexdigest()[:16],
        name=artifact,
        finished_at=normalize_timestamp(created) if created else from_epoch(path.stat().st_mtime),
        source_file=str(path),
        hosts=[target],
    )
