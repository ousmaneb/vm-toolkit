"""Parser for OpenVAS / Greenbone (GVM) XML reports."""

import hashlib
from pathlib import Path

from defusedxml import ElementTree

from ..db import from_epoch, normalize_timestamp
from ..normalize import Finding, Host, ScanResult


def severity_from_score(score: float | None) -> str:
    # CVSS v3 qualitative ratings. GVM's own threat labels have no "critical" in older versions.
    if score is None or score <= 0:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _text(el, path: str) -> str | None:
    found = el.find(path)
    return found.text.strip() if found is not None and found.text and found.text.strip() else None


def _report_element(root):
    if root.find("results") is not None:
        return root
    for el in root.iter("report"):
        if el.find("results") is not None:
            return el
    raise ValueError("no <results> element found; this does not look like a GVM XML report")


def _port(value: str | None) -> tuple[int, str]:
    # Values look like "443/tcp", "general/tcp" or "package".
    if not value or "/" not in value:
        return 0, ""
    number, protocol = value.split("/", 1)
    return (int(number) if number.isdigit() else 0), protocol.lower()


def parse_openvas_file(path: Path) -> ScanResult:
    data = path.read_bytes()
    report = _report_element(ElementTree.fromstring(data))

    names: dict[str, str] = {}
    for h in report.findall("host"):
        ip = _text(h, "ip")
        for detail in h.findall("detail"):
            value = _text(detail, "value")
            if _text(detail, "name") == "hostname" and ip and value:
                names[ip] = value.lower()

    hosts: dict[str, Host] = {}

    def host_for(ip: str, hostname: str | None) -> Host:
        if ip not in hosts:
            name = (hostname or names.get(ip) or ip).lower()
            hosts[ip] = Host(name=name, ip=ip)
        return hosts[ip]

    # Every host GVM reached counts as scanned, even with no results, so fixes are detected.
    for h in report.findall("host"):
        if _text(h, "ip"):
            host_for(_text(h, "ip"), None)

    for result in report.findall("results/result"):
        ip = _text(result, "host")
        if not ip:
            continue
        nvt = result.find("nvt")
        score = _text(result, "severity") or (_text(nvt, "cvss_base") if nvt is not None else None)
        score = float(score) if score else None
        port, protocol = _port(_text(result, "port"))
        cves = []
        if nvt is not None:
            cves = [ref.get("id") for ref in nvt.findall("refs/ref") if ref.get("type") == "cve"]
        tags = dict(part.split("=", 1) for part in (_text(nvt, "tags") or "").split("|") if "=" in part) \
            if nvt is not None else {}
        host_for(ip, _text(result, "host/hostname")).findings.append(Finding(
            rule_id=nvt.get("oid", "") if nvt is not None else "",
            title=_text(result, "name") or "",
            severity=severity_from_score(score),
            cves=cves,
            cvss_score=score,
            port=port,
            protocol=protocol,
            description=tags.get("summary") or tags.get("insight"),
            solution=_text(nvt, "solution") if nvt is not None else None,
            evidence=_text(result, "description"),
        ))

    start, end = _text(report, "scan_start"), _text(report, "scan_end")
    task = _text(report, "task/name")
    return ScanResult(
        scanner="openvas",
        source_id=task or report.get("id") or path.stem,
        run_id=report.get("id") or hashlib.sha256(data).hexdigest()[:16],
        name=task,
        started_at=normalize_timestamp(start) if start else None,
        finished_at=normalize_timestamp(end) if end else from_epoch(path.stat().st_mtime),
        source_file=str(path),
        hosts=list(hosts.values()),
    )
