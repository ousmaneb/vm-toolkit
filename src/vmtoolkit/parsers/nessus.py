"""Parsers for .nessus (v2) files and for per-host JSON from the Nessus API."""

import hashlib
import re
from datetime import datetime
from pathlib import Path

from defusedxml import ElementTree

from ..db import from_epoch, to_iso
from ..normalize import SEVERITIES, Finding, Host, ScanResult

# Nessus local-check plugins usually print these lines in their output.
INSTALLED_RE = re.compile(r"Installed (?:version|package)\s*:\s*(\S.*)", re.IGNORECASE)
FIXED_RE = re.compile(r"Fixed (?:version|package)\s*:\s*(\S.*)", re.IGNORECASE)


def _severity(value) -> str:
    try:
        return SEVERITIES[int(value)]
    except (TypeError, ValueError, IndexError):
        return "info"


def _float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _versions(output: str | None) -> tuple[str | None, str | None]:
    if not output:
        return None, None
    installed, fixed = INSTALLED_RE.search(output), FIXED_RE.search(output)
    return (installed.group(1).strip() if installed else None,
            fixed.group(1).strip() if fixed else None)


def _host_time(props: dict, key: str) -> str | None:
    if props.get(f"{key}_TIMESTAMP"):
        return from_epoch(props[f"{key}_TIMESTAMP"])
    if props.get(key):
        try:
            return to_iso(datetime.strptime(props[key], "%a %b %d %H:%M:%S %Y"))
        except ValueError:
            return None
    return None


def _host_name(props: dict, fallback: str) -> str:
    for key in ("host-fqdn", "hostname", "netbios-name", "host-ip"):
        if props.get(key):
            return props[key].strip().lower()
    return fallback.strip().lower()


def _report_item(item) -> Finding:
    def text(tag):
        el = item.find(tag)
        return el.text.strip() if el is not None and el.text else None

    output = text("plugin_output")
    installed, fixed = _versions(output)
    return Finding(
        rule_id=item.get("pluginID", ""),
        title=item.get("pluginName", ""),
        severity=_severity(item.get("severity")),
        cves=[el.text.strip() for el in item.findall("cve") if el.text],
        cvss_score=_float(text("cvss3_base_score")) or _float(text("cvss_base_score")),
        port=int(item.get("port") or 0),
        protocol=(item.get("protocol") or "").lower(),
        service=item.get("svc_name"),
        installed_version=installed,
        fixed_version=fixed,
        description=text("description") or text("synopsis"),
        solution=text("solution"),
        evidence=output,
    )


def parse_nessus_file(path: Path, **overrides) -> ScanResult:
    """Parse a .nessus file. Keyword overrides replace scan metadata (used by the API connector)."""
    data = path.read_bytes()
    root = ElementTree.fromstring(data)
    report = root.find("Report")
    if report is None:
        raise ValueError(f"{path} is not a .nessus v2 file (no <Report> element)")

    hosts, starts, ends = [], [], []
    for rh in report.findall("ReportHost"):
        props = {t.get("name"): (t.text or "") for t in rh.findall("HostProperties/tag")}
        start, end = _host_time(props, "HOST_START"), _host_time(props, "HOST_END")
        starts += [start] if start else []
        ends += [end] if end else []
        hosts.append(Host(
            name=_host_name(props, rh.get("name", "")),
            ip=props.get("host-ip") or None,
            fqdn=props.get("host-fqdn") or None,
            os=props.get("operating-system") or None,
            credentialed=props.get("Credentialed_Scan", "").lower() == "true",
            findings=[_report_item(item) for item in rh.findall("ReportItem")],
        ))

    fields = {
        "scanner": "nessus",
        "source_id": report.get("name", path.stem),
        "run_id": hashlib.sha256(data).hexdigest()[:16],
        "name": report.get("name"),
        "started_at": min(starts) if starts else None,
        "finished_at": max(ends) if ends else from_epoch(path.stat().st_mtime),
        "source_file": str(path),
    }
    fields.update(overrides)
    return ScanResult(hosts=hosts, **fields)


def parse_api_host(host_json: dict, plugins: dict[str, dict]) -> Host:
    """Build a Host from GET /scans/{id}/hosts/{host_id} plus that host's plugin detail responses.

    Used only when the export endpoint is unavailable.
    """
    info = host_json.get("info", {})
    host = Host(
        name=_host_name(info, info.get("host-ip", "unknown")),
        ip=info.get("host-ip"),
        fqdn=info.get("host-fqdn"),
        os=info.get("operating-system"),
        credentialed=str(info.get("Credentialed_Scan", "")).lower() == "true",
    )
    for vuln in host_json.get("vulnerabilities", []):
        plugin_id = str(vuln.get("plugin_id"))
        detail = plugins.get(plugin_id, {})
        attrs = detail.get("info", {}).get("plugindescription", {}).get("pluginattributes", {})
        risk = attrs.get("risk_information", {})
        cves = []
        for ref in (attrs.get("ref_information") or {}).get("ref", []):
            if ref.get("name", "").lower() == "cve":
                values = (ref.get("values") or {}).get("value", [])
                cves += values if isinstance(values, list) else [values]
        outputs = detail.get("outputs") or [{}]
        for out in outputs:
            ports = list((out.get("ports") or {"0 / / ": []}).keys())
            for port_key in ports:
                port, protocol, service = [p.strip() for p in (port_key.split("/") + ["", ""])[:3]]
                installed, fixed = _versions(out.get("plugin_output"))
                host.findings.append(Finding(
                    rule_id=plugin_id,
                    title=vuln.get("plugin_name", ""),
                    severity=_severity(vuln.get("severity")),
                    cves=cves,
                    cvss_score=_float(risk.get("cvss3_base_score")) or _float(risk.get("cvss_base_score")),
                    port=int(port or 0),
                    protocol=protocol.lower(),
                    service=service or None,
                    installed_version=installed,
                    fixed_version=fixed,
                    description=attrs.get("description") or attrs.get("synopsis"),
                    solution=attrs.get("solution"),
                    evidence=out.get("plugin_output"),
                ))
    return host
