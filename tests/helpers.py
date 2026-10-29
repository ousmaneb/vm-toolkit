"""Synthetic test data builders. Nothing here comes from a real scan."""

from xml.sax.saxutils import escape


def make_nessus(hosts: dict[str, list[dict]], end_ts: int = 1_790_000_000, credentialed: bool = True,
                report_name: str = "FAKE lab scan") -> bytes:
    """Build a minimal .nessus v2 document. hosts maps a hostname to a list of item dicts."""
    parts = [f'<?xml version="1.0" ?><NessusClientData_v2><Report name="{escape(report_name)}">']
    for i, (name, items) in enumerate(hosts.items(), start=10):
        parts.append(f'<ReportHost name="192.0.2.{i}"><HostProperties>'
                     f'<tag name="host-ip">192.0.2.{i}</tag>'
                     f'<tag name="host-fqdn">{name}</tag>'
                     f'<tag name="HOST_START_TIMESTAMP">{end_ts - 600}</tag>'
                     f'<tag name="HOST_END_TIMESTAMP">{end_ts}</tag>'
                     f'<tag name="Credentialed_Scan">{"true" if credentialed else "false"}</tag>'
                     '</HostProperties>')
        for item in items:
            cves = "".join(f"<cve>{c}</cve>" for c in item.get("cves", []))
            parts.append(
                f'<ReportItem port="{item.get("port", 0)}" svc_name="general" protocol="tcp" '
                f'severity="{item.get("severity", 3)}" pluginID="{item["id"]}" '
                f'pluginName="{escape(item.get("name", "FAKE plugin"))}" pluginFamily="General">'
                f'<description>Synthetic test finding</description><solution>Upgrade</solution>'
                f'<cvss3_base_score>{item.get("cvss", 7.5)}</cvss3_base_score>{cves}'
                f'<plugin_output>{escape(item.get("output", ""))}</plugin_output></ReportItem>'
            )
        parts.append("</ReportHost>")
    parts.append("</Report></NessusClientData_v2>")
    return "".join(parts).encode("utf-8")
