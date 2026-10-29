import json
from pathlib import Path
from xml.etree.ElementTree import ParseError

from ..normalize import ScanResult

FORMATS = ("nessus", "openvas", "trivy")


def detect_format(path: Path) -> str:
    head = path.read_bytes()[:4096].lstrip()
    if head.startswith(b"{"):
        try:
            report = json.loads(path.read_bytes())
        except ValueError:
            raise ValueError(f"{path} is not valid JSON") from None
        if "Results" in report or "SchemaVersion" in report:
            return "trivy"
    elif b"NessusClientData_v2" in head:
        return "nessus"
    elif b"<report" in head or b"<get_reports_response" in head:
        return "openvas"
    raise ValueError(f"Can't tell what scanner produced {path}. Pass --format ({', '.join(FORMATS)}).")


def parse_file(path: Path, fmt: str | None = None, host: str | None = None) -> ScanResult:
    from .nessus import parse_nessus_file
    from .openvas import parse_openvas_file
    from .trivy import parse_trivy_file

    fmt = fmt or detect_format(path)
    try:
        if fmt == "nessus":
            return parse_nessus_file(path)
        if fmt == "openvas":
            return parse_openvas_file(path)
        if fmt == "trivy":
            return parse_trivy_file(path, host=host)
    except ParseError as e:
        raise ValueError(f"{path} is not valid XML: {e}") from None
    raise ValueError(f"Unknown format {fmt!r}; expected one of {', '.join(FORMATS)}")
