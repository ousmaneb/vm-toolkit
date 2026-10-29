"""Nessus API connector: list scans, download every historical run, back up and import it."""

import json
import logging
import os
import re
import sqlite3
import time
from pathlib import Path

import requests
import urllib3

from .config import Settings, get_secret
from .db import from_epoch
from .normalize import ImportSummary, ScanResult, store_scan
from .parsers.nessus import parse_api_host, parse_nessus_file

log = logging.getLogger(__name__)


class NessusError(Exception):
    pass


class ExportUnavailable(NessusError):
    pass


class NessusClient:
    def __init__(self, url: str, verify: bool | str = True, access_key: str | None = None,
                 secret_key: str | None = None, username: str | None = None,
                 password: str | None = None, timeout: int = 60, sleep=time.sleep):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.sleep = sleep
        self.session = requests.Session()
        self.session.verify = verify
        self._token = None
        if access_key and secret_key:
            self.session.headers["X-ApiKeys"] = f"accessKey={access_key}; secretKey={secret_key}"
        elif username and password:
            resp = self._request("POST", "/session", json={"username": username, "password": password})
            self._token = resp.json()["token"]
            self.session.headers["X-Cookie"] = f"token={self._token}"
        else:
            raise NessusError(
                "No Nessus credentials found. Set NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY "
                "(or NESSUS_USERNAME and NESSUS_PASSWORD) in .env or the environment."
            )

    @classmethod
    def from_settings(cls, settings: Settings) -> "NessusClient":
        cfg = settings.section("nessus")
        verify: bool | str = bool(cfg.get("verify_tls", True))
        pem = get_secret("NESSUS_CA_CERT")
        if cfg.get("ca_cert"):
            verify = str(settings.resolve(cfg["ca_cert"]))
        elif pem:
            # In containers the CA comes in as a secret; requests needs it as a file.
            path = settings.data_dir / "nessus-ca.pem"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(pem.strip() + "\n", encoding="utf-8")
            path.chmod(0o600)
            verify = str(path)
        elif not verify:
            log.warning("TLS certificate checks for Nessus are turned off (nessus.verify_tls = false).")
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        client = cls(
            cfg["url"], verify=verify,
            access_key=get_secret("NESSUS_ACCESS_KEY"), secret_key=get_secret("NESSUS_SECRET_KEY"),
            username=get_secret("NESSUS_USERNAME"), password=get_secret("NESSUS_PASSWORD"),
        )
        if cfg.get("proxy"):
            # For example Tailscale's userspace HTTP proxy, when Nessus is only reachable over the tailnet.
            client.session.proxies = {"https": cfg["proxy"], "http": cfg["proxy"]}
        return client

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        try:
            resp = self.session.request(method, self.url + path, timeout=self.timeout, **kwargs)
        except requests.exceptions.SSLError:
            raise NessusError(
                f"TLS certificate check failed for {self.url}. Set nessus.ca_cert to the Nessus CA "
                "file (download it from /getcert), or set nessus.verify_tls = false."
            ) from None
        except requests.exceptions.ConnectionError:
            raise NessusError(f"Could not connect to Nessus at {self.url}. Is it running?") from None
        if resp.status_code == 401:
            raise NessusError("Nessus rejected the credentials (HTTP 401). Check the Nessus keys in .env or the environment.")
        if resp.status_code >= 400:
            raise NessusError(f"Nessus returned HTTP {resp.status_code} for {method} {path}")
        return resp

    def server_properties(self) -> dict:
        return self._request("GET", "/server/properties").json()

    def list_scans(self) -> list[dict]:
        return self._request("GET", "/scans").json().get("scans") or []

    def scan_details(self, scan_id: int, history_id: int | None = None) -> dict:
        params = {"history_id": history_id} if history_id is not None else None
        return self._request("GET", f"/scans/{scan_id}", params=params).json()

    def host_details(self, scan_id: int, host_id: int, history_id: int) -> dict:
        return self._request("GET", f"/scans/{scan_id}/hosts/{host_id}",
                             params={"history_id": history_id}).json()

    def plugin_details(self, scan_id: int, host_id: int, plugin_id: int, history_id: int) -> dict:
        return self._request("GET", f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}",
                             params={"history_id": history_id}).json()

    def export(self, scan_id: int, history_id: int, timeout: int = 300) -> bytes:
        try:
            resp = self._request("POST", f"/scans/{scan_id}/export", params={"history_id": history_id},
                                 json={"format": "nessus"})
        except NessusError as e:
            if "HTTP 401" in str(e):
                raise
            raise ExportUnavailable(str(e)) from None
        file_id = resp.json()["file"]
        deadline = time.monotonic() + timeout
        while True:
            status = self._request("GET", f"/scans/{scan_id}/export/{file_id}/status").json()
            if status.get("status") == "ready":
                break
            if time.monotonic() > deadline:
                raise NessusError(f"Export of scan {scan_id} run {history_id} not ready after {timeout}s")
            self.sleep(2)
        return self._request("GET", f"/scans/{scan_id}/export/{file_id}/download").content

    def close(self) -> None:
        if self._token:
            try:
                self._request("DELETE", "/session")
            except NessusError:
                pass
        self.session.close()


def safe_name(name: str) -> str:
    # Characters Windows doesn't allow in file names are replaced too.
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")[:60] or "scan"


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".part")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def download_run(client: NessusClient, scan_id: int, history_id: int, run_dir: Path,
                 export_timeout: int = 300) -> None:
    """Save one scan run under run_dir: scan.json plus report.nessus, or hosts/*.json as a fallback."""
    run_dir.mkdir(parents=True, exist_ok=True)
    details = client.scan_details(scan_id, history_id)
    _write(run_dir / "scan.json", json.dumps(details, indent=2).encode("utf-8"))
    try:
        _write(run_dir / "report.nessus", client.export(scan_id, history_id, timeout=export_timeout))
        return
    except ExportUnavailable as e:
        log.warning("Export not available for scan %s run %s (%s); downloading host by host instead.",
                    scan_id, history_id, e)
    hosts_dir = run_dir / "hosts"
    hosts_dir.mkdir(exist_ok=True)
    for host in details.get("hosts") or []:
        host_id = host["host_id"]
        host_json = client.host_details(scan_id, host_id, history_id)
        plugins = {
            str(v["plugin_id"]): client.plugin_details(scan_id, host_id, v["plugin_id"], history_id)
            for v in host_json.get("vulnerabilities", [])
        }
        _write(hosts_dir / f"{host_id}.json",
               json.dumps({"host": host_json, "plugins": plugins}, indent=2).encode("utf-8"))
    (run_dir / "complete").touch()


def is_downloaded(run_dir: Path) -> bool:
    return (run_dir / "report.nessus").exists() or (run_dir / "complete").exists()


def load_run(run_dir: Path, scan_id: int, history_id: int, name: str, run: dict) -> ScanResult:
    meta = {
        "source_id": str(scan_id),
        "run_id": str(history_id),
        "name": name,
        "started_at": from_epoch(run["creation_date"]) if run.get("creation_date") else None,
        "finished_at": from_epoch(run.get("last_modification_date") or run["creation_date"]),
    }
    report = run_dir / "report.nessus"
    if report.exists():
        return parse_nessus_file(report, **meta)
    hosts = []
    for path in sorted((run_dir / "hosts").glob("*.json")):
        saved = json.loads(path.read_text(encoding="utf-8"))
        hosts.append(parse_api_host(saved["host"], saved["plugins"]))
    return ScanResult(scanner="nessus", source_file=str(run_dir), hosts=hosts, **meta)


def reimport(settings: Settings, conn: sqlite3.Connection) -> list[str]:
    """Rebuild the database from the raw backups alone, without contacting Nessus."""
    include_info = settings.section("import").get("include_info", False)
    lines = []
    for scan_json in sorted((settings.raw_dir / "nessus").glob("*/*/scan.json")):
        run_dir = scan_json.parent
        if not is_downloaded(run_dir):
            lines.append(f"{run_dir}: download was interrupted, skipped")
            continue
        details = json.loads(scan_json.read_text(encoding="utf-8"))
        scan_id = int(run_dir.parent.name.split("-", 1)[0])
        history_id = int(run_dir.name)
        run = next((r for r in details.get("history") or [] if r["history_id"] == history_id), None)
        if run is None:
            lines.append(f"{run_dir}: scan.json has no history entry for run {history_id}, skipped")
            continue
        name = (details.get("info") or {}).get("name") or run_dir.parent.name
        result = load_run(run_dir, scan_id, history_id, name, run)
        lines.append(store_scan(conn, result, include_info=include_info).describe())
    return lines


def pull(client: NessusClient, settings: Settings, conn: sqlite3.Connection,
         scan_ids: list[int] | None = None) -> list[str]:
    """Download every completed run of every scan (or just scan_ids) and import it.

    Runs already on disk are not downloaded again. Returns one line per run describing what happened.
    """
    cfg = settings.section("nessus")
    include_info = settings.section("import").get("include_info", False)
    lines = []
    for scan in client.list_scans():
        scan_id, name = scan["id"], scan.get("name") or str(scan["id"])
        if scan_ids and scan_id not in scan_ids:
            continue
        runs = client.scan_details(scan_id).get("history") or []
        for run in sorted(runs, key=lambda r: r.get("creation_date") or 0):
            history_id = run["history_id"]
            if run.get("status") != "completed":
                lines.append(f"{name} run {history_id}: status is '{run.get('status')}', skipped "
                             "(only completed runs are used, so partial scans don't mark things fixed)")
                continue
            run_dir = settings.raw_dir / "nessus" / f"{scan_id}-{safe_name(name)}" / str(history_id)
            if not is_downloaded(run_dir):
                download_run(client, scan_id, history_id, run_dir, int(cfg.get("export_timeout", 300)))
            result = load_run(run_dir, scan_id, history_id, name, run)
            summary: ImportSummary = store_scan(conn, result, include_info=include_info)
            lines.append(summary.describe())
    return lines
