"""Check requirements.txt, package.json and package-lock.json files against OSV.dev."""

import hashlib
import json
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

import requests
from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from .db import utcnow
from .normalize import Finding, Host, ScanResult
from .web import WebError, fetch

QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{}"
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".tox"}
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
SEMVER_RE = re.compile(r"\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?")


@dataclass
class Dependency:
    name: str
    ecosystem: str
    version: str | None
    spec: str
    exact: bool
    source: Path


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: str | None
    cves: list[str]
    fixed: str | None
    aliases: set[str] = field(default_factory=set)


@dataclass
class FileReport:
    path: Path
    deps: list[Dependency] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    note: str | None = None


def parse_requirements(path: Path, seen: set[Path] | None = None) -> FileReport:
    report = FileReport(path)
    seen = seen or set()
    seen.add(path.resolve())
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #")[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")):
            included = path.parent / line.split(maxsplit=1)[1]
            if included.exists() and included.resolve() not in seen:
                sub = parse_requirements(included, seen)
                report.deps += sub.deps
                report.skipped += sub.skipped
            continue
        if line.startswith("-"):
            continue
        try:
            req = Requirement(line)
        except InvalidRequirement:
            report.skipped.append(f"{line} (not a package requirement)")
            continue
        specs = list(req.specifier)
        pinned = [s for s in specs if s.operator in ("==", "===") and "*" not in s.version]
        if pinned:
            report.deps.append(Dependency(req.name, "PyPI", pinned[0].version, str(req.specifier), True, path))
        elif lower := [s.version for s in specs if s.operator in (">=", "~=", "==")]:
            report.deps.append(Dependency(req.name, "PyPI", lower[0].rstrip(".*"), str(req.specifier), False, path))
        else:
            report.skipped.append(f"{req.name} (no lower version bound, can't check)")
    return report


def parse_package_json(path: Path) -> FileReport:
    report = FileReport(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            match = SEMVER_RE.search(spec)
            if not match or spec.startswith(("git", "file:", "link:", "http", "workspace:")):
                report.skipped.append(f"{name} {spec} (not a registry version, can't check)")
                continue
            exact = bool(re.fullmatch(r"=?v?" + SEMVER_RE.pattern, spec.strip()))
            report.deps.append(Dependency(name, "npm", match.group(0), spec, exact, path))
    return report


def parse_package_lock(path: Path) -> FileReport:
    report = FileReport(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if "packages" in data:
        for key, info in data["packages"].items():
            if not key or info.get("link") or not info.get("version"):
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            report.deps.append(Dependency(name, "npm", info["version"], info["version"], True, path))
    else:
        def walk(deps):
            for name, info in (deps or {}).items():
                if info.get("version"):
                    report.deps.append(Dependency(name, "npm", info["version"], info["version"], True, path))
                walk(info.get("dependencies"))
        walk(data.get("dependencies"))
    # The same package often appears many times at the same version.
    unique = {(d.name, d.version): d for d in report.deps}
    report.deps = list(unique.values())
    return report


def find_files(paths: list[Path]) -> list[Path]:
    found = []
    for path in paths:
        if path.is_file():
            found.append(path)
            continue
        for candidate in sorted(path.rglob("*")):
            if any(part in SKIP_DIRS for part in candidate.relative_to(path).parts):
                continue
            if candidate.is_file() and (candidate.name in ("package.json", "package-lock.json")
                                        or re.fullmatch(r"requirements.*\.txt", candidate.name)):
                found.append(candidate)
    return found


def parse_files(paths: list[Path]) -> list[FileReport]:
    files = find_files(paths)
    for path in list(files):
        lock = path.with_name("package-lock.json")
        if path.name == "package.json" and lock.exists() and lock not in files:
            files.append(lock)
    reports = []
    for path in files:
        if path.name == "package.json" and path.with_name("package-lock.json").exists():
            report = FileReport(path, note="checked package-lock.json next to it instead, which has exact versions")
        elif path.name == "package.json":
            report = parse_package_json(path)
        elif path.name == "package-lock.json":
            report = parse_package_lock(path)
        elif path.suffix == ".txt":
            report = parse_requirements(path)
        else:
            report = FileReport(path, note="not a supported file type, skipped")
        reports.append(report)
    return reports


def version_key(version: str):
    try:
        return (0, Version(version))
    except InvalidVersion:
        return (1, tuple(int(n) for n in re.findall(r"\d+", version)))


def _fixed_version(vuln: dict, dep: Dependency) -> str | None:
    fixes = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != dep.name.lower() or pkg.get("ecosystem") != dep.ecosystem:
            continue
        for rng in affected.get("ranges", []):
            fixes += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    if not fixes:
        return None
    later = [f for f in fixes if version_key(f) > version_key(dep.version)]
    return min(later or fixes, key=version_key)


def _severity(vuln: dict) -> str | None:
    label = (vuln.get("database_specific") or {}).get("severity")
    for affected in vuln.get("affected", []):
        label = label or (affected.get("database_specific") or {}).get("severity")
    return SEVERITY.get(str(label).upper())


def merge_aliases(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """OSV often returns one issue several times (GHSA, PYSEC, ...). Keep one, preferring a rated entry."""
    merged: list[Vulnerability] = []
    for v in sorted(vulns, key=lambda v: (v.severity is None, not v.id.startswith("GHSA-"), v.id)):
        same = next((m for m in merged if m.aliases & v.aliases), None)
        if same is None:
            merged.append(v)
            continue
        same.aliases |= v.aliases
        same.cves = sorted(set(same.cves) | set(v.cves))
        same.fixed = same.fixed or v.fixed
    order = {s: i for i, s in enumerate(("critical", "high", "medium", "low", None))}
    return sorted(merged, key=lambda v: (order[v.severity], v.id))


def check(session: requests.Session, deps: list[Dependency]) -> dict[int, list[Vulnerability]]:
    """Query OSV for each dependency. Returns vulnerabilities keyed by index into deps."""
    results: dict[int, list[Vulnerability]] = {}
    details: dict[str, dict] = {}
    for start in range(0, len(deps), 500):
        batch = deps[start:start + 500]
        queries = [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in batch]
        resp = fetch(session, "POST", QUERYBATCH_URL, json={"queries": queries})
        if resp.status_code != 200:
            raise WebError(f"OSV returned HTTP {resp.status_code}")
        for offset, result in enumerate(resp.json().get("results", [])):
            dep = batch[offset]
            found = []
            for v in result.get("vulns") or []:
                if v["id"] not in details:
                    r = fetch(session, "GET", VULN_URL.format(v["id"]))
                    if r.status_code != 200:
                        raise WebError(f"OSV returned HTTP {r.status_code} for {v['id']}")
                    details[v["id"]] = r.json()
                full = details[v["id"]]
                ids = {full["id"], *full.get("aliases", [])}
                found.append(Vulnerability(
                    id=full["id"],
                    summary=full.get("summary") or textwrap.shorten(full.get("details") or "", 120, placeholder="..."),
                    severity=_severity(full),
                    cves=sorted(a for a in ids if a.startswith("CVE-")),
                    fixed=_fixed_version(full, dep),
                    aliases=ids,
                ))
            if found:
                results[start + offset] = merge_aliases(found)
    return results


def describe(dep: Dependency) -> str:
    if dep.exact:
        return f"{dep.name} {dep.version}"
    return (f"{dep.name} {dep.spec} (a range, not an exact version: checked the lowest allowed version "
            f"{dep.version}; what's actually installed may differ)")


def describe_vuln(v: Vulnerability) -> str:
    aliases = [c for c in v.cves if c != v.id]
    cves = f" ({', '.join(aliases)})" if aliases else ""
    fix = f" Fixed in {v.fixed}." if v.fixed else " No fixed version listed."
    rating = (v.severity or "unrated").upper()
    return f"{rating:8} {v.id}{cves} {v.summary.rstrip('.')}.{fix}"


def to_scan(reports: list[FileReport], deps: list[Dependency], found: dict[int, list[Vulnerability]],
            project: Path, host: str | None) -> ScanResult:
    asset = host or f"project:{project.resolve().name}"
    findings = []
    for i, vulns in found.items():
        dep = deps[i]
        for v in vulns:
            findings.append(Finding(
                rule_id=v.id,
                title=f"{v.id} in {dep.name}: {v.summary}".strip(": ")
                      + ("" if v.severity else " [OSV gives no severity rating]"),
                # Unrated entries are stored as low so they still show up; the title says why.
                severity=v.severity or "low",
                cves=v.cves, package=dep.name, installed_version=dep.version, fixed_version=v.fixed,
                solution=f"Upgrade {dep.name} to {v.fixed} or later" if v.fixed else None,
                evidence=f"{dep.source}: {describe(dep)}",
            ))
    digest = hashlib.sha256("".join(str(r.path) for r in reports).encode() + utcnow().encode()).hexdigest()[:16]
    return ScanResult(
        scanner="osv", source_id=str(project.resolve()), run_id=digest, name=f"dependencies in {project.name or '.'}",
        finished_at=utcnow(), source_file=str(project),
        # Dependency files list every package, which is the same visibility a credentialed scan has.
        hosts=[Host(name=asset.lower(), credentialed=True, findings=findings)],
    )
