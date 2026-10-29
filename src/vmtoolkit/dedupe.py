"""Spot findings from different scanners that describe the same problem on the same machine."""

import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher

from .assets import entries
from .config import Settings

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
TITLE_SIMILARITY = 0.8


class UnionFind:
    def __init__(self):
        self.parent: dict = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b) -> None:
        self.parent[self.find(a)] = self.find(b)

    def groups(self) -> list[set]:
        out = defaultdict(set)
        for x in self.parent:
            out[self.find(x)].add(x)
        return list(out.values())


@dataclass
class Link:
    a: int
    b: int
    confidence: str
    reason: str


def machine_groups(conn: sqlite3.Connection, settings: Settings) -> tuple[list[set[int]], list[str]]:
    """Group asset rows that are the same machine under different names. Returns groups and reasons."""
    assets = conn.execute("SELECT id, name, ip FROM assets").fetchall()
    uf, reasons = UnionFind(), []
    for a in assets:
        uf.find(a["id"])

    by_ip, by_short = defaultdict(list), defaultdict(list)
    for a in assets:
        named_by_ip = a["name"].replace(".", "").isdigit()
        ip = a["ip"] or (a["name"] if named_by_ip else None)
        if ip:
            by_ip[ip].append(a)
        # "web-01" and "web-01.lab" are the same machine; an IP address has no short name.
        if not named_by_ip:
            by_short[a["name"].split(".")[0]].append(a)
    for kind, index in (("share IP", by_ip), ("have the same host name", by_short)):
        for key, rows in index.items():
            for other in rows[1:]:
                if uf.find(rows[0]["id"]) != uf.find(other["id"]):
                    uf.union(rows[0]["id"], other["id"])
                    reasons.append(f"{rows[0]['name']} and {other['name']} {kind} {key}")

    lookup = {a["name"].lower(): a for a in assets} | {a["ip"]: a for a in assets if a["ip"]}
    for key, entry in entries(settings).items():
        known = [lookup[n.lower()] for n in [key, *entry.get("aliases", [])] if n.lower() in lookup]
        for other in known[1:]:
            if uf.find(known[0]["id"]) != uf.find(other["id"]):
                uf.union(known[0]["id"], other["id"])
                reasons.append(f'{known[0]["name"]} and {other["name"]} are aliases in [assets."{key}"]')
    return uf.groups(), reasons


def _title(t: str) -> str:
    return " ".join(t.lower().replace("fake:", "").split())


def find_links(findings: list[sqlite3.Row], cves: dict[int, set[str]], names: dict[int, str]) -> list[Link]:
    links = []
    for i, a in enumerate(findings):
        for b in findings[i + 1:]:
            if a["scanner"] == b["scanner"]:
                continue  # one scanner reporting twice means two ports or packages, not a duplicate
            where = f"{names[a['asset_id']]} ({a['scanner']}) and {names[b['asset_id']]} ({b['scanner']})"
            shared = cves[a["id"]] & cves[b["id"]]
            if shared:
                links.append(Link(a["id"], b["id"], "high", f"{where} both report {', '.join(sorted(shared))}"))
            elif a["package"] and a["package"].lower() == (b["package"] or "").lower() \
                    and a["installed_version"] and a["installed_version"] == b["installed_version"]:
                links.append(Link(a["id"], b["id"], "high",
                                  f"{where} both flag {a['package']} {a['installed_version']}"))
            elif not cves[a["id"]] and not cves[b["id"]] and a["port"] and a["port"] == b["port"] \
                    and a["protocol"] == b["protocol"]:
                ratio = SequenceMatcher(None, _title(a["title"]), _title(b["title"])).ratio()
                if ratio >= TITLE_SIMILARITY:
                    links.append(Link(a["id"], b["id"], "medium",
                                      f"{where} report similar titles ({ratio:.0%} alike) on port "
                                      f"{a['port']}/{a['protocol']}, and neither lists a CVE"))
    return links


def _primary(members: list[sqlite3.Row], cves: dict[int, set[str]]) -> sqlite3.Row:
    # Keep the most severe report, then the one with CVEs, then the one seen first.
    return sorted(members, key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), not cves[f["id"]],
                                          f["first_seen"] or "", f["id"]))[0]


def dedupe(conn: sqlite3.Connection, settings: Settings) -> list[str]:
    """Rebuild the duplicates table from scratch and describe what was found."""
    groups, machine_reasons = machine_groups(conn, settings)
    names = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM assets")}
    cves: dict[int, set[str]] = defaultdict(set)
    for r in conn.execute("SELECT finding_id, cve FROM finding_cves"):
        cves[r["finding_id"]].add(r["cve"])

    lines = [f"Treated as one machine: {r}." for r in machine_reasons]
    rows = []
    for group in groups:
        findings = conn.execute(
            f"SELECT * FROM findings WHERE asset_id IN ({','.join('?' * len(group))}) ORDER BY id", sorted(group)
        ).fetchall()
        links = find_links(findings, cves, names)
        uf = UnionFind()
        for link in links:
            uf.union(link.a, link.b)
        by_id = {f["id"]: f for f in findings}
        for member_ids in uf.groups():
            members = [by_id[i] for i in sorted(member_ids)]
            primary = _primary(members, cves)
            lines.append(f"Same problem, counted once as finding {primary['id']} ({primary['title']}):")
            for link in links:
                if link.a in member_ids:
                    lines.append(f"  - {link.reason} [{link.confidence} confidence]")
            for f in members:
                if f["id"] == primary["id"]:
                    continue
                link = next(l for l in links if f["id"] in (l.a, l.b))
                rows.append((f["id"], primary["id"], link.confidence,
                             f"Duplicate of finding {primary['id']}: {link.reason}."))
    with conn:
        conn.execute("DELETE FROM duplicates")
        conn.executemany("INSERT INTO duplicates (finding_id, primary_id, confidence, reason) VALUES (?, ?, ?, ?)",
                         rows)
    total = conn.execute("SELECT count(*) FROM findings").fetchone()[0]
    lines.append(f"{len(rows)} of {total} findings are duplicates of another scanner's report.")
    return lines
