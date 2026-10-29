"""Group open findings into fixes and order them by how much risk each removes.

Each finding is closed by exactly one fix, so sorting fixes by the risk they remove is already
the best order: no combination of k fixes removes more risk than the top k.
"""

import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field

from .config import Settings
from .db import utcnow
from .deps import version_key
from .prioritize import prioritize


@dataclass
class Fix:
    key: str
    action: str
    risk: float = 0.0
    findings: list[dict] = field(default_factory=list)
    machines: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)
    rank: int = 0
    share: float = 0.0
    cumulative: float = 0.0

    def explain(self) -> str:
        top = sorted(self.findings, key=lambda f: -f["score"])
        listed = ", ".join(f"#{f['rank']} {f['title']} on {f['machine']} ({f['score']:.1f})" for f in top[:5])
        more = f" and {len(top) - 5} more" if len(top) > 5 else ""
        lines = [f"Fix {self.rank}: {self.action}",
                 f"  Machines: {', '.join(sorted(self.machines))}",
                 f"  Removes risk {self.risk:.1f} ({self.share:.0%} of the total), the sum of the priority scores "
                 f"of the {len(top)} findings it closes: {listed}{more}."]
        lines += [f"  Note: {n}" for n in self.notes]
        return "\n".join(lines)


def _solution_key(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower()).rstrip(".")


def build_fixes(conn: sqlite3.Connection) -> list[Fix]:
    rows = conn.execute(
        """SELECT p.rank, p.score, f.id, f.scanner, f.rule_id, f.title, f.package, f.installed_version,
                  f.fixed_version, f.solution, a.name AS machine
           FROM priorities p JOIN findings f ON f.id = p.finding_id JOIN assets a ON a.id = f.asset_id
           ORDER BY p.rank"""
    ).fetchall()
    fixes: dict[str, Fix] = {}
    versions: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        if r["package"]:
            key = f"package:{r['package'].lower()}"
            action = f"Upgrade {r['package']}"
            if r["fixed_version"]:
                versions[key].add(r["fixed_version"])
        elif r["solution"]:
            key = f"solution:{_solution_key(r['solution'])}"
            action = r["solution"].strip()
        else:
            key = f"rule:{r['scanner']}:{r['rule_id']}"
            action = f"Remediate: {r['title']} (the scanner gave no fix steps)"
        fix = fixes.setdefault(key, Fix(key=key, action=action))
        fix.risk += r["score"]
        fix.machines.add(r["machine"])
        fix.findings.append({"id": r["id"], "rank": r["rank"], "score": r["score"], "title": r["title"],
                             "machine": r["machine"], "fixed_version": r["fixed_version"]})

    for key, fix in fixes.items():
        if not key.startswith("package:"):
            continue
        if versions[key]:
            target = max(versions[key], key=version_key)
            fix.action += f" to {target} or later"
            if len(versions[key]) > 1:
                fix.notes.append(f"its findings need different versions ({', '.join(sorted(versions[key], key=version_key))}); "
                                 f"{target} is the highest, so it covers all of them")
        if any(not f["fixed_version"] for f in fix.findings):
            fix.notes.append("some of these findings list no fixed version; check the vendor advisory")

    ordered = sorted(fixes.values(), key=lambda f: (-f.risk, f.key))
    total = sum(f.risk for f in ordered) or 1.0
    running = 0.0
    for i, fix in enumerate(ordered, start=1):
        running += fix.risk
        fix.rank, fix.share, fix.cumulative = i, fix.risk / total, running / total
    return ordered


def plan(conn: sqlite3.Connection, settings: Settings, target: float | None = None,
         max_fixes: int | None = None) -> tuple[list[Fix], list[Fix], str]:
    """Return (chosen fixes, the rest, a one-line summary) and store the plan for the ticket generator."""
    prioritize(conn, settings)
    fixes = build_fixes(conn)
    if not fixes:
        return [], [], "No open findings, so there is nothing to fix."
    if target is None and max_fixes is None:
        target = 0.8
    chosen = []
    for fix in fixes:
        if max_fixes is not None and len(chosen) >= max_fixes:
            break
        chosen.append(fix)
        if target is not None and fix.cumulative >= target:
            break
    rest = fixes[len(chosen):]
    removed = chosen[-1].cumulative
    summary = (f"These {len(chosen)} fixes remove {removed:.0%} of the total risk "
               f"({sum(f.risk for f in chosen):.1f} of {sum(f.risk for f in fixes):.1f}).")
    if rest:
        summary += f" The other {len(rest)} fixes remove the remaining {1 - removed:.0%}."

    with conn:
        conn.execute("DELETE FROM plan_items")
        conn.execute("DELETE FROM plan_fixes")
        conn.executemany(
            "INSERT INTO plan_fixes (fix_key, rank, action, risk, share, explanation) VALUES (?, ?, ?, ?, ?, ?)",
            [(f.key, f.rank, f.action, f.risk, f.share, f.explain()) for f in fixes],
        )
        conn.executemany("INSERT INTO plan_items (fix_key, finding_id) VALUES (?, ?)",
                         [(f.key, item["id"]) for f in fixes for item in f.findings])
        # Keep this plan for the history; a later run the same day replaces it.
        day = utcnow()[:10]
        conn.execute("DELETE FROM plan_history WHERE day = ?", (day,))
        conn.executemany(
            """INSERT INTO plan_history (day, rank, action, risk, share, findings, machines)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(day, f.rank, f.action, f.risk, f.share, len(f.findings), len(f.machines)) for f in fixes])
    return chosen, rest, summary
