"""Rank open findings by exploit likelihood x impact x machine importance, and say why."""

import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field

from .assets import asset_config
from .config import Settings
from .db import utcnow
from .dedupe import dedupe

DEFAULTS = {
    # A public exploit means someone can use it today, even if EPSS hasn't caught up.
    "exploit_floor": 0.5,
    # Used when there's no EPSS score: findings without a CVE, or CVEs not enriched yet.
    "no_epss_likelihood": {"critical": 0.3, "high": 0.2, "medium": 0.05, "low": 0.01},
    # Applied unless the machine is internet-facing and the attack works over the network.
    "internal_factor": 0.8,
}
SEVERITY_IMPACT = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5}
PREDICTED_VECTOR_MIN = 0.8
# NVD's attack vector words, as stored in the cves table by `vmt enrich`.
VECTOR_WORDS = {"NETWORK": "network", "ADJACENT_NETWORK": "adjacent_network", "LOCAL": "local", "PHYSICAL": "physical"}


@dataclass
class Ranked:
    finding_id: int
    machine: str
    title: str
    severity: str
    first_seen: str
    score: float
    likelihood: float
    impact: float
    weight: float
    exposure: float
    on_kev: bool
    factors: list[str] = field(default_factory=list)
    rank: int = 0
    rank_reason: str = ""

    def explain(self) -> str:
        lines = [f"#{self.rank} score {self.score:.1f}: {self.title} on {self.machine} ({self.severity})",
                 *[f"  - {f}" for f in self.factors],
                 f"  = 100 x {self.likelihood:.2f} x {self.impact:.2f} x {self.weight:.2f} x {self.exposure:.2f} "
                 f"= {self.score:.1f}",
                 f"  {self.rank_reason}"]
        return "\n".join(lines)


def _options(settings: Settings) -> dict:
    cfg = settings.section("prioritize")
    return {**DEFAULTS, **cfg, "no_epss_likelihood": {**DEFAULTS["no_epss_likelihood"],
                                                      **cfg.get("no_epss_likelihood", {})}}


def _likelihood(cves: set[str], severity: str, intel: dict, opts: dict) -> tuple[float, str]:
    if not cves:
        value = opts["no_epss_likelihood"][severity]
        return value, f"likelihood {value:.2f}: no CVE, so the default for {severity} findings is used"
    best, best_reason = -1.0, ""
    for cve in sorted(cves):
        info = intel.get(cve, {})
        if info.get("kev"):
            value, reason = 1.0, f"{cve} is on CISA KEV (known exploited), so likelihood is 1.00"
        else:
            if info.get("epss") is not None:
                value, reason = info["epss"], f"{cve} EPSS {info['epss']:.3f}"
            else:
                value = opts["no_epss_likelihood"][severity]
                reason = (f"{cve} has no EPSS score stored (run `vmt enrich`), so the {severity} default "
                          f"{value:.2f} is used")
            if info.get("exploit") and value < opts["exploit_floor"]:
                value = opts["exploit_floor"]
                reason += f", raised to {value:.2f} because a public exploit exists ({info['exploit']})"
        if value > best:
            best, best_reason = value, reason
    if len(cves) > 1:
        best_reason += f" (highest of {len(cves)} CVEs)"
    return best, f"likelihood {best:.2f}: {best_reason}"


def _cve_intel(conn: sqlite3.Connection) -> dict[str, dict]:
    intel: dict[str, dict] = defaultdict(dict)
    for r in conn.execute("""SELECT cve, epss FROM epss_history e
                             WHERE date = (SELECT max(date) FROM epss_history WHERE cve = e.cve)"""):
        intel[r["cve"]]["epss"] = r["epss"]
    for r in conn.execute("SELECT cve FROM kev"):
        intel[r["cve"]]["kev"] = True
    for r in conn.execute("SELECT cve, source, ref FROM exploits ORDER BY source, ref"):
        intel[r["cve"]].setdefault("exploit", f"{r['source']} {r['ref']}")
    for r in conn.execute("SELECT cve, cvss_score, attack_vector FROM cves"):
        intel[r["cve"]]["cvss"] = r["cvss_score"]
        intel[r["cve"]]["vector"] = r["attack_vector"]
    # A confident prediction stands in for a missing NVD attack vector (see `vmt classify`).
    for r in conn.execute("SELECT cve, attack_vector, vector_confidence FROM cve_predictions WHERE vector_confidence >= ?",
                          (PREDICTED_VECTOR_MIN,)):
        if not intel[r["cve"]].get("vector"):
            intel[r["cve"]]["predicted_vector"] = (VECTOR_WORDS.get(r["attack_vector"], r["attack_vector"].lower()),
                                                   r["vector_confidence"])
    return intel


def score_findings(conn: sqlite3.Connection, settings: Settings) -> list[Ranked]:
    opts = _options(settings)
    intel = _cve_intel(conn)
    cves: dict[int, set[str]] = defaultdict(set)
    for r in conn.execute("SELECT finding_id, cve FROM finding_cves"):
        cves[r["finding_id"]].add(r["cve"])
    members: dict[int, list[sqlite3.Row]] = defaultdict(list)
    for r in conn.execute("""SELECT d.primary_id, f.* FROM duplicates d JOIN findings f ON f.id = d.finding_id
                             WHERE f.status = 'open'"""):
        members[r["primary_id"]].append(r)

    ranked = []
    for f in conn.execute(
        """SELECT f.*, a.name AS machine, a.ip FROM findings f JOIN assets a ON a.id = f.asset_id
           WHERE f.status = 'open' AND f.severity != 'info'
             AND f.id NOT IN (SELECT finding_id FROM duplicates)
             AND f.id NOT IN (SELECT finding_id FROM fp_labels WHERE label = 'false_positive')"""
    ).fetchall():
        dupes = members.get(f["id"], [])
        all_cves = cves[f["id"]].union(*(cves[d["id"]] for d in dupes))
        factors = []
        if dupes:
            factors.append("also reported by " + ", ".join(f"{d['scanner']} (finding {d['id']})" for d in dupes)
                           + "; counted once, using CVEs from all reports")

        likelihood, reason = _likelihood(all_cves, f["severity"], intel, opts)
        factors.append(reason)

        scores = [s for s in [f["cvss_score"], *(d["cvss_score"] for d in dupes)] if s is not None]
        nvd_scores = [intel[c]["cvss"] for c in all_cves if intel.get(c, {}).get("cvss") is not None]
        if scores:
            cvss, source = max(scores), "scanner"
        elif nvd_scores:
            cvss, source = max(nvd_scores), "NVD"
        else:
            cvss, source = SEVERITY_IMPACT[f["severity"]], f"no CVSS available, typical for {f['severity']}"
        impact = cvss / 10
        factors.append(f"impact {impact:.2f}: CVSS {cvss} ({source})")

        asset = asset_config(settings, f["machine"], f["ip"])
        where = f'[assets."{asset.matched}"]' if asset.matched else "not listed in config, so the default"
        factors.append(f"machine importance {asset.weight:.2f}: {f['machine']} is {asset.criticality} ({where})")

        vectors = {intel.get(c, {}).get("vector") for c in all_cves} - {None}
        predicted = [intel[c]["predicted_vector"] for c in all_cves if intel.get(c, {}).get("predicted_vector")]
        vector_source = ""
        if not vectors and predicted:
            vectors = {v for v, _ in predicted}
            vector_source = (" (predicted from the description, "
                             f"{max(p for _, p in predicted):.0%} confident, as NVD hasn't scored it)")
        network = not vectors or "network" in vectors
        if asset.internet_facing and network:
            exposure = 1.0
            vector_note = "" if vectors else " (attack vector unknown, assumed network)"
            factors.append(f"exposure 1.00: internet-facing and attackable over the network{vector_note}{vector_source}")
        else:
            exposure = float(opts["internal_factor"])
            why = "not internet-facing" if not asset.internet_facing else \
                f"attack vector is {', '.join(sorted(vectors))}, not network{vector_source}"
            factors.append(f"exposure {exposure:.2f}: {why}")

        ranked.append(Ranked(
            finding_id=f["id"], machine=f["machine"], title=f["title"], severity=f["severity"],
            first_seen=f["first_seen"] or "", score=round(100 * likelihood * impact * asset.weight * exposure, 1),
            likelihood=likelihood, impact=impact, weight=asset.weight, exposure=exposure,
            on_kev=any(intel.get(c, {}).get("kev") for c in all_cves), factors=factors,
        ))

    # Ties go to the finding that has been open longer.
    ranked.sort(key=lambda r: (-r.score, r.first_seen, r.finding_id))
    for i, r in enumerate(ranked, start=1):
        r.rank = i
        if i == 1:
            r.rank_reason = "Ranked first: highest score."
            continue
        above = ranked[i - 2]
        if above.score > r.score:
            r.rank_reason = f"Ranked below #{i - 1} because its score is lower ({r.score:.1f} vs {above.score:.1f})."
        elif above.first_seen < r.first_seen:
            r.rank_reason = (f"Same score as #{i - 1}; ranked below it because it was first seen later "
                             f"({r.first_seen[:10]} vs {above.first_seen[:10]}).")
        else:
            r.rank_reason = f"Same score and first-seen date as #{i - 1}; the order between them is arbitrary."
    return ranked


def prioritize(conn: sqlite3.Connection, settings: Settings) -> list[Ranked]:
    """Refresh duplicate groups, score every open finding and store the ranking."""
    dedupe(conn, settings)
    ranked = score_findings(conn, settings)
    now = utcnow()
    with conn:
        conn.execute("DELETE FROM priorities")
        conn.executemany(
            """INSERT INTO priorities (finding_id, rank, score, likelihood, impact, weight, exposure,
                                       explanation, computed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(r.finding_id, r.rank, r.score, r.likelihood, r.impact, r.weight, r.exposure, r.explain(), now)
             for r in ranked],
        )
        # Keep this ranking for the history; a later run the same day replaces it.
        conn.execute("DELETE FROM priority_history WHERE day = ?", (now[:10],))
        conn.executemany("INSERT INTO priority_history (day, finding_id, rank, score) VALUES (?, ?, ?, ?)",
                         [(now[:10], r.finding_id, r.rank, r.score) for r in ranked])
    return ranked
