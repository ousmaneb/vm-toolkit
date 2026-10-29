"""Numbers for the weekly leadership reports, worked out from the database. report_pdf.py lays them out."""

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .config import Settings
from .db import parse_iso, utcnow
from .forecast import forecast

SEVERITIES = ["critical", "high", "medium", "low"]
LOOKBACK_DAYS = 90  # window for "how fast do we fix things", long enough to hold a useful number of fixes


@dataclass
class Finding:
    id: int
    machine: str
    title: str
    severity: str
    first_seen: datetime
    fixed_at: datetime | None
    cves: list[str]


@dataclass
class Snapshot:
    open: int
    critical_high: int
    overdue: int
    known_exploited: int


@dataclass
class ReportData:
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    days: int
    fake: bool
    now: Snapshot
    before: Snapshot
    new: int
    fixed: int
    trend: list[tuple[datetime, int, int]]  # week end, open, critical + high
    compliance: list[dict]  # per severity
    on_time_rate: float | None
    kev_open: list[dict]
    kev_new: list[dict]
    top_fixes: list[dict]
    total_risk: float
    top_risks: list[dict]
    misses: list[dict]
    overdue_by_machine: list[tuple[str, int]]
    freshness: list[tuple[str, str]]
    last_scan: datetime | None = None
    first_seen: datetime | None = None  # earliest finding: no trend can be claimed before there was data
    status: str = "green"
    status_reason: str = ""
    summary: list[str] = field(default_factory=list)
    attention: list[str] = field(default_factory=list)
    impact: list[str] = field(default_factory=list)
    advice: list[tuple[str, str]] = field(default_factory=list)  # (what to do, why and how)
    questions: list[str] = field(default_factory=list)


def _days(a: datetime, b: datetime) -> float:
    return (b - a).total_seconds() / 86400


def load_findings(conn: sqlite3.Connection) -> list[Finding]:
    """Same scope as the dashboard: no info-level findings, nothing marked as a false positive."""
    cves: dict[int, list[str]] = {}
    for row in conn.execute("SELECT finding_id, cve FROM finding_cves ORDER BY cve"):
        cves.setdefault(row["finding_id"], []).append(row["cve"])
    rows = conn.execute(
        """SELECT f.id, a.name AS machine, f.title, f.severity, f.first_seen, f.fixed_at
           FROM findings f JOIN assets a ON a.id = f.asset_id
           WHERE f.severity != 'info' AND f.first_seen IS NOT NULL
             AND f.id NOT IN (SELECT finding_id FROM fp_labels WHERE label = 'false_positive')""")
    return [Finding(r["id"], r["machine"], r["title"], r["severity"], parse_iso(r["first_seen"]),
                    parse_iso(r["fixed_at"]) if r["fixed_at"] else None, cves.get(r["id"], []))
            for r in rows]


def is_open(f: Finding, at: datetime) -> bool:
    return f.first_seen <= at and (f.fixed_at is None or f.fixed_at > at)


def snapshot(findings: list[Finding], kev: dict[str, datetime], sla: dict[str, int], at: datetime) -> Snapshot:
    open_ = [f for f in findings if is_open(f, at)]
    return Snapshot(
        open=len(open_),
        critical_high=sum(f.severity in ("critical", "high") for f in open_),
        overdue=sum(f.severity in sla and _days(f.first_seen, at) > sla[f.severity] for f in open_),
        known_exploited=sum(any(c in kev and kev[c] <= at for c in f.cves) for f in open_),
    )


def _kev(conn: sqlite3.Connection) -> dict[str, datetime]:
    """CVE -> when it was added to KEV (or when we first saw it there, if CISA gave no date)."""
    return {r["cve"]: parse_iso(r["date_added"] + "T00:00:00Z" if r["date_added"] else r["first_seen_at"])
            for r in conn.execute("SELECT cve, date_added, first_seen_at FROM kev")}


def period_ago(days: int) -> str:
    return "last week" if days == 7 else f"{days} days ago"


def period_name(days: int) -> str:
    return {7: "weekly", 30: "monthly", 90: "quarterly"}.get(days, f"{days}-day")


def _plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else many or word + 's'}"


def build(conn: sqlite3.Connection, settings: Settings, days: int = 7, now: datetime | None = None) -> ReportData:
    now = now or parse_iso(utcnow())
    start = now - timedelta(days=days)
    sla = {k: int(v) for k, v in settings.section("sla_days").items()}
    findings = load_findings(conn)
    kev = _kev(conn)
    fake = bool(conn.execute("SELECT EXISTS (SELECT 1 FROM findings WHERE is_fake = 1)").fetchone()[0])

    trend = []
    for weeks_back in range(11, -1, -1):
        at = now - timedelta(weeks=weeks_back)
        s = snapshot(findings, kev, sla, at)
        trend.append((at, s.open, s.critical_high))

    since = now - timedelta(days=LOOKBACK_DAYS)
    compliance = []
    fixed_recent = [f for f in findings if f.fixed_at and since < f.fixed_at <= now]
    for sev in SEVERITIES:
        done = [f for f in fixed_recent if f.severity == sev]
        on_time = [f for f in done if sev in sla and _days(f.first_seen, f.fixed_at) <= sla[sev]]
        open_ = [f for f in findings if f.severity == sev and is_open(f, now)]
        compliance.append({
            "severity": sev, "deadline": sla.get(sev), "fixed": len(done),
            "on_time": len(on_time) / len(done) if done else None,
            "avg_days": sum(_days(f.first_seen, f.fixed_at) for f in done) / len(done) if done else None,
            "open": len(open_),
            "overdue": sum(sev in sla and _days(f.first_seen, now) > sla[sev] for f in open_),
        })
    graded = [f for f in fixed_recent if f.severity in sla]
    on_time_rate = (sum(_days(f.first_seen, f.fixed_at) <= sla[f.severity] for f in graded) / len(graded)
                    if graded else None)

    ransomware = {r[0] for r in conn.execute("SELECT cve FROM kev WHERE ransomware = 'Known'")}
    internet = {r[0] for r in conn.execute("SELECT finding_id FROM priorities WHERE exposure >= 1.0")}
    kev_open = []
    for f in findings:
        listed = [c for c in f.cves if c in kev and kev[c] <= now]
        if listed and is_open(f, now):
            age = _days(f.first_seen, now)
            kev_open.append({"cve": listed[0], "machine": f.machine, "title": f.title, "severity": f.severity,
                             "days_open": int(age), "overdue": f.severity in sla and age > sla[f.severity],
                             "kev_added": kev[listed[0]], "ransomware": any(c in ransomware for c in listed),
                             "internet": f.id in internet})
    kev_open.sort(key=lambda r: (not r["overdue"], -r["days_open"]))
    kev_new = [r for r in kev_open if r["kev_added"] > start]

    fixes = conn.execute(
        """SELECT p.rank, p.action, p.risk, p.share, count(i.finding_id) AS findings,
                  count(DISTINCT f.asset_id) AS machines
           FROM plan_fixes p JOIN plan_items i ON i.fix_key = p.fix_key JOIN findings f ON f.id = i.finding_id
           GROUP BY p.fix_key ORDER BY p.rank""").fetchall()
    total_risk = conn.execute("SELECT coalesce(sum(score), 0) FROM priorities").fetchone()[0]
    top_fixes, cumulative = [], 0.0
    for r in fixes[:10]:
        cumulative += r["share"]
        top_fixes.append({**dict(r), "cumulative": cumulative})

    top_risks = [dict(r) for r in conn.execute(
        """SELECT p.rank, p.score, a.name AS machine, f.severity, f.title,
                  (SELECT group_concat(cve, ', ') FROM finding_cves c WHERE c.finding_id = f.id) AS cves,
                  EXISTS (SELECT 1 FROM finding_cves c JOIN kev k ON k.cve = c.cve WHERE c.finding_id = f.id) AS kev
           FROM priorities p JOIN findings f ON f.id = p.finding_id JOIN assets a ON a.id = f.asset_id
           WHERE f.status = 'open' ORDER BY p.rank LIMIT 10""")]

    horizon = (now + timedelta(days=30)).strftime("%Y-%m-%d")
    misses = [{"finding": m.finding_id, "machine": m.machine, "title": m.title, "severity": m.severity,
               "due": m.due, "chance": m.p_on_time}
              for m in forecast(conn, settings, as_of=now) if m.at_risk and m.due <= horizon]
    misses.sort(key=lambda m: (m["due"], m["chance"]))

    by_machine: dict[str, int] = {}
    for f in findings:
        if is_open(f, now) and f.severity in sla and _days(f.first_seen, now) > sla[f.severity]:
            by_machine[f.machine] = by_machine.get(f.machine, 0) + 1
    overdue_by_machine = sorted(by_machine.items(), key=lambda kv: (-kv[1], kv[0]))[:10]

    freshness = [(f"Last {r['scanner']} scan", r["last"][:10]) for r in conn.execute(
        "SELECT scanner, max(finished_at) AS last FROM scans GROUP BY scanner ORDER BY scanner")]
    last_scan = conn.execute("SELECT max(finished_at) FROM scans").fetchone()[0]
    last_epss = conn.execute("SELECT max(date) FROM epss_history").fetchone()[0]
    last_rank = conn.execute("SELECT max(computed_at) FROM priorities").fetchone()[0]
    freshness += [("Threat data (EPSS) updated", last_epss or "never"),
                  ("Findings last ranked", last_rank[:10] if last_rank else "never")]

    data = ReportData(
        generated_at=now, period_start=start, period_end=now, days=days, fake=fake,
        now=snapshot(findings, kev, sla, now), before=snapshot(findings, kev, sla, start),
        new=sum(start < f.first_seen <= now for f in findings),
        fixed=sum(f.fixed_at is not None and start < f.fixed_at <= now for f in findings),
        trend=trend, compliance=compliance, on_time_rate=on_time_rate, kev_open=kev_open, kev_new=kev_new,
        top_fixes=top_fixes, total_risk=total_risk, top_risks=top_risks, misses=misses,
        overdue_by_machine=overdue_by_machine, freshness=freshness,
        last_scan=parse_iso(last_scan) if last_scan else None,
        first_seen=min((f.first_seen for f in findings), default=None),
    )
    data.status, data.status_reason = rate(data)
    data.summary = summarize(data, days)
    data.attention = needs_attention(data)
    data.impact = business_impact(data)
    data.advice = recommendations(data)
    data.questions = questions(data)
    return data


def rate(d: ReportData) -> tuple[str, str]:
    kev_late = sum(r["overdue"] for r in d.kev_open)
    critical_late = next(c["overdue"] for c in d.compliance if c["severity"] == "critical")
    if kev_late:
        return "red", (f"{_plural(kev_late, 'vulnerability', 'vulnerabilities')} that attackers are known to "
                       f"exploit {'is' if kev_late == 1 else 'are'} past {'its' if kev_late == 1 else 'their'} "
                       "fix deadline.")
    if critical_late:
        return "red", f"{_plural(critical_late, 'critical vulnerability', 'critical vulnerabilities')} past deadline."
    if d.now.overdue or (d.on_time_rate is not None and d.on_time_rate < 0.9):
        why = []
        if d.now.overdue:
            why.append(f"{_plural(d.now.overdue, 'vulnerability', 'vulnerabilities')} past deadline")
        if d.on_time_rate is not None and d.on_time_rate < 0.9:
            why.append(f"only {d.on_time_rate:.0%} of recent fixes met their deadline (target 90%)")
        return "amber", "; ".join(why).capitalize() + "."
    return "green", "Nothing is past its deadline and recent fixes met their deadlines."


def summarize(d: ReportData, days: int) -> list[str]:
    change = d.now.open - d.before.open
    trend = ("unchanged" if change == 0 else f"{abs(change)} {'more' if change > 0 else 'fewer'}")
    period = period_ago(days)
    lines = [f"There are {_plural(d.now.open, 'open vulnerability', 'open vulnerabilities')}, {trend} than "
             f"{period}: {d.new} found and {d.fixed} fixed in the period." if change else
             f"There are {_plural(d.now.open, 'open vulnerability', 'open vulnerabilities')}, the same as {period}: "
             f"{d.new} found and {d.fixed} fixed in the period."]
    kev_late = sum(r["overdue"] for r in d.kev_open)
    if d.now.known_exploited:
        lines.append(f"{d.now.known_exploited} of them {'is' if d.now.known_exploited == 1 else 'are'} on CISA's "
                     f"list of vulnerabilities attackers are actively exploiting"
                     + (f"; {kev_late} of those {'is' if kev_late == 1 else 'are'} past the fix deadline." if kev_late
                        else ", and all are within their fix deadline."))
    else:
        lines.append("None of them is on CISA's list of vulnerabilities attackers are actively exploiting.")
    if d.on_time_rate is not None:
        crit = next(c for c in d.compliance if c["severity"] == "critical")
        speed = f" Critical issues took {crit['avg_days']:.0f} days on average." if crit["avg_days"] is not None else ""
        lines.append(f"Over the last {LOOKBACK_DAYS} days, {d.on_time_rate:.0%} of fixes met their deadline.{speed}")
    if len(d.top_fixes) >= 3:
        lines.append(f"The three highest-value fixes in the patch plan would remove "
                     f"{d.top_fixes[2]['cumulative']:.0%} of the measured risk.")
    return lines


def needs_attention(d: ReportData) -> list[str]:
    items = []
    kev_late = [r for r in d.kev_open if r["overdue"]]
    if kev_late:
        machines = len({r["machine"] for r in kev_late})
        items.append(f"{_plural(len(kev_late), 'actively exploited vulnerability', 'actively exploited vulnerabilities')}"
                     f" past deadline on {_plural(machines, 'machine')}.")
    if d.kev_new:
        items.append(f"{len(d.kev_new)} newly added to CISA's actively-exploited list this period.")
    if d.misses:
        items.append(f"{_plural(len(d.misses), 'vulnerability', 'vulnerabilities')} likely to miss "
                     "{its} deadline in the next 30 days at the current pace.".format(
                         its="its" if len(d.misses) == 1 else "their"))
    if d.overdue_by_machine:
        name, count = d.overdue_by_machine[0]
        items.append(f"Most overdue machine: {name} ({count} past deadline).")
    return items


def report_path(settings: Settings, audience: str, when: datetime, days: int = 7) -> Path:
    """data/reports/2026-10-29-ceo.pdf for a weekly report on the main database. Other databases get their
    name added, and other periods their length: 2026-10-29-fake-ceo-30d.pdf."""
    stem = "" if settings.db_path.resolve() == (settings.data_dir / "vmt.db").resolve() else f"-{settings.db_path.stem}"
    period = "" if days == 7 else f"-{days}d"
    return settings.data_dir / "reports" / f"{when:%Y-%m-%d}{stem}-{audience}{period}.pdf"


GLOSSARY = [
    ("Vulnerability", "A weakness in software that an attacker could use to break in, steal data or stop a "
                      "system working. Fixing one usually means installing an update."),
    ("Actively exploited", "On the US government's (CISA) public list of weaknesses that criminals are using in "
                           "real attacks right now. These are the most urgent."),
    ("Critical / high", "The scanner's rating of how much damage a weakness could do. Critical is the worst."),
    ("Deadline", "How long we allow ourselves to fix a weakness, depending on how serious it is. Past deadline "
                 "means it has been open longer than that."),
    ("Measured risk", "Our score for each weakness: how likely it is to be attacked, how bad it would be, how "
                      "important the computer is, and whether it can be reached from the internet."),
    ("Fix / update", "Installing a newer version of the software, which removes the weakness. One update often "
                     "fixes many weaknesses on many computers at once."),
]


def has_history(d: ReportData) -> bool:
    return d.first_seen is not None and d.first_seen < d.period_start


def business_impact(d: ReportData) -> list[str]:
    """What the numbers mean for the business, without security jargon."""
    out = []
    late = [r for r in d.kev_open if r["overdue"]]
    if d.kev_open:
        weaknesses = {r["cve"] for r in d.kev_open}
        machines = {r["machine"] for r in d.kev_open}
        text = (f"Criminals are actively using {_plural(len(weaknesses), 'weakness', 'weaknesses')} that we still "
                f"have. {'It shows' if len(weaknesses) == 1 else 'They show'} up as "
                f"{_plural(len(d.kev_open), 'open problem')} on {_plural(len(machines), 'computer')}. These are the "
                "most likely way an attacker would get into our systems.")
        ransom = {r["cve"] for r in d.kev_open if r["ransomware"]}
        if ransom:
            text += (f" {len(ransom)} of the {_plural(len(weaknesses), 'weakness', 'weaknesses')} "
                     f"{'is' if len(ransom) == 1 else 'are'} known to be used by ransomware gangs, who lock up "
                     "systems and demand payment.")
        exposed = {r["machine"] for r in d.kev_open if r["internet"]}
        if exposed:
            text += (f" {len(exposed)} of the affected computers {'is' if len(exposed) == 1 else 'are'} reachable "
                     "from the internet.")
        out.append(text)
    else:
        out.append("None of the weaknesses we have are on the public list of ones criminals are using right now. "
                   "That lowers the immediate risk, but it can change any day.")
    if late:
        which = ("That problem is" if len(d.kev_open) == 1 else
                 f"All {len(d.kev_open)} are" if len(late) == len(d.kev_open) else
                 f"{len(late)} of those {len(d.kev_open)} problems {'is' if len(late) == 1 else 'are'}")
        out.append(f"{which} past our own fix deadline. If one were used in an attack, it would be hard to show we "
                   "had acted reasonably, which matters for insurers, customers and regulators.")
    if not has_history(d):
        out.append("This is the first period with scan results, so there is no trend yet. The next report will "
                   "show whether things are getting better or worse.")
    else:
        monthly = (d.new - d.fixed) * 30 / d.days
        if monthly >= 1:
            out.append(f"We are finding new weaknesses faster than we fix them. At this pace the backlog grows by "
                       f"about {monthly:.0f} a month.")
        elif monthly <= -1:
            out.append(f"We are fixing weaknesses faster than new ones appear. At this pace the backlog shrinks by "
                       f"about {-monthly:.0f} a month.")
        else:
            out.append("New weaknesses and fixes are roughly in balance, so the backlog is holding steady.")
    if d.on_time_rate is not None and d.on_time_rate < 0.9:
        crit = next(c for c in d.compliance if c["severity"] == "critical")
        slow = (f" The most serious ones take {crit['avg_days']:.0f} days on average against a "
                f"{crit['deadline']}-day deadline." if crit["avg_days"] and crit["deadline"]
                and crit["avg_days"] > crit["deadline"] else "")
        out.append(f"Only {d.on_time_rate:.0%} of fixes are done on time (our target is 90%).{slow} The longer a "
                   "weakness stays open, the longer the window for an attacker.")
    return out


def recommendations(d: ReportData) -> list[tuple[str, str]]:
    """Concrete next steps, most urgent first."""
    out = []
    late = [r for r in d.kev_open if r["overdue"]]
    if late:
        out.append((f"Fix the {_plural(len(late), 'overdue actively exploited problem')} this week.",
                    "These are the ones attackers are using now. Where an update can't be installed straight away, "
                    "disconnect the affected computers or restrict who can reach them until it can."))
    elif d.kev_open:
        out.append(("Keep the actively exploited weaknesses at the top of the list.",
                    "They are still within deadline. Fix them before anything else so they never become overdue."))
    if len(d.top_fixes) >= 3:
        out.append((f"Approve time for the three highest-value updates ({d.top_fixes[2]['cumulative']:.0%} of our "
                    "measured risk).",
                    "Each update fixes many problems at once, so these give the best return on effort. They are "
                    "listed under Highest-value fixes on page 1."))
    if d.on_time_rate is not None and d.on_time_rate < 0.9:
        out.append(("Set a regular maintenance window.",
                    "A fixed slot, for example every second week, stops updates waiting for spare time. It is the "
                    "most reliable way to meet deadlines."))
    if d.overdue_by_machine and d.overdue_by_machine[0][1] >= 5:
        name, count = d.overdue_by_machine[0]
        out.append((f"Review {name}.",
                    f"It has {count} overdue problems, the most of any computer. Check that it has an owner, that "
                    "it is still needed, and whether it can be updated or replaced."))
    if has_history(d) and (d.new - d.fixed) * 30 / d.days >= 1:
        out.append(("Stop the backlog growing.",
                    "Either free up more time for fixing, or reduce how many new problems appear, for example by "
                    "retiring old software and computers that are no longer needed."))
    if d.last_scan is None or (d.generated_at - d.last_scan).days > 7:
        when = f"since {d.last_scan:%B %d}" if d.last_scan else "yet"
        out.append(("Check the scanner.",
                    f"No new scan results have arrived {when}, so these numbers may be out of date."))
    if not out:
        out.append(("Keep the current routine.",
                    "Nothing is overdue and fixes are on time. Keep scanning and patching on the same schedule."))
    return out


def questions(d: ReportData) -> list[str]:
    out = []
    if any(r["overdue"] for r in d.kev_open):
        out.append("Which of the actively exploited weaknesses can't be fixed this week, and what are we doing "
                   "to protect those computers in the meantime?")
    if d.on_time_rate is not None and d.on_time_rate < 0.9:
        out.append("What would it take to fix 90% of problems within deadline: time, people, or approval for "
                   "downtime?")
    if d.top_fixes:
        out.append("Is anything blocking the top updates, such as a supplier, a system that can't be restarted, or "
                   "testing?")
    out.append("Are there computers or systems that aren't being scanned at all?")
    return out
