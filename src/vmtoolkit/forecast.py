"""Forecast how long open findings will take to fix, and which will probably miss their deadline.

Averaging the time-to-fix of fixed findings underestimates it, because the slowest findings are
still open and left out. Kaplan-Meier survival curves count open findings as "not fixed yet after
N days", which removes that bias.
"""

import sqlite3
from bisect import bisect_right
from dataclasses import dataclass
from functools import lru_cache
from itertools import groupby
from datetime import datetime, timedelta, timezone

from .assets import asset_config
from .config import Settings
from .db import parse_iso, utcnow

MIN_EVENTS = 10


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")
NOT_FP = "SELECT finding_id FROM fp_labels WHERE label = 'false_positive'"


class Survival:
    """Kaplan-Meier estimate of P(still open after t days)."""

    def __init__(self, durations: list[float], fixed: list[bool]):
        self.events = sum(fixed)
        self.n = len(durations)
        self.max_time = max(durations, default=0.0)
        self.times, self.values = [], []
        at_risk, s = len(durations), 1.0
        for t, group in groupby(sorted(zip(durations, fixed)), key=lambda pair: pair[0]):
            same = [f for _, f in group]
            events = sum(same)
            if events:
                s *= 1 - events / at_risk
                self.times.append(t)
                self.values.append(s)
            at_risk -= len(same)

    def __call__(self, t: float) -> float:
        i = bisect_right(self.times, t)
        return self.values[i - 1] if i else 1.0

    def median(self) -> float | None:
        return next((t for t, v in zip(self.times, self.values) if v <= 0.5), None)

    def conditional_median(self, age: float) -> float | None:
        """Day by which half of the findings still open at `age` were fixed."""
        target = self(age) / 2
        return next((t for t, v in zip(self.times, self.values) if t >= age and v <= target), None)


@dataclass
class Forecast:
    finding_id: int
    machine: str
    title: str
    severity: str
    age: int
    deadline_days: int
    due: str
    p_on_time: float | None
    expected_day: float | None
    reason: str

    @property
    def at_risk(self) -> bool:
        return self.p_on_time is not None and self.p_on_time < 0.5


def _history(conn: sqlite3.Connection, as_of: datetime, settings: Settings | None = None) -> list[dict]:
    """Every counted finding first seen by as_of, with what was known about it on that date."""
    rows = conn.execute(
        f"""SELECT f.id, f.severity, f.title, f.first_seen, f.fixed_at, a.name AS machine, a.ip
            FROM findings f JOIN assets a ON a.id = f.asset_id
            WHERE f.severity != 'info' AND f.first_seen IS NOT NULL
              AND f.id NOT IN (SELECT finding_id FROM duplicates) AND f.id NOT IN ({NOT_FP})"""
    ).fetchall()
    out = []
    for r in rows:
        first = parse_iso(r["first_seen"])
        if first > as_of:
            continue
        fixed = parse_iso(r["fixed_at"]) if r["fixed_at"] else None
        done = fixed is not None and fixed <= as_of
        end = fixed if done else as_of
        tier = asset_config(settings, r["machine"], r["ip"]).criticality if settings else "medium"
        out.append({**dict(r), "days": (end - first).total_seconds() / 86400, "fixed": done, "first": first,
                    "tier": tier})
    return out


def _curves(history: list[dict]):
    """Return a lookup (severity, machine) -> (curve, description), falling back to broader groups."""

    @lru_cache(maxsize=None)
    def build(severity: str | None, machine: str | None, tier: str | None) -> Survival:
        rows = [h for h in history if (severity is None or h["severity"] == severity)
                and (machine is None or h["machine"] == machine) and (tier is None or h["tier"] == tier)]
        return Survival([h["days"] for h in rows], [h["fixed"] for h in rows])

    def lookup(severity: str, machine: str, tier: str) -> tuple[Survival | None, str]:
        for sev, mach, tr, label in ((severity, machine, None, f"{severity} findings on {machine}"),
                                     (severity, None, tier, f"{severity} findings on {tier}-importance machines"),
                                     (severity, None, None, f"{severity} findings on all machines"),
                                     (None, None, None, "findings of every severity")):
            curve = build(sev, mach, tr)
            if curve.events >= MIN_EVENTS:
                return curve, f"{curve.events} past fixes of {label}"
        return None, "fewer than 10 past fixes to learn from"

    return lookup


def forecast(conn: sqlite3.Connection, settings: Settings, as_of: datetime | None = None) -> list[Forecast]:
    as_of = as_of or parse_iso(utcnow())
    sla = {k: int(v) for k, v in settings.section("sla_days").items()}
    history = _history(conn, as_of, settings)
    curve_for = _curves(history)
    out = []
    for h in history:
        if h["fixed"] or h["severity"] not in sla:
            continue
        age, deadline = h["days"], sla[h["severity"]]
        due = (h["first"] + timedelta(days=deadline)).strftime("%Y-%m-%d")
        base = dict(finding_id=h["id"], machine=h["machine"], title=h["title"], severity=h["severity"],
                    age=int(age), deadline_days=deadline, due=due)
        if age > deadline:
            out.append(Forecast(**base, p_on_time=None, expected_day=None,
                                reason=f"Already overdue: open {int(age)} days against a {deadline}-day deadline."))
            continue
        curve, source = curve_for(h["severity"], h["machine"], h["tier"])
        if curve is None:
            out.append(Forecast(**base, p_on_time=None, expected_day=None, reason=f"No forecast: {source}."))
            continue
        still_open = curve(age)
        p = 1 - curve(deadline) / still_open if still_open > 0 else 0.0
        expected = curve.conditional_median(age)
        when = (f"half of them were fixed by day {expected:.0f}" if expected is not None
                else "fewer than half of them were ever fixed in the history")
        beyond = (f" The history only covers {curve.max_time:.0f} days, so the estimate past that is flat."
                  if deadline > curve.max_time else "")
        reason = (f"Based on {source}: of those still open at day {int(age)}, {p:.0%} were fixed by day {deadline} "
                  f"(its deadline, {due}), and {when}.{beyond}")
        out.append(Forecast(**base, p_on_time=round(p, 3), expected_day=expected, reason=reason))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(out, key=lambda f: (not f.at_risk, f.p_on_time is None, f.p_on_time or 0, order[f.severity]))


def backtest(conn: sqlite3.Connection, settings: Settings, days_back: int = 90,
             now: datetime | None = None) -> str:
    """Forecast as of `days_back` ago and compare with what happened. Reports the Brier score."""
    now = now or parse_iso(utcnow())
    as_of = now - timedelta(days=days_back)
    results = []
    for f in forecast(conn, settings, as_of=as_of):
        if f.p_on_time is None:
            continue
        due = datetime.strptime(f.due, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if due > now:
            continue  # we don't know yet whether it made its deadline
        fixed_at = conn.execute("SELECT fixed_at FROM findings WHERE id = ?", (f.finding_id,)).fetchone()[0]
        made_it = fixed_at is not None and parse_iso(fixed_at) <= due
        results.append((f.p_on_time, 1.0 if made_it else 0.0))
    if len(results) < 20:
        return (f"Backtest as of {as_of:%Y-%m-%d}: only {len(results)} findings had a deadline that has passed since, "
                "too few to judge accuracy.")
    brier = sum((p - y) ** 2 for p, y in results) / len(results)
    rate = sum(y for _, y in results) / len(results)
    baseline = sum((rate - y) ** 2 for _, y in results) / len(results)
    lines = [f"Backtest: forecasts made as of {as_of:%Y-%m-%d} for {len(results)} findings whose deadline has passed.",
             f"Brier score {brier:.3f} (0 is perfect). Always guessing the overall on-time rate ({rate:.0%}) "
             f"scores {baseline:.3f}, so the forecast is "
             + ("better than that guess." if brier < baseline else "no better than that guess.")]
    for low, high in ((0, 0.25), (0.25, 0.5), (0.5, 0.75), (0.75, 1.01)):
        bucket = [(p, y) for p, y in results if low <= p < high]
        if bucket:
            lines.append(f"  forecast {low:.0%}-{min(high, 1):.0%} on time: {plural(len(bucket), 'finding')}, "
                         f"{sum(y for _, y in bucket) / len(bucket):.0%} actually were")
    return "\n".join(lines)


def km_median_by_severity(conn: sqlite3.Connection) -> dict[str, float | None]:
    history = _history(conn, parse_iso(utcnow()))
    out = {}
    for severity in ("critical", "high", "medium", "low"):
        rows = [h for h in history if h["severity"] == severity]
        out[severity] = Survival([h["days"] for h in rows], [h["fixed"] for h in rows]).median() if rows else None
    return out
