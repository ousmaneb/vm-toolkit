"""Dashboard numbers, computed with pandas so they can be tested without Streamlit."""

import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
AGE_BUCKETS = [(0, 30, "0-30 days"), (31, 90, "31-90 days"), (91, 180, "91-180 days"), (181, None, "over 180 days")]


def connect_readonly(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise FileNotFoundError(f"No database at {path}. Import scans first, or run `vmt fake-data`.")
    # as_uri() gives a correct file: URI on Windows too (file:///C:/...).
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def load_findings(conn: sqlite3.Connection) -> pd.DataFrame:
    df = pd.read_sql_query(
        """SELECT f.id, a.name AS machine, f.scanner, f.title, f.severity, f.status, f.first_seen,
                  f.last_seen, f.fixed_at, f.is_fake,
                  (SELECT group_concat(cve, ', ') FROM finding_cves c WHERE c.finding_id = f.id) AS cves
           FROM findings f JOIN assets a ON a.id = f.asset_id
           WHERE f.severity != 'info' AND f.id NOT IN (SELECT finding_id FROM fp_labels WHERE label = 'false_positive')""",
        conn,
    )
    for col in ("first_seen", "last_seen", "fixed_at"):
        df[col] = pd.to_datetime(df[col], utc=True)
    df["severity"] = pd.Categorical(df["severity"], categories=SEVERITY_ORDER, ordered=True)
    return df


def has_fake(conn: sqlite3.Connection) -> bool:
    return bool(conn.execute("SELECT EXISTS (SELECT 1 FROM findings WHERE is_fake = 1)").fetchone()[0])


def open_by_severity(df: pd.DataFrame) -> pd.DataFrame:
    counts = df[df.status == "open"].groupby("severity", observed=False).size()
    return counts.reindex(SEVERITY_ORDER, fill_value=0).rename("open").reset_index()


def age_days(df: pd.DataFrame, now: datetime) -> pd.Series:
    return (pd.Timestamp(now) - df["first_seen"]).dt.days


def age_buckets(df: pd.DataFrame, now: datetime) -> pd.DataFrame:
    open_ = df[df.status == "open"].copy()
    ages = age_days(open_, now)
    open_["age"] = "over 180 days"
    for low, high, label in AGE_BUCKETS:
        mask = (ages >= low) & (ages <= high) if high is not None else ages >= low
        open_.loc[mask, "age"] = label
    counts = open_.groupby(["severity", "age"], observed=False).size().rename("open").reset_index()
    counts["age"] = pd.Categorical(counts["age"], categories=[b[2] for b in AGE_BUCKETS], ordered=True)
    return counts.sort_values(["age", "severity"]).reset_index(drop=True)


def overdue(df: pd.DataFrame, sla_days: dict[str, int], now: datetime) -> pd.DataFrame:
    open_ = df[df.status == "open"].copy()
    open_["age_days"] = age_days(open_, now)
    open_["deadline_days"] = open_["severity"].astype(str).map(sla_days)
    late = open_[open_["age_days"] > open_["deadline_days"]].copy()
    late["days_overdue"] = late["age_days"] - late["deadline_days"]
    late["why"] = late.apply(
        lambda r: f"{r.severity} findings must be fixed within {r.deadline_days} days; "
                  f"this one has been open {r.age_days} days", axis=1)
    cols = ["machine", "severity", "title", "cves", "first_seen", "age_days", "deadline_days", "days_overdue", "why"]
    return late.sort_values(["severity", "days_overdue"], ascending=[True, False])[cols].reset_index(drop=True)


def time_to_fix(df: pd.DataFrame) -> pd.DataFrame:
    fixed = df[df.status == "fixed"].copy()
    fixed["days"] = (fixed["fixed_at"] - fixed["first_seen"]).dt.total_seconds() / 86400
    out = fixed.groupby("severity", observed=False)["days"].agg(["count", "mean", "median"])
    out = out.reindex(SEVERITY_ORDER).reset_index()
    out.columns = ["severity", "fixed", "mean_days", "median_days"]
    out["fixed"] = out["fixed"].fillna(0).astype(int)
    return out.round(1)


def time_to_fix_survival(conn: sqlite3.Connection) -> dict[str, float | None]:
    from ..forecast import km_median_by_severity

    return km_median_by_severity(conn)


def at_risk(conn: sqlite3.Connection, settings) -> pd.DataFrame:
    from ..forecast import forecast

    rows = [{"finding": f.finding_id, "machine": f.machine, "severity": f.severity, "title": f.title,
             "due": f.due, "chance_on_time": f.p_on_time, "why": f.reason}
            for f in forecast(conn, settings) if f.at_risk]
    return pd.DataFrame(rows, columns=["finding", "machine", "severity", "title", "due", "chance_on_time", "why"])


def trend(df: pd.DataFrame, now: datetime, freq: str = "W") -> pd.DataFrame:
    """Open count at the end of each period, plus how many were found and fixed during it."""
    if df.empty:
        return pd.DataFrame(columns=["period_end", "open", "new", "fixed"])
    ends = pd.date_range(df["first_seen"].min().normalize(), pd.Timestamp(now), freq=freq, tz="UTC")
    rows, previous = [], None
    for end in ends:
        open_now = ((df.first_seen <= end) & (df.fixed_at.isna() | (df.fixed_at > end))).sum()
        found = (df.first_seen <= end) & (df.first_seen > previous) if previous is not None else df.first_seen <= end
        fixed = (df.fixed_at <= end) & (df.fixed_at > previous) if previous is not None else df.fixed_at <= end
        rows.append({"period_end": end, "open": int(open_now), "new": int(found.sum()), "fixed": int(fixed.sum())})
        previous = end
    return pd.DataFrame(rows)


def load_priorities(conn: sqlite3.Connection) -> pd.DataFrame:
    """The latest `vmt prioritize` ranking, limited to findings that are still open."""
    return pd.read_sql_query(
        """SELECT p.rank, p.score, a.name AS machine, f.severity, f.title, p.explanation
           FROM priorities p JOIN findings f ON f.id = p.finding_id JOIN assets a ON a.id = f.asset_id
           WHERE f.status = 'open' ORDER BY p.rank""",
        conn,
    )


def progress(conn: sqlite3.Connection) -> dict[str, int]:
    """How far through the workflow this database is, for the home page's next-step hint."""
    def one(sql):
        return conn.execute(sql).fetchone()[0]

    return {
        "findings": one("SELECT count(*) FROM findings"),
        "machines": one("SELECT count(*) FROM assets"),
        "unenriched": one("""SELECT count(DISTINCT c.cve) FROM finding_cves c
                             WHERE NOT EXISTS (SELECT 1 FROM epss_history e WHERE e.cve = c.cve)
                               AND NOT EXISTS (SELECT 1 FROM cves n WHERE n.cve = c.cve)"""),
        "prioritized": one("SELECT count(*) FROM priorities"),
        "planned": one("SELECT count(*) FROM plan_fixes"),
        "known_exploited": one("""SELECT count(DISTINCT f.id) FROM findings f
                                  JOIN finding_cves c ON c.finding_id = f.id JOIN kev k ON k.cve = c.cve
                                  WHERE f.status = 'open' AND f.severity != 'info' AND f.id NOT IN
                                        (SELECT finding_id FROM fp_labels WHERE label = 'false_positive')"""),
    }
