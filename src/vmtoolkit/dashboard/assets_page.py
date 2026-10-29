"""The Assets page: every machine, who owns it, how important and exposed it is, and when it was last scanned."""

import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

from vmtoolkit.config import Settings
from vmtoolkit.dashboard import metrics
from vmtoolkit.inventory import machines, stale_days


def render(settings: Settings, db_path: Path):
    st.title("Assets")
    st.markdown("Every machine the scanners have reported, with the settings that drive its ranking. Importance, "
                "internet exposure, owner and team come from `[assets]` in `config.toml`; a machine that isn't "
                "listed counts as medium importance and not internet-facing.")
    try:
        with metrics.connect_readonly(db_path) as conn:
            rows = machines(conn, settings)
    except (FileNotFoundError, sqlite3.OperationalError):
        rows = []
    if not rows:
        st.info("No machines yet. Bring in scan results first.", icon=":material/info:")
        return

    limit = stale_days(settings)
    stale = sum(m["stale"] for m in rows)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Machines", len(rows), border=True)
    c2.metric("Without an owner", sum(not m["owner"] for m in rows), border=True,
              help="Set owner and team under [assets] in config.toml so tickets and reports name them.")
    c3.metric("Internet-facing", sum(m["internet_facing"] for m in rows), border=True)
    c4.metric(f"Not scanned in {limit}+ days", stale, border=True,
              help="Scans used to reach these machines but no longer do, so their findings may be out of date.")
    if stale:
        st.warning(f"{stale} machine{'s' if stale != 1 else ''} stopped being scanned. Check that they are still in "
                   "a scan policy and reachable, or remove them if they were retired.", icon=":material/visibility_off:")

    show = st.segmented_control("Show", ["All", "Not scanned recently", "No owner", "Internet-facing"],
                                default="All", required=True)
    df = pd.DataFrame(rows)
    if show == "Not scanned recently":
        df = df[df.stale]
    elif show == "No owner":
        df = df[df.owner.isna()]
    elif show == "Internet-facing":
        df = df[df.internet_facing]
    df = df.sort_values(["overdue", "open"], ascending=False)
    st.dataframe(
        df[["machine", "importance", "internet_facing", "owner", "team", "open", "critical_high", "overdue",
            "last_scanned", "days_since_scan"]],
        width="stretch", hide_index=True,
        column_config={
            "internet_facing": st.column_config.CheckboxColumn("internet"),
            "critical_high": st.column_config.NumberColumn("critical or high"),
            "last_scanned": st.column_config.DatetimeColumn("last scanned", format="YYYY-MM-DD"),
            "days_since_scan": st.column_config.NumberColumn("days since scan"),
        })
    st.caption("To set a machine's importance, exposure, owner and team, add it to config.toml:")
    st.code('[assets."web-01.example.com"]\ncriticality = "high"        # low | medium | high | critical\n'
            'internet_facing = true\nowner = "alice@example.com"\nteam = "Web"', language="toml")
