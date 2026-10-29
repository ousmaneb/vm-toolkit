"""The Root causes page: which teams, which software and which repeat problems keep the backlog where it is."""

import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

from vmtoolkit.config import Settings
from vmtoolkit.dashboard import metrics
from vmtoolkit.insights import analyse, headlines
from vmtoolkit.report import LOOKBACK_DAYS


def render(settings: Settings, db_path: Path):
    st.title("Root causes")
    st.markdown("Fixing findings one by one keeps the backlog steady; fixing what produces them shrinks it. This page "
                f"looks at open problems and fixes from the last {LOOKBACK_DAYS} days by team, by software, and at "
                "problems that came back after a scan showed them fixed.")
    try:
        with metrics.connect_readonly(db_path) as conn:
            result = analyse(conn, settings)
    except (FileNotFoundError, sqlite3.OperationalError):
        result = None
    if not result or not result["teams"]:
        st.info("No findings yet. Bring in scan results first.", icon=":material/info:")
        return

    for line in headlines(result):
        st.markdown(f"- {line}")

    st.subheader("By team")
    st.caption("Teams come from team = \"...\" under [assets] in config.toml. On time and days to fix count fixes "
               f"from the last {LOOKBACK_DAYS} days.")
    st.dataframe(pd.DataFrame(result["teams"]), width="stretch", hide_index=True, column_config={
        "share_of_overdue": st.column_config.ProgressColumn("share of overdue", min_value=0, max_value=1,
                                                            format="percent"),
        "on_time": st.column_config.NumberColumn("on time", format="percent"),
        "median_days_to_fix": st.column_config.NumberColumn("median days to fix", format="%.0f"),
        "fixed_90d": st.column_config.NumberColumn(f"fixed ({LOOKBACK_DAYS} days)"),
        "oldest_open_days": st.column_config.NumberColumn("oldest open (days)"),
        "came_back": st.column_config.NumberColumn("came back"),
    })

    st.subheader("By software")
    st.caption("The package the scanner names, or its fix when it names none. One update to the top rows closes "
               "the most problems.")
    st.dataframe(pd.DataFrame(result["software"]).head(25), width="stretch", hide_index=True, column_config={
        "software": st.column_config.TextColumn("software or fix", width="large"),
        "fixed_90d": st.column_config.NumberColumn(f"fixed ({LOOKBACK_DAYS} days)"),
        "came_back": st.column_config.NumberColumn("came back"),
    })

    st.subheader("Problems that came back")
    if result["came_back"]:
        st.caption("A scan stopped reporting these, and a later scan of the same machine reported them again. "
                   "Check that fixes go into images, templates and configuration management, not only running "
                   "machines.")
        st.dataframe(pd.DataFrame(result["came_back"]), width="stretch", hide_index=True)
    else:
        st.caption("None: nothing a scan showed as fixed has come back.")
