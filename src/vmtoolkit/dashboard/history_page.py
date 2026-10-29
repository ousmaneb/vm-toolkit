"""The History page: headline numbers day by day, and what the rankings and plan said on any past day."""

import sqlite3
from datetime import date
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from vmtoolkit.config import Settings
from vmtoolkit.dashboard import metrics, tools
from vmtoolkit.dashboard.tools_page import execute
from vmtoolkit.history import plan_on, ranking_on, snapshots

RANGES = {"30 days": 30, "90 days": 90, "1 year": 365, "All": None}
SERIES = {"open": "Open", "critical_high": "Critical or high", "overdue": "Past deadline",
          "known_exploited": "Actively exploited"}
# One hue per series; overdue and exploited are warm so the problem lines stand out from the totals.
COLORS = ["#3987e5", "#184f95", "#d95926", "#b42318"]


def render(settings: Settings, db_path: Path, offline: bool):
    st.title("History")
    st.markdown("Every day the daily run saves a snapshot of the headline numbers, and every Prioritize and Patch "
                "plan run is kept by date. Nothing is overwritten, so you can see how things changed and look back "
                "at any day.")
    try:
        with metrics.connect_readonly(db_path) as conn:
            rows = snapshots(conn)
    except (FileNotFoundError, sqlite3.OperationalError):
        rows = []

    if not rows or all(r["reconstructed"] == 0 for r in rows) and len(rows) < 7:
        with st.container(border=True):
            st.markdown("**Fill in the past**")
            st.caption("Rebuilds the daily counts for the last year from the scan dates already in the database. "
                       "Days that already have a snapshot are left alone. Rebuilt days have counts only: status, "
                       "on-time rate and risk weren't recorded at the time.")
            if st.button("Rebuild the past year", icon=":material/history:"):
                _, code, _ = execute(tools.base_command(settings, db_path, offline)
                                     + ["history", "save", "--backfill", "365"], settings.base_dir)
                if code == 0:
                    st.rerun()
                st.error("Couldn't rebuild the history. Run `vmt history save --backfill 365` to see why.")
        if not rows:
            return

    df = pd.DataFrame([dict(r) for r in rows])
    df["day"] = pd.to_datetime(df["day"])
    span = st.segmented_control("Show", list(RANGES), default="90 days", required=True)
    if RANGES[span]:
        df = df[df["day"] >= df["day"].max() - pd.Timedelta(days=RANGES[span])]

    long = df.melt(id_vars="day", value_vars=list(SERIES), var_name="measure", value_name="count")
    long["measure"] = long["measure"].map(SERIES)
    chart = alt.Chart(long).mark_line(strokeWidth=2).encode(
        x=alt.X("day:T", title=None),
        y=alt.Y("count:Q", title="Findings"),
        color=alt.Color("measure:N", scale=alt.Scale(domain=list(SERIES.values()), range=COLORS),
                        legend=alt.Legend(title=None, orient="top")),
        tooltip=[alt.Tooltip("day:T", title="Day"), "measure", "count"],
    )
    st.altair_chart(chart, width="stretch")
    rebuilt = df[df.reconstructed == 1]
    if not rebuilt.empty:
        st.caption(f"Days up to {rebuilt.day.max():%Y-%m-%d} were rebuilt from scan dates; later days were recorded "
                   "by the daily run.")

    st.subheader("Look back at a day")
    days = sorted(df["day"].dt.date.unique())
    picked: date = st.date_input("Day", value=days[-1], min_value=days[0], max_value=days[-1])
    key = picked.strftime("%Y-%m-%d")
    with metrics.connect_readonly(db_path) as conn:
        snap = conn.execute("SELECT * FROM history_snapshots WHERE day = ?", (key,)).fetchone()
        ranking, fixes = ranking_on(conn, key), plan_on(conn, key)
    if snap:
        c1, c2, c3, c4 = st.columns(4)
        for col, field in zip((c1, c2, c3, c4), SERIES):
            col.metric(SERIES[field], snap[field], border=True)
        if snap["reconstructed"]:
            st.caption("Rebuilt from scan dates: no status was recorded for this day.")
        elif snap["status"]:
            st.markdown(f"Status that day: **{snap['status'].upper()}**. {snap['status_reason']}")
    else:
        st.info("No snapshot for this day.", icon=":material/info:")

    left, right = st.columns(2)
    with left:
        st.markdown("**Top risks that day**")
        if ranking:
            st.caption(f"From the ranking saved on {ranking[0]['day']}. 'Fixed on' shows if and when it was fixed later.")
            st.dataframe(pd.DataFrame([dict(r) for r in ranking]).drop(columns=["day"]), width="stretch",
                         hide_index=True)
        else:
            st.caption("No ranking saved on or before this day.")
    with right:
        st.markdown("**Patch plan that day**")
        if fixes:
            st.caption(f"From the plan saved on {fixes[0]['day']}.")
            plan_df = pd.DataFrame([dict(r) for r in fixes])[["rank", "action", "findings", "machines", "share"]]
            st.dataframe(plan_df, width="stretch", hide_index=True,
                         column_config={"share": st.column_config.NumberColumn("risk removed", format="percent")})
        else:
            st.caption("No plan saved on or before this day.")

    st.subheader("All days")
    table = df.sort_values("day", ascending=False).drop(columns=["taken_at"])
    table["day"] = table["day"].dt.strftime("%Y-%m-%d")
    st.dataframe(table, width="stretch", hide_index=True)
    st.download_button("Download history as CSV", table.to_csv(index=False).encode(), file_name="vmt-history.csv",
                       mime="text/csv", icon=":material/download:")
