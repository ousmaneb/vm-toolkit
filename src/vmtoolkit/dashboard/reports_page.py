"""The Reports page (weekly CEO and CISO PDFs) and the Automation page (the scheduled daily run)."""

import re
import sqlite3
from datetime import time as clock
from pathlib import Path

import streamlit as st

from vmtoolkit import schedule
from vmtoolkit.config import ConfigError, Settings, load_settings
from vmtoolkit.daily import log_tail, recent_runs
from vmtoolkit.dashboard import metrics, tools
from vmtoolkit.dashboard.tools_page import execute
from vmtoolkit.db import parse_iso
from vmtoolkit.report import report_path

STATUS_BADGE = {"ok": ("Succeeded", "green", ":material/check_circle:"),
                "failed": ("Failed", "red", ":material/error:"),
                "running": ("Running or stopped", "gray", ":material/hourglass_top:")}


PERIODS = {"Last 7 days": 7, "Last 30 days": 30, "Last 90 days": 90, "Custom": None}


def list_reports(settings: Settings) -> list[tuple[str, int, dict[str, Path]]]:
    """(date, period in days, {"ceo": path, "ciso": path}) for the selected database, newest first."""
    sample = report_path(settings, "ceo", parse_iso("2000-01-01T00:00:00Z"))
    suffix = sample.name[10:-len("-ceo.pdf")]
    pattern = re.compile(r"(\d{4}-\d{2}-\d{2})" + re.escape(suffix) + r"-(ceo|ciso)(?:-(\d+)d)?\.pdf$")
    found: dict[tuple[str, int], dict[str, Path]] = {}
    for path in sample.parent.glob("*.pdf"):
        m = pattern.match(path.name)
        if m:
            found.setdefault((m[1], int(m[3] or 7)), {})[m[2]] = path
    return [(date, days, files) for (date, days), files in sorted(found.items(), key=lambda kv: (kv[0][0], -kv[0][1]),
                                                                  reverse=True)]


def download_buttons(files: dict[str, Path], key: str):
    for who, label in (("ceo", "CEO summary"), ("ciso", "CISO report")):
        if who in files:
            st.download_button(label, files[who].read_bytes(), file_name=files[who].name, mime="application/pdf",
                               icon=":material/download:", key=f"{key}-{who}")


def render_reports(settings: Settings, db_path: Path, offline: bool):
    st.title("Reports")
    st.markdown("Create a report for leadership at any time, for any period, and download it straight away. The "
                "**CEO summary** is written for non-technical readers: status, headline numbers, what it means for "
                "the business, what we recommend, and questions to ask. The **CISO report** adds the detail behind "
                "it.")

    with st.container(border=True):
        st.markdown("**Create a report**")
        choice = st.segmented_control("Period", list(PERIODS), default="Last 7 days", required=True)
        days = PERIODS[choice] or st.number_input("Number of days", min_value=1, max_value=730, value=14)
        audience = st.radio("Which report", ["both", "ceo", "ciso"], horizontal=True,
                            format_func={"both": "Both", "ceo": "CEO summary", "ciso": "CISO report"}.get)
        if st.button("Create report", type="primary", icon=":material/picture_as_pdf:"):
            output, code, _ = execute(tools.base_command(settings, db_path, offline)
                                      + ["report", "--days", str(days), "--audience", audience], settings.base_dir)
            if code == 0:
                made = {line.split(" report: ")[0].lower(): Path(line.split(": ", 1)[1])
                        for line in output.splitlines() if line.startswith(("CEO report: ", "CISO report: "))}
                st.session_state.new_reports = made
            else:
                st.session_state.new_reports = None
                st.error(output.strip() or f"Failed with exit code {code}", icon=":material/error:")
        made = st.session_state.get("new_reports")
        if made:
            st.success("Ready. Download below; a copy is also saved in the reports folder.",
                       icon=":material/check_circle:")
            with st.container(horizontal=True):
                download_buttons(made, "new")

    weekday = str(settings.section("daily").get("report_weekday", "monday")).capitalize()
    st.caption(f"The automatic daily run also creates a weekly report every {weekday} (report_weekday under [daily] "
               f"in config.toml). Saved in {settings.data_dir / 'reports'}.")

    reports = list_reports(settings)
    if not reports:
        st.info("No saved reports for this database yet.", icon=":material/info:")
        return
    st.subheader("Saved reports")
    for date, days, files in reports:
        with st.container(border=True, horizontal=True, vertical_alignment="center"):
            label = "Week" if days == 7 else f"{days} days"
            st.markdown(f"**{label} ending {date}**", width="stretch")
            download_buttons(files, f"{date}-{days}")


def render_automation(settings: Settings, db_path: Path, offline: bool):
    st.title("Automation")
    st.markdown("`vmt daily` does the whole routine in one go: pull new results from Nessus, enrich CVEs, find "
                "duplicates, prioritize, update the patch plan and forecast, check GitHub and news, send alerts, "
                "and write the weekly reports when they're due. If the Nessus pull fails it stops there and sends "
                "you an alert, rather than reporting yesterday's data as today's.")

    main = load_settings(settings.base_dir / "config.toml") if (settings.base_dir / "config.toml").exists() else settings
    with st.container(border=True):
        st.markdown("**Schedule**")
        current = schedule.status()
        if current.startswith("Installed"):
            st.badge(current, icon=":material/schedule:", color="green")
        else:
            st.badge("Not scheduled", icon=":material/schedule:", color="gray")
        st.caption(f"The scheduled run always uses your main database ({main.db_path.name}), whatever is picked "
                   "in the sidebar. The computer must be on; on a Mac a missed run happens when it wakes.")
        when = st.time_input("Run every day at", value=clock(7, 0), step=900)
        agreed = st.checkbox("I understand this adds a daily job to this computer's scheduler")
        with st.container(horizontal=True):
            if st.button("Install schedule", type="primary", icon=":material/event_repeat:", disabled=not agreed):
                try:
                    st.success(schedule.install(main, f"{when:%H:%M}"), icon=":material/check_circle:")
                except ConfigError as e:
                    st.error(str(e), icon=":material/error:")
            if st.button("Remove schedule", icon=":material/event_busy:", disabled=not current.startswith("Installed")):
                st.info(schedule.remove(), icon=":material/info:")

    with st.container(border=True):
        st.markdown("**Run it now**")
        st.caption(f"Runs every step on {db_path.name} and takes a few minutes. Keep this page open.")
        if st.button("Run the daily routine now", icon=":material/play_arrow:"):
            output, code, seconds = execute(tools.base_command(settings, db_path, offline) + ["daily"],
                                            settings.base_dir)
            (st.success if code == 0 else st.error)(f"{'Finished' if code == 0 else 'Finished with problems'} "
                                                    f"in {seconds:.0f} s.")
            st.code(output, language=None)

    st.subheader("Recent runs")
    try:
        with metrics.connect_readonly(db_path) as conn:
            runs = recent_runs(conn)
    except (FileNotFoundError, sqlite3.OperationalError):
        runs = []
    if not runs:
        st.caption("No runs recorded for this database yet.")
        return
    for run in runs:
        label, color, icon = STATUS_BADGE.get(run["status"], STATUS_BADGE["running"])
        with st.container(border=True):
            with st.container(horizontal=True, vertical_alignment="center"):
                st.markdown(f"**{parse_iso(run['started_at']).astimezone():%a %b %d, %H:%M}**", width="stretch")
                st.badge(label, icon=icon, color=color)
            if run["failed_steps"]:
                st.markdown(f"Failed: {run['failed_steps']}")
            if run["reports"]:
                st.caption("Reports: " + ", ".join(Path(p).name for p in run["reports"].split(", ")))
            with st.expander("Log"):
                st.code(log_tail(run["log_path"]) or "Log file not found.", language=None)
