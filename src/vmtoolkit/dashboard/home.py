"""The home page: headline numbers, the next step to take, and the workflow with a link to every tool."""

from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from vmtoolkit.config import Settings
from vmtoolkit.dashboard import metrics
from vmtoolkit.dashboard.tools_page import GROUPS, TOOLS

STEPS = [
    ("data", "Get your scan results into the toolkit."),
    ("risk", "Add threat data and rank what matters most."),
    ("fix", "Turn the ranking into fixes, tickets and alerts."),
    ("intel", "Predict exploitation and watch for new activity."),
    ("ai", "Ask the LLM to explain a CVE or answer questions."),
]


def next_step(progress: dict[str, int] | None, demo: bool = True) -> tuple[str, str, str]:
    """(headline, why, page key) for the most useful thing to do next."""
    if not progress or not progress["findings"]:
        return ("Bring in your first scan results",
                "The database has no findings yet. Pull from Nessus or import a scan file"
                + (", or generate demo data to explore safely." if demo else "."),
                "import")
    if progress["unenriched"]:
        return ("Enrich your CVEs",
                f"{progress['unenriched']} CVEs have no threat data yet, so rankings can't tell which are exploited.",
                "enrich")
    if not progress["prioritized"]:
        return "Rank your findings", "Findings and threat data are in. Prioritize to see what to fix first.", "prioritize"
    if not progress["planned"]:
        return "Make a patch plan", "Group the ranked findings into the fewest fixes that remove the most risk.", "plan"
    return ("Review the dashboard",
            "Everything is up to date. Re-run Import and Enrich after each new scan to keep it that way.",
            "dashboard")


def render(settings: Settings, db_path: Path, pages: dict):
    st.title("Vulnerability management")
    st.caption(f"Using {db_path.name}")

    progress, summary = None, None
    if db_path.exists():
        with metrics.connect_readonly(db_path) as conn:
            progress = metrics.progress(conn)
            df = metrics.load_findings(conn)
        sla = {k: int(v) for k, v in settings.section("sla_days").items()}
        open_df = df[df.status == "open"]
        summary = {
            "Open findings": len(open_df),
            "Critical or high": int(open_df.severity.isin(["critical", "high"]).sum()),
            "Overdue": len(metrics.overdue(df, sla, datetime.now(timezone.utc))),
            "Known exploited": progress["known_exploited"],
        }

    if summary:
        helps = {
            "Open findings": "Problems the latest scans still report, excluding info-level and false positives.",
            "Critical or high": "Open findings rated critical or high by the scanner.",
            "Overdue": "Open longer than the fix deadline for their severity ([sla_days] in config.toml).",
            "Known exploited": "Open findings whose CVE is on CISA's Known Exploited Vulnerabilities list.",
        }
        icons = {"Open findings": ":material/bug_report:", "Critical or high": ":material/priority_high:",
                 "Overdue": ":material/alarm:", "Known exploited": ":material/local_fire_department:"}
        for col, (label, value) in zip(st.columns(4), summary.items()):
            col.metric(label, value, help=helps[label], border=True, icon=icons[label])

    headline, why, key = next_step(progress, demo="demo-data" in pages)
    with st.container(border=True):
        st.markdown(f"#### :material/flag: Next step: {headline}")
        st.markdown(why)
        with st.container(horizontal=True):
            st.page_link(pages[key], label=f"Open {pages[key].title}", icon=":material/arrow_forward:")
            if key == "import" and "demo-data" in pages:
                st.page_link(pages["demo-data"], label="Generate demo data", icon=":material/science:")
            else:
                st.page_link(pages["reports"], label="Create a leadership report", icon=":material/picture_as_pdf:")

    st.subheader("How it fits together")
    st.caption("Work left to right. Every step has its own page in the menu.")
    columns = st.columns(3) + st.columns(3)
    for col, (number, (group, text)) in zip(columns, enumerate(STEPS, 1)):
        with col.container(border=True, height="stretch"):
            st.markdown(f"**{number}. {GROUPS[group]}**")
            st.caption(text)
            for tool in (t for t in TOOLS if t.group == group and t.key in pages):
                st.page_link(pages[tool.key], label=tool.title, icon=tool.icon)
    with columns[len(STEPS)].container(border=True, height="stretch"):
        st.markdown(f"**{GROUPS['settings']}**")
        st.caption("API keys, the automatic daily run, weekly reports, and demo data to practise on.")
        st.page_link(pages["setup"], label="Setup status", icon=":material/key:")
        st.page_link(pages["automation"], label="Automation", icon=":material/event_repeat:")
        st.page_link(pages["reports"], label="Reports", icon=":material/summarize:")
        if "demo-data" in pages:
            st.page_link(pages["demo-data"], label="Demo data", icon=":material/science:")
