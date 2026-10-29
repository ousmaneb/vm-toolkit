"""The home page: headline numbers, the next step to take, and the workflow with a link to every tool."""

from pathlib import Path

import streamlit as st

from vmtoolkit.config import Settings
from vmtoolkit.dashboard import metrics, style
from vmtoolkit.dashboard.tools_page import GROUPS, TOOLS
from vmtoolkit.report import build

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


def summary(settings: Settings, db_path: Path):
    """(progress, report data), or (None, None) before the database exists. The numbers are the same ones the
    CEO report uses, so the dashboard and the PDFs never disagree."""
    if not db_path.exists():
        return None, None
    with metrics.connect_readonly(db_path) as conn:
        return metrics.progress(conn), build(conn, settings)


def render(settings: Settings, db_path: Path, pages: dict):
    progress, d = summary(settings, db_path)
    if d is None or not progress["findings"]:
        st.html(style.hero("No data yet", "No vulnerabilities on record yet.",
                           "Bring in scan results to see how exposed you are.", None, "",
                           dict.fromkeys(style.SEVERITY, 0)))
    else:
        severities = {c["severity"]: c["open"] for c in d.compliance}
        exploited = d.now.known_exploited
        headline = f"{d.now.open:,} open vulnerabilities." + (
            f" {exploited} {'is' if exploited == 1 else 'are'} known to be exploited by attackers." if exploited else "")
        scanned = f"last scan {d.last_scan:%b %d, %Y}" if d.last_scan else "no scans recorded"
        source = "Demo data" if d.fake else "Live data"
        st.html(style.hero(f"{source} · {scanned}", headline, d.status_reason, d.status, d.status_reason,
                           severities))
        st.html(style.kpis([
            ("Open vulnerabilities", d.now.open, d.now.open - d.before.open, style.SIGNAL,
             "Problems the latest scans still report, excluding info-level findings and false positives."),
            ("Critical or high", d.now.critical_high, d.now.critical_high - d.before.critical_high,
             style.SEVERITY["critical"], "Open findings rated critical or high by the scanner."),
            ("Past deadline", d.now.overdue, d.now.overdue - d.before.overdue, "#B54708",
             "Open longer than the fix deadline for their severity ([sla_days] in config.toml)."),
            ("Known exploited", exploited, exploited - d.before.known_exploited, "#9E1C55",
             "Open findings whose CVE is on CISA's Known Exploited Vulnerabilities list."),
        ]))

    headline, why, key = next_step(progress, demo="demo-data" in pages)
    with st.container(border=True, key="next-step"):
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
        with col.container(border=True, height="stretch", key=f"step-{group}"):
            st.markdown(f"**{number}. {GROUPS[group]}**")
            st.caption(text)
            for tool in (t for t in TOOLS if t.group == group and t.key in pages):
                st.page_link(pages[tool.key], label=tool.title, icon=tool.icon)
    with columns[len(STEPS)].container(border=True, height="stretch", key="step-settings"):
        st.markdown(f"**{GROUPS['settings']}**")
        st.caption("API keys, the automatic daily run, weekly reports, and demo data to practise on.")
        st.page_link(pages["setup"], label="Setup status", icon=":material/key:")
        st.page_link(pages["automation"], label="Automation", icon=":material/event_repeat:")
        st.page_link(pages["reports"], label="Reports", icon=":material/summarize:")
        if "demo-data" in pages:
            st.page_link(pages["demo-data"], label="Demo data", icon=":material/science:")
