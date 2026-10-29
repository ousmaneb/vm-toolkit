"""Streamlit app: a home page, the charts dashboard, and one page per tool.

Started by `vmt dashboard`, which passes --config and --db after `--`.
"""

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import altair as alt
import streamlit as st

from vmtoolkit.config import load_settings, production
from vmtoolkit.dashboard import (assets_page, auth, history_page, home, metrics, nav, reports_page, style, tools,
                                 tools_page)

SERIES = {"light": {"new": "#2a78d6", "fixed": "#eb6834", "surface": "#fcfcfb"},
          "dark": {"new": "#3987e5", "fixed": "#d95926", "surface": "#1a1a19"}}
DB_LABELS = {"vmt.db": "Live data", "fake.db": "Demo data"}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path)
    parser.add_argument("--db", type=Path)
    # parse_known_args: Streamlit and its test runner may leave their own arguments in argv.
    return parser.parse_known_args(sys.argv[1:])[0]


def theme() -> dict:
    try:
        return SERIES["dark" if st.context.theme.type == "dark" else "light"]
    except AttributeError:
        return SERIES["light"]


def severity_scale():
    # Severity has one set of colors across the whole app (dashboard/style.py); every bar also has a label.
    return alt.Scale(domain=metrics.SEVERITY_ORDER, range=[style.SEVERITY[s] for s in metrics.SEVERITY_ORDER])


def overview(settings):
    colors = theme()
    now = datetime.now(timezone.utc)
    st.title("Dashboard")

    try:
        conn = metrics.connect_readonly(settings.db_path)
    except FileNotFoundError as e:
        st.info(str(e), icon=":material/info:")
        return
    with conn:
        df = metrics.load_findings(conn)
        priorities = metrics.load_priorities(conn)
        km = metrics.time_to_fix_survival(conn)
        risky = metrics.at_risk(conn, settings)

    st.caption(f"{settings.db_path.name}, read-only. Info-level findings and false positives are left out.")
    if df.empty:
        st.info("No findings yet. Import scan results first.", icon=":material/info:")
        return

    left, right = st.columns(2)
    machines = left.multiselect("Machines", sorted(df.machine.unique()), placeholder="All machines")
    scanners = right.multiselect("Scanners", sorted(df.scanner.unique()), placeholder="All scanners")
    if machines:
        df = df[df.machine.isin(machines)]
        priorities = priorities[priorities.machine.isin(machines)]
        risky = risky[risky.machine.isin(machines)]
    if scanners:
        df = df[df.scanner.isin(scanners)]

    sla = {k: int(v) for k, v in settings.section("sla_days").items()}
    late = metrics.overdue(df, sla, now)
    fix = metrics.time_to_fix(df)
    open_df = df[df.status == "open"]
    fixed_count = int(fix.fixed.sum())
    overall_mttr = (fix.mean_days * fix.fixed).sum() / fixed_count if fixed_count else None

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Open findings", len(open_df), border=True)
    c2.metric("Critical + high open", int(open_df.severity.isin(["critical", "high"]).sum()), border=True)
    c3.metric("Overdue", len(late), border=True)
    c4.metric("Average days to fix", f"{overall_mttr:.0f}" if overall_mttr is not None else "n/a", border=True)

    tab_now, tab_priorities, tab_late, tab_speed, tab_trend = st.tabs(
        ["Open findings", "Top priorities", f"Overdue ({len(late)})", "Time to fix", "Trend"])

    with tab_now:
        left, right = st.columns(2)
        with left:
            st.markdown("**Open by severity**")
            by_sev = metrics.open_by_severity(df)
            bars = alt.Chart(by_sev).mark_bar(cornerRadiusEnd=4).encode(
                x=alt.X("severity:N", sort=metrics.SEVERITY_ORDER, title=None, axis=alt.Axis(labelAngle=0)),
                y=alt.Y("open:Q", title="Open findings"),
                color=alt.Color("severity:N", scale=severity_scale(), legend=None),
                tooltip=["severity", "open"],
            )
            labels = bars.mark_text(dy=-8).encode(text="open:Q", color=alt.value("currentColor"))
            st.altair_chart(bars + labels, width="stretch")
            st.caption("Count of findings whose latest scan still reports them.")
        with right:
            st.markdown("**How long open findings have been open**")
            ages = metrics.age_buckets(df, now)
            # Stack critical at the bottom, so the most urgent part of each bar sits on the baseline.
            ages["stack"] = ages["severity"].cat.codes
            stacked = alt.Chart(ages).mark_bar(stroke=colors["surface"], strokeWidth=2).encode(
                x=alt.X("age:N", sort=[b[2] for b in metrics.AGE_BUCKETS], title=None, axis=alt.Axis(labelAngle=0)),
                y=alt.Y("open:Q", title="Open findings"),
                color=alt.Color("severity:N", scale=severity_scale(), sort=metrics.SEVERITY_ORDER,
                                legend=alt.Legend(title="Severity", orient="top")),
                order=alt.Order("stack:Q", sort="ascending"),
                tooltip=["age", "severity", "open"],
            )
            st.altair_chart(stacked, width="stretch")
            st.caption("Age is counted from the first scan that found the problem, not from the CVE's publish date.")

    with tab_priorities:
        if priorities.empty:
            st.info("No ranking yet. Run Prioritize to rank open findings.", icon=":material/info:")
        else:
            st.caption("From the last Prioritize run: score = 100 x exploit likelihood x impact x machine "
                       "importance x exposure. The explanation column says where each number came from.")
            st.dataframe(priorities.head(15), width="stretch", hide_index=True,
                         column_config={"score": st.column_config.ProgressColumn(
                             "score", min_value=0, max_value=100, format="%.1f")})

    with tab_late:
        st.caption("Deadlines per severity come from [sla_days] in config.toml: "
                   + ", ".join(f"{k} {v} days" for k, v in sla.items()) + ".")
        st.dataframe(late, width="stretch", hide_index=True)
        st.markdown(f"**Likely to miss their deadline ({len(risky)})**")
        st.caption("From the last Deadline forecast run: open findings with under a 50% chance of being fixed "
                   "by their deadline, judged from how long similar findings took in the past.")
        st.dataframe(risky, width="stretch", hide_index=True)

    with tab_speed:
        fix["median_days_incl_open"] = fix["severity"].astype(str).map(km).round(1)
        st.caption("mean_days and median_days only count fixed findings, so they understate how long fixes take: "
                   "the slowest ones are still open. median_days_incl_open is a Kaplan-Meier estimate that also "
                   "counts still-open findings; it is blank when fewer than half have been fixed so far.")
        st.dataframe(fix, width="stretch", hide_index=True)

    with tab_trend:
        weekly = metrics.trend(df, now)
        st.markdown("**Open findings at the end of each week**")
        line = alt.Chart(weekly).mark_line(strokeWidth=2, color=colors["new"]).encode(
            x=alt.X("period_end:T", title="Week ending"), y=alt.Y("open:Q", title="Open findings"))
        points = line.mark_point(size=64, filled=True, opacity=0).encode(
            tooltip=[alt.Tooltip("period_end:T", title="Week ending"), "open"])
        st.altair_chart(line + points, width="stretch")

        # The first week counts everything the first scan found as "new", which would dwarf the rest.
        flows = weekly.iloc[1:].melt(id_vars="period_end", value_vars=["new", "fixed"], var_name="change",
                                     value_name="findings")
        st.markdown("**Found vs. fixed per week**")
        flow_chart = alt.Chart(flows).mark_line(strokeWidth=2).encode(
            x=alt.X("period_end:T", title="Week ending"),
            y=alt.Y("findings:Q", title="Findings per week"),
            color=alt.Color("change:N", scale=alt.Scale(domain=["new", "fixed"], range=[colors["new"], colors["fixed"]]),
                            legend=alt.Legend(title=None, orient="top")),
            tooltip=[alt.Tooltip("period_end:T", title="Week ending"), "change", "findings"],
        )
        st.altair_chart(flow_chart, width="stretch")
        st.caption("New = first seen that week. Fixed = first missing from a scan that week. "
                   "If new stays above fixed, the backlog is growing. The first week is left out because "
                   "everything the first scan found counts as new.")
        with st.expander("Weekly numbers as a table"):
            st.dataframe(weekly, width="stretch", hide_index=True)


def db_label(path: Path, data_dir: Path) -> str:
    if path.parent != data_dir.resolve():
        return str(path)
    return f"{DB_LABELS[path.name]} ({path.name})" if path.name in DB_LABELS else path.name


def main():
    args = parse_args()
    settings = load_settings(args.config, db=args.db)
    st.set_page_config(page_title="Vulnerability management", page_icon=":material/shield:", layout="wide")
    style.apply()
    user = auth.require_login(settings)
    live = production()

    def page(fn, title, icon, key, **kwargs):
        # Each page needs its own function name, so wrap the shared renderers in a named closure.
        def run():
            fn()
        run.__name__ = key.replace("-", "_")
        return st.Page(run, title=title, icon=icon, url_path=key, **kwargs)

    pages: dict[str, st.Page] = {}
    state = {}
    pages["home"] = page(lambda: home.render(state["settings"], state["db"], pages), "Home", ":material/home:",
                         "home", default=True)
    pages["dashboard"] = page(lambda: overview(state["settings"]), "Dashboard", ":material/monitoring:", "dashboard")
    # Demo data has no place in production.
    shown_tools = [t for t in tools_page.TOOLS if not (live and t.key == "demo-data")]
    for tool in shown_tools:
        pages[tool.key] = page(lambda tool=tool: tools_page.render_tool(tool, state["settings"], state["db"],
                                                                       state["offline"]),
                               tool.title, tool.icon, tool.key)
    pages["setup"] = page(lambda: tools_page.render_setup(state["settings"]), "Setup status", ":material/key:", "setup")
    pages["assets"] = page(lambda: assets_page.render(state["settings"], state["db"]),
                           "Assets", ":material/dns:", "assets")
    pages["history"] = page(lambda: history_page.render(state["settings"], state["db"], state["offline"]),
                            "History", ":material/history:", "history")
    pages["reports"] = page(lambda: reports_page.render_reports(state["settings"], state["db"], state["offline"]),
                            "Reports", ":material/summarize:", "reports")
    pages["automation"] = page(lambda: reports_page.render_automation(state["settings"], state["db"], state["offline"]),
                               "Automation", ":material/event_repeat:", "automation")

    nav_page = st.navigation(list(pages.values()), position="hidden")
    current = next(key for key, p in pages.items() if p.title == nav_page.title)
    # The selectbox below sets this; on the first run it is still the startup database.
    chosen = Path(st.session_state.get("db-choice", settings.db_path)).resolve()
    nav.sidebar(pages, current, "Live data" if live else db_label(chosen, settings.data_dir))

    with st.sidebar:
        st.html('<div class="vmt-nav-label">Data source</div>')
        if live:
            db_path = settings.data_dir / "vmt.db"
        else:
            choices = tools.database_choices(settings, settings.db_path)
            db_path = st.selectbox("Database", choices, format_func=lambda p: db_label(p, settings.data_dir),
                                   key="db-choice", label_visibility="collapsed",
                                   help="Every page uses this database. 'Live data' is your real data.")
        offline = st.toggle("Offline mode", help="Tools use only cached web data and make no network calls.")
    if user:
        auth.sign_out_button(user, settings)
    state.update(settings=load_settings(args.config, db=db_path), db=db_path, offline=offline)

    if db_path.exists():
        with metrics.connect_readonly(db_path) as conn:
            if metrics.has_fake(conn):
                st.warning("FAKE DATA: this database contains generated demo data, not results from your environment.",
                           icon=":material/science:")
    nav_page.run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    main()
