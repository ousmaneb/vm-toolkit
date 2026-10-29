"""The sidebar: overview pages always visible, the workflow groups folded, and a search box over every tool."""

from html import escape

import streamlit as st

from vmtoolkit.dashboard import style
from vmtoolkit.dashboard.tools_page import GROUPS, TOOLS

OVERVIEW = ["home", "dashboard", "history", "reports"]
GROUP_ICONS = {"data": ":material/download:", "risk": ":material/shield:", "fix": ":material/build:",
               "intel": ":material/insights:", "ai": ":material/auto_awesome:", "settings": ":material/settings:"}
SUMMARIES = {t.key: t.summary for t in TOOLS}


def groups(pages: dict) -> dict[str, list[str]]:
    """Group -> page keys, in workflow order. Settings also holds the setup and automation pages."""
    out = {group: [t.key for t in TOOLS if t.group == group and t.key in pages] for group in GROUPS}
    out["data"] = ["assets"] + out["data"]
    out["settings"] = ["setup", "automation"] + out["settings"]
    return out


def matches(query: str, pages: dict) -> list[str]:
    words = query.lower().split()
    found = []
    for key, page in pages.items():
        text = f"{page.title} {SUMMARIES.get(key, '')}".lower()
        if all(w in text for w in words):
            found.append(key)
    return found


def sidebar(pages: dict, current: str, source: str):
    with st.sidebar:
        st.html(f"<style>{NAV_CSS}</style>")
        st.html(f'<div class="vmt-brand"><span class="vmt-brand__mark">VM</span>'
                f'<span><b>Vulnerability management</b><small>{escape(source)}</small></span></div>')
        query = st.text_input("Find a tool", placeholder="Find a tool, e.g. tickets", key="nav-search",
                              label_visibility="collapsed", icon=":material/search:")
        if query.strip():
            found = matches(query, pages)
            for key in found:
                st.page_link(pages[key], label=pages[key].title, icon=pages[key].icon)
            if not found:
                st.caption("No tool matches. Try a word like scan, ticket or report.")
            return

        for key in OVERVIEW:
            st.page_link(pages[key], label=pages[key].title, icon=pages[key].icon)
        st.html('<div class="vmt-nav-label">Workflow</div>')
        for group, keys in groups(pages).items():
            if not keys:
                continue
            with st.expander(f"{GROUPS[group]}", expanded=current in keys, icon=GROUP_ICONS[group],
                             key=f"nav-{group}"):
                for key in keys:
                    st.page_link(pages[key], label=pages[key].title, icon=pages[key].icon)


NAV_CSS = """
[data-testid="stSidebarHeader"] { display: none; }
.vmt-brand { display: flex; align-items: center; gap: 10px; padding: 4px 2px 10px; }
.vmt-brand__mark { display: inline-flex; align-items: center; justify-content: center; width: 34px; height: 34px;
  border-radius: 9px; background: linear-gradient(135deg, #2F6FED, #12A594); color: #fff; font-weight: 700;
  font-size: 0.85rem; letter-spacing: 0.04em; flex: none; }
.vmt-brand b { display: block; font-size: 0.95rem; line-height: 1.2; }
.vmt-brand small { display: block; font-size: 0.75rem; opacity: 0.7; }
.vmt-nav-label { font-size: 0.72rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase;
  opacity: 0.6; margin: 10px 2px 2px; }
[class*="st-key-nav-"] details { border: none !important; border-left: 3px solid var(--step) !important;
  border-radius: 0 8px 8px 0 !important; background: rgba(255,255,255,0.04); }
[class*="st-key-nav-"] summary { font-weight: 600; }
""" + "".join(f".st-key-nav-{group} {{ --step: {color}; }}\n" for group, color in style.STEPS.items())
