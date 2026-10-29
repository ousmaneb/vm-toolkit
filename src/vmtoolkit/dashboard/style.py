"""The dashboard's look: fonts, colors and the home page's hero.

Colors are fixed meanings: the severity colors are only ever used for severity, the step colors only
for workflow stages. Tints are rgba so the same CSS reads in light and dark mode. Every value that
comes from the database is escaped before it goes into HTML.
"""

import mimetypes
from html import escape

import streamlit as st

# Slim Linux images have no .woff2 entry, so the fonts would be served as octet-stream.
mimetypes.add_type("font/woff2", ".woff2")

INK = "#0B1F3A"
SIGNAL = "#2F6FED"
SEVERITY = {"critical": "#D92D20", "high": "#F2741C", "medium": "#E8B10C", "low": "#12A594"}
STATUS = {"red": ("#D92D20", "Action needed"), "amber": ("#E8B10C", "Watch"), "green": ("#12A594", "On track")}
STEPS = {"data": "#2F6FED", "risk": "#E8590C", "fix": "#12A594", "intel": "#7A5AF8", "ai": "#C11574",
         "settings": "#64748B"}

FONTS = "app/static/fonts"
CSS = f"""
@font-face {{ font-family: "IBM Plex Sans"; font-weight: 400; font-display: swap;
  src: url("{FONTS}/ibm-plex-sans-latin-400-normal.woff2") format("woff2"); }}
@font-face {{ font-family: "IBM Plex Sans"; font-weight: 500; font-display: swap;
  src: url("{FONTS}/ibm-plex-sans-latin-500-normal.woff2") format("woff2"); }}
@font-face {{ font-family: "IBM Plex Sans"; font-weight: 600; font-display: swap;
  src: url("{FONTS}/ibm-plex-sans-latin-600-normal.woff2") format("woff2"); }}
@font-face {{ font-family: "IBM Plex Sans"; font-weight: 700; font-display: swap;
  src: url("{FONTS}/ibm-plex-sans-latin-700-normal.woff2") format("woff2"); }}
@font-face {{ font-family: "IBM Plex Mono"; font-weight: 500; font-display: swap;
  src: url("{FONTS}/ibm-plex-mono-latin-500-normal.woff2") format("woff2"); }}

h1, h2, h3, h4 {{ letter-spacing: -0.015em; }}
h1 {{ font-weight: 700 !important; }}
[data-testid="stMetricValue"], .vmt-num {{ font-family: "IBM Plex Mono", ui-monospace, monospace; }}
[data-testid="stMetric"] {{ border-top: 3px solid {SIGNAL}; }}
[data-testid="stSidebarNav"] a span {{ font-weight: 500; }}
a:focus-visible, button:focus-visible {{ outline: 2px solid {SIGNAL}; outline-offset: 2px; }}

.vmt-hero {{ background: linear-gradient(135deg, {INK} 0%, #13315C 60%, #1B4486 100%); color: #F2F6FC;
  border-radius: 14px; padding: 28px 32px 24px; margin-bottom: 8px; }}
.vmt-hero__top {{ display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; }}
.vmt-eyebrow {{ font-size: 0.78rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase;
  color: #9FB4D6; }}
.vmt-status {{ display: inline-flex; align-items: center; gap: 8px; padding: 5px 12px; border-radius: 999px;
  background: rgba(255,255,255,0.10); font-size: 0.85rem; font-weight: 600; }}
.vmt-status i {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
.vmt-hero h1 {{ color: #FFFFFF; font-size: clamp(1.6rem, 2.8vw, 2.25rem); line-height: 1.15; margin: 14px 0 6px;
  padding: 0; }}
.vmt-hero p {{ color: #C9D6EA; margin: 0 0 20px; max-width: 70ch; }}
.vmt-bar {{ display: flex; height: 14px; border-radius: 7px; overflow: hidden; background: rgba(255,255,255,0.12); }}
.vmt-bar span {{ display: block; min-width: 3px; }}
.vmt-legend {{ display: flex; flex-wrap: wrap; gap: 6px 22px; margin-top: 12px; font-size: 0.9rem; color: #DCE6F5; }}
.vmt-legend b {{ font-family: "IBM Plex Mono", ui-monospace, monospace; color: #FFFFFF; margin-left: 6px; }}
.vmt-legend i {{ width: 10px; height: 10px; border-radius: 3px; display: inline-block; margin-right: 6px; }}

.vmt-kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px;
  margin: 14px 0 6px; }}
.vmt-kpi {{ border: 1px solid rgba(127,127,127,0.22); border-top: 4px solid var(--tone); border-radius: 12px;
  padding: 14px 16px 12px; background: rgba(127,127,127,0.04); }}
.vmt-kpi__label {{ font-size: 0.86rem; font-weight: 500; opacity: 0.85; }}
.vmt-kpi__label::before {{ content: ""; display: inline-block; width: 8px; height: 8px; border-radius: 2px;
  background: var(--tone); margin-right: 7px; vertical-align: 1px; }}
.vmt-kpi__value {{ font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 2rem; font-weight: 500;
  line-height: 1.2; margin: 4px 0 2px; }}
.vmt-kpi__delta {{ font-size: 0.82rem; opacity: 0.85; }}
.vmt-up {{ color: #D92D20; }} .vmt-down {{ color: #12A594; }}

[class*="st-key-step-"] {{ border-top: 4px solid var(--step) !important; border-radius: 12px !important; }}
""" + "".join(f".st-key-step-{key} {{ --step: {color}; }}\n" for key, color in STEPS.items()) + """
.st-key-next-step { background: rgba(47,111,237,0.07); border-left: 4px solid #2F6FED !important;
  border-radius: 12px !important; }
"""


def apply():
    st.html(f"<style>{CSS}</style>")


def hero(eyebrow: str, headline: str, sentence: str, status: str | None, reason: str,
         severities: dict[str, int]) -> str:
    total = sum(severities.values())
    bar = "".join(f'<span style="width:{count / total * 100:.2f}%;background:{SEVERITY[sev]}" '
                  f'title="{count} {sev}"></span>' for sev, count in severities.items() if count) if total else ""
    legend = "".join(f'<span><i style="background:{SEVERITY[sev]}"></i>{sev.capitalize()}<b>{count}</b></span>'
                     for sev, count in severities.items())
    pill = ""
    if status:
        color, word = STATUS[status]
        pill = (f'<span class="vmt-status" title="{escape(reason)}"><i style="background:{color}"></i>'
                f'Status: {status.upper()} &middot; {word}</span>')
    return (f'<section class="vmt-hero" aria-label="Exposure summary">'
            f'<div class="vmt-hero__top"><span class="vmt-eyebrow">{escape(eyebrow)}</span>{pill}</div>'
            f'<h1>{escape(headline)}</h1><p>{escape(sentence)}</p>'
            f'<div class="vmt-bar" role="img" aria-label="Open vulnerabilities by severity">{bar}</div>'
            f'<div class="vmt-legend">{legend}</div></section>')


def kpis(cards: list[tuple[str, int, int | None, str, str]]) -> str:
    """(label, value, change since last week or None, color, explanation) per card."""
    out = []
    for label, value, change, tone, help_text in cards:
        if change is None:
            delta = "&nbsp;"
        elif change == 0:
            delta = "No change vs last week"
        else:
            # Every card counts problems, so up is bad.
            delta = (f'<span class="{"vmt-up" if change > 0 else "vmt-down"}">'
                     f'{"&#9650;" if change > 0 else "&#9660;"} {abs(change)}</span> vs last week')
        out.append(f'<div class="vmt-kpi" style="--tone:{tone}" title="{escape(help_text)}">'
                   f'<div class="vmt-kpi__label">{escape(label)}</div>'
                   f'<div class="vmt-kpi__value">{value:,}</div><div class="vmt-kpi__delta">{delta}</div></div>')
    return f'<div class="vmt-kpis">{"".join(out)}</div>'
