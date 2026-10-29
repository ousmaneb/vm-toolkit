"""Lays out the leadership reports as PDF.

Both start with a one-page summary and a plain-English page of advice; the CISO version then adds the detail.
"""

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from . import palette
from .report import GLOSSARY, LOOKBACK_DAYS, ReportData, period_name

INK = colors.HexColor("#1f2328")
MUTED = colors.HexColor("#59636e")
RULE = colors.HexColor("#d0d7de")
SHADE = colors.HexColor("#f6f8fa")
NAVY = colors.HexColor(palette.INK)
BLUE = colors.HexColor(palette.SIGNAL)
SEVERITY = {sev: colors.HexColor(c) for sev, c in palette.SEVERITY.items()}
# Status text and border use darker shades of the dashboard's status colors, so they stay readable on
# their light tint when printed.
STATUS = {
    "red": (colors.HexColor("#B42318"), colors.HexColor("#FEF3F2"), palette.STATUS["red"][1]),
    "amber": (colors.HexColor("#93370D"), colors.HexColor("#FFFAEB"), palette.STATUS["amber"][1]),
    "green": (colors.HexColor("#0E7C70"), colors.HexColor("#ECFDF3"), palette.STATUS["green"][1]),
}
GOOD, BAD = colors.HexColor(palette.BETTER), colors.HexColor(palette.WORSE)

WIDTH = letter[0] - 1.5 * inch

body = ParagraphStyle("body", fontName="Helvetica", fontSize=10, leading=14, textColor=INK)
small = ParagraphStyle("small", parent=body, fontSize=8.5, leading=11)
muted = ParagraphStyle("muted", parent=small, textColor=MUTED)
title = ParagraphStyle("title", parent=body, fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=NAVY)
subtitle = ParagraphStyle("subtitle", parent=body, textColor=MUTED, spaceAfter=10)
h2 = ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=NAVY,
                    spaceBefore=11, spaceAfter=5)
bullet = ParagraphStyle("bullet", parent=body, leftIndent=12, bulletIndent=0, spaceAfter=2)
kpi_value = ParagraphStyle("kpi_value", parent=body, fontName="Helvetica-Bold", fontSize=24, leading=28)
cell = ParagraphStyle("cell", parent=small)
cell_head = ParagraphStyle("cell_head", parent=small, fontName="Helvetica-Bold", textColor=MUTED)
cell_num = ParagraphStyle("cell_num", parent=small, alignment=TA_RIGHT)


def p(text: str, style=body) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def table(header: list[str], rows: list[list], widths: list[float], numeric: set[int] = frozenset()) -> Table:
    data = [[p(h, cell_head) for h in header]]
    data += [[c if isinstance(c, Paragraph) else p(c, cell_num if i in numeric else cell) for i, c in enumerate(row)]
             for row in rows]
    t = Table(data, colWidths=[w * WIDTH for w in widths], repeatRows=1, hAlign="LEFT")
    style = [("LINEBELOW", (0, 0), (-1, 0), 0.75, RULE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    style += [("BACKGROUND", (0, r), (-1, r), SHADE) for r in range(2, len(data), 2)]
    t.setStyle(TableStyle(style))
    return t


def empty(text: str) -> Paragraph:
    return p(text, muted)


def status_banner(d: ReportData) -> Table:
    ink, fill, word = STATUS[d.status]
    t = Table([[Paragraph(f"<b>Status: {d.status.upper()}</b> &nbsp; {escape(word)}",
                          ParagraphStyle("s", parent=body, textColor=ink)),
                p(d.status_reason, ParagraphStyle("r", parent=body, textColor=ink))]],
              colWidths=[2.3 * inch, WIDTH - 2.3 * inch])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), fill), ("BOX", (0, 0), (-1, -1), 0.75, ink),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 10),
                           ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    return t


def kpis(d: ReportData) -> Table:
    tiles = [("Open vulnerabilities", d.now.open, d.before.open),
             ("Critical or high", d.now.critical_high, d.before.critical_high),
             ("Past deadline", d.now.overdue, d.before.overdue),
             ("Actively exploited", d.now.known_exploited, d.before.known_exploited)]
    days = (d.period_end - d.period_start).days
    period = "last week" if days == 7 else f"{days} days ago"
    cells = []
    for label, value, before in tiles:
        change = value - before
        # Every tile counts problems, so going up is bad.
        color = MUTED if change == 0 else BAD if change > 0 else GOOD
        delta = f"no change vs {period}" if change == 0 else f"{change:+d} vs {period}"
        cells.append([p(label, muted), p(value, kpi_value),
                      Paragraph(escape(delta), ParagraphStyle("d", parent=small, textColor=color))])
    t = Table([cells], colWidths=[WIDTH / 4] * 4)
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.75, RULE), ("INNERGRID", (0, 0), (-1, -1), 0.75, RULE),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 10),
                           ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    return t


def severity_bar(d: ReportData) -> Drawing:
    """Open vulnerabilities split by severity, in the same colors as the dashboard's exposure bar."""
    counts = [(c["severity"], c["open"]) for c in d.compliance]
    total = sum(n for _, n in counts)
    drawing = Drawing(WIDTH, 30)
    drawing.hAlign = "CENTER"  # same as the tables above it
    x = 0.0
    for sev, n in counts:
        if total and n:
            width = WIDTH * n / total
            drawing.add(Rect(x, 16, width, 9, fillColor=SEVERITY[sev], strokeColor=None))
            x += width
    if not total:
        drawing.add(Rect(0, 16, WIDTH, 9, fillColor=RULE, strokeColor=None))
    x = 0.0
    for sev, n in counts:
        drawing.add(Rect(x, 2, 7, 7, fillColor=SEVERITY[sev], strokeColor=None))
        label = f"{sev.capitalize()} {n:,}"
        drawing.add(String(x + 11, 2, label, fontName="Helvetica", fontSize=8.5, fillColor=INK))
        x += 11 + len(label) * 5 + 22
    return drawing


def trend_chart(d: ReportData) -> Drawing:
    width, height = WIDTH, 1.45 * inch
    drawing = Drawing(width, height)
    chart = HorizontalLineChart()
    chart.x, chart.y, chart.width, chart.height = 34, 30, width - 44, height - 52
    chart.data = [[t[1] for t in d.trend], [t[2] for t in d.trend]]
    chart.categoryAxis.categoryNames = [t[0].strftime("%b %d") for t in d.trend]
    chart.categoryAxis.labels.fontName = chart.valueAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = chart.valueAxis.labels.fontSize = 7
    chart.categoryAxis.labels.fillColor = chart.valueAxis.labels.fillColor = MUTED
    chart.categoryAxis.strokeColor = chart.valueAxis.strokeColor = RULE
    chart.valueAxis.valueMin = 0
    chart.valueAxis.gridStrokeColor = RULE
    chart.valueAxis.visibleGrid = True
    chart.valueAxis.gridStrokeWidth = 0.4
    chart.lines[0].strokeColor, chart.lines[0].strokeWidth = BLUE, 2
    chart.lines[1].strokeColor, chart.lines[1].strokeWidth = SEVERITY["critical"], 2
    drawing.add(chart)
    legend = Legend()
    legend.x, legend.y = 34, height - 4
    legend.fontName, legend.fontSize, legend.fillColor = "Helvetica", 8, INK
    legend.columnMaximum, legend.deltax, legend.dxTextSpace = 1, 150, 4
    legend.alignment = "right"
    legend.colorNamePairs = [(BLUE, "All open"), (SEVERITY["critical"], "Critical or high")]
    drawing.add(legend)
    return drawing


def summary_page(d: ReportData, audience: str) -> list:
    story = [
        p(f"Security posture: {period_name(d.days)} summary" if audience == "ceo"
          else f"Vulnerability management: {period_name(d.days)} report",
          title),
        p(f"Period {d.period_start:%b %d} to {d.period_end:%b %d, %Y}. Prepared for the "
          f"{'CEO' if audience == 'ceo' else 'CISO'}.", subtitle),
        status_banner(d), Spacer(1, 10), kpis(d), Spacer(1, 8), severity_bar(d),
        p("Summary", h2), *[Paragraph(escape(s), bullet, bulletText="•") for s in d.summary],
        p("Open vulnerabilities, last 12 weeks", h2), trend_chart(d),
    ]
    actions = [[str(f["rank"]), f["action"], str(f["machines"]), pct(f["share"])] for f in d.top_fixes[:3]]
    story += [p("Highest-value fixes", h2),
              table(["#", "Fix", "Machines", "Risk removed"], actions, [0.05, 0.67, 0.12, 0.16], {2, 3})
              if actions else empty("No patch plan yet.")]
    if d.attention:
        story += [p("Needs attention", h2), *[Paragraph(escape(a), bullet, bulletText="•") for a in d.attention]]
    story.append(p("Page 2 explains what this means for the business and what we recommend, in plain terms.", muted))
    return story


def advice_page(d: ReportData) -> list:
    story = [PageBreak(), p("What this means for the business", h2),
             *[Paragraph(escape(s), bullet, bulletText="•") for s in d.impact],
             p("What we recommend", h2)]
    for n, (action, why) in enumerate(d.advice, 1):
        story.append(Paragraph(f"<b>{escape(action)}</b> {escape(why)}", bullet, bulletText=f"{n}."))
    story += [p("Questions to ask your team", h2),
              *[Paragraph(escape(q), bullet, bulletText="•") for q in d.questions],
              KeepTogether([p("Terms used in this report", h2),
                            *[Paragraph(f"<b>{escape(term)}:</b> {escape(meaning)}",
                                        ParagraphStyle("term", parent=small, spaceAfter=3))
                              for term, meaning in GLOSSARY]])]
    return story


def detail_pages(d: ReportData) -> list:
    story = [PageBreak(), p("Deadline compliance", h2),
             p(f"Fixes in the last {LOOKBACK_DAYS} days, and what is open now. Deadlines are set per severity in "
               "config.toml.", muted), Spacer(1, 4)]
    rows = [[c["severity"].capitalize(), f"{c['deadline']} days" if c["deadline"] else "none", c["fixed"],
             pct(c["on_time"]), "n/a" if c["avg_days"] is None else f"{c['avg_days']:.0f}", c["open"], c["overdue"]]
            for c in d.compliance]
    story.append(table(["Severity", "Deadline", "Fixed", "On time", "Avg days to fix", "Open", "Past deadline"],
                       rows, [0.16, 0.14, 0.1, 0.12, 0.18, 0.12, 0.18], {2, 3, 4, 5, 6}))

    story += [p(f"Actively exploited vulnerabilities ({len(d.kev_open)} open)", h2),
              p("On CISA's Known Exploited Vulnerabilities list: attackers are using these now.", muted), Spacer(1, 4)]
    rows = [[r["cve"], r["machine"], r["title"], r["days_open"], "yes" if r["overdue"] else "no",
             r["kev_added"].strftime("%Y-%m-%d")] for r in d.kev_open[:15]]
    story.append(table(["CVE", "Machine", "Finding", "Days open", "Past deadline", "Listed"], rows,
                       [0.17, 0.15, 0.34, 0.1, 0.12, 0.12], {3}) if rows else empty("None open."))
    if len(d.kev_open) > 15:
        story.append(p(f"And {len(d.kev_open) - 15} more.", muted))

    rows = [[f["rank"], f["action"], f["findings"], f["machines"], pct(f["share"]), pct(f["cumulative"])]
            for f in d.top_fixes]
    story += [KeepTogether([p("Patch plan", h2),
                            p("Fixes grouped by package or patch, in order of risk removed.", muted), Spacer(1, 4),
                            table(["#", "Fix", "Findings", "Machines", "Risk removed", "Cumulative"], rows,
                                  [0.05, 0.47, 0.11, 0.11, 0.13, 0.13], {2, 3, 4, 5})
                            if rows else empty("No patch plan yet.")])]

    rows = [[r["rank"], f"{r['score']:.1f}", r["machine"], r["severity"], r["title"] + ("  [KEV]" if r["kev"] else ""),
             r["cves"] or ""] for r in d.top_risks]
    story += [KeepTogether([p("Top 10 individual risks", h2),
                            p("Score = 100 x exploit likelihood x impact x machine importance x exposure.", muted),
                            Spacer(1, 4),
                            table(["#", "Score", "Machine", "Severity", "Finding", "CVE"], rows,
                                  [0.05, 0.08, 0.15, 0.1, 0.42, 0.2], {0, 1}) if rows else empty("Not ranked yet.")])]

    rows = [[m["finding"], m["machine"], m["title"], m["severity"], m["due"], pct(m["chance"])] for m in d.misses[:15]]
    story += [KeepTogether([p(f"Likely to miss their deadline in the next 30 days ({len(d.misses)})", h2),
                            p("Forecast from how long similar findings took to fix in the past.", muted), Spacer(1, 4),
                            table(["ID", "Machine", "Finding", "Severity", "Due", "Chance on time"], rows,
                                  [0.07, 0.16, 0.4, 0.1, 0.12, 0.15], {0, 5}) if rows else empty("None expected.")])]

    teams = d.causes.get("teams", [])
    rows = [[t["team"], t["machines"], t["open"], t["overdue"], pct(t["share_of_overdue"]), pct(t["on_time"]),
             "n/a" if t["median_days_to_fix"] is None else f"{t['median_days_to_fix']:.0f}", t["came_back"]]
            for t in teams]
    software = d.causes.get("software", [])[:8]
    srows = [[s["software"], s["machines"], s["open"], s["overdue"], s["fixed_90d"], s["came_back"]] for s in software]
    story += [KeepTogether([p("Where the problems come from", h2),
                            p(f"By team (set in [assets]), over open problems and fixes in the last {LOOKBACK_DAYS} "
                              "days. 'Came back' counts problems that returned after a scan showed them fixed.",
                              muted), Spacer(1, 4),
                            table(["Team", "Machines", "Open", "Overdue", "Share of overdue", "On time",
                                   "Median days to fix", "Came back"], rows,
                                  [0.2, 0.1, 0.09, 0.1, 0.14, 0.1, 0.15, 0.12], {1, 2, 3, 4, 5, 6, 7})
                            if rows else empty("No data yet.")]),
              Spacer(1, 6),
              KeepTogether([p("By software, most open problems first:", muted), Spacer(1, 4),
                            table(["Software or fix", "Machines", "Open", "Overdue", "Fixed (90 days)", "Came back"],
                                  srows, [0.46, 0.1, 0.09, 0.1, 0.13, 0.12], {1, 2, 3, 4, 5})
                            if srows else empty("No data yet.")])]

    rows = [[f"#{a['id']}", a["machine"], a["title"] + ("  [KEV]" if a["kev"] else ""), a["expires_at"][:10],
             a["approved_by"], a["reason"]] for a in d.accepted]
    story += [KeepTogether([p(f"Accepted risks ({len(d.accepted)})", h2),
                            p("Findings a named approver agreed to leave unfixed until a date. They don't count as "
                              "past deadline while accepted, and come back when the acceptance ends.", muted),
                            Spacer(1, 4),
                            table(["#", "Machine", "Finding", "Until", "Approved by", "Reason"], rows,
                                  [0.06, 0.14, 0.3, 0.11, 0.14, 0.25]) if rows else empty("None.")])]

    rows = [[name, count] for name, count in d.overdue_by_machine]
    story += [KeepTogether([p("Machines with the most past-deadline findings", h2),
                            table(["Machine", "Past deadline"], rows, [0.5, 0.2], {1})
                            if rows else empty("None.")])]

    story += [KeepTogether([p("Data freshness and method", h2),
                            table(["Item", "Date"], [[a, b] for a, b in d.freshness], [0.5, 0.3]), Spacer(1, 6),
                            p("Counts leave out info-level findings and findings marked as false positives. "
                              "A finding counts as fixed on the first later scan of the same machine that no longer "
                              "reports it. Risk shares come from the latest Prioritize and Patch plan runs.", muted)])]
    return story


def render(d: ReportData, audience: str, path: Path, source: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    prepared = d.generated_at.strftime("%Y-%m-%d %H:%M UTC")

    def decorate(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(0.75 * inch, letter[1] - 0.5 * inch, "Vulnerability management report")
        canvas.drawRightString(letter[0] - 0.75 * inch, letter[1] - 0.5 * inch,
                               f"Period ending {d.period_end:%b %d, %Y}")
        canvas.drawString(0.75 * inch, 0.5 * inch, f"Confidential. Prepared {prepared} from {source}.")
        canvas.drawRightString(letter[0] - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")
        if d.fake:
            canvas.setFont("Helvetica-Bold", 72)
            canvas.setFillColor(colors.Color(0.85, 0.2, 0.2, alpha=0.12))
            canvas.translate(letter[0] / 2, letter[1] / 2)
            canvas.rotate(35)
            canvas.drawCentredString(0, 0, "FAKE DATA")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(path), pagesize=letter, leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                            topMargin=0.8 * inch, bottomMargin=0.8 * inch,
                            title=f"Vulnerability report, {d.days} days ending {d.period_end:%Y-%m-%d}",
                            author="vmtoolkit", subject=f"{period_name(d.days).capitalize()} {audience.upper()} report")
    story = summary_page(d, audience) + advice_page(d)
    if audience == "ciso":
        story += detail_pages(d)
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return path
