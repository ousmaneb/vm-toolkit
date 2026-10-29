"""Colors shared by the dashboard and the PDF reports, so a severity or status looks the same everywhere.

Severity colors are only ever used for severity, step colors only for workflow stages.
"""

INK = "#0B1F3A"
SIGNAL = "#2F6FED"
SEVERITY = {"critical": "#D92D20", "high": "#F2741C", "medium": "#E8B10C", "low": "#12A594"}
STATUS = {"red": ("#D92D20", "Action needed"), "amber": ("#E8B10C", "Watch"), "green": ("#12A594", "On track")}
STEPS = {"data": "#2F6FED", "risk": "#E8590C", "fix": "#12A594", "intel": "#7A5AF8", "ai": "#C11574",
         "settings": "#64748B"}
WORSE, BETTER = "#D92D20", "#12A594"
