"""One page per tool: a short explanation, its options, and the output of the matching `vmt` command."""

import logging
import shlex
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import streamlit as st

from vmtoolkit.config import Settings
from vmtoolkit.dashboard import tools

LLM_COST = ("I understand this sends the CVE data, scanner findings and my notes to the AI provider "
           "(machine names and IPs are replaced with placeholders) and costs money")

Request = tuple[list[str], str | None] | None


@dataclass
class Tool:
    key: str
    title: str
    icon: str
    group: str
    summary: str
    form: Callable[[Settings, Path], Request]
    needs: list[str] = field(default_factory=list)  # rows of tools.SECRETS; any one being ready is enough
    tags: list[str] = field(default_factory=list)  # internet, cost, writes, slow


def opt(flag: str, value) -> list[str]:
    if value is None or value == "" or value is False:
        return []
    return [flag] if value is True else [flag, str(value)]


def uploads(label: str, types: list[str] | None, folder: Path, multiple: bool = True) -> list[str]:
    files = st.file_uploader(label, type=types, accept_multiple_files=multiple)
    if not multiple:
        files = [files] if files else []
    return [str(tools.save_upload(folder, f.name, f.getvalue())) for f in files]


def nessus(settings, folder):
    st.caption(f"Nessus server from config.toml: {settings.section('nessus')['url']}")
    action = st.radio("What to do", ["check", "scans", "pull", "reimport"],
                      format_func={"check": "Test the connection", "scans": "List scans",
                                   "pull": "Download new results", "reimport": "Rebuild from saved backups"}.get)
    scans = tools.split_ids(st.text_input("Only these scan IDs (optional)", placeholder="12, 15")) \
        if action == "pull" else []
    return ["nessus", action, *[a for s in scans for a in ("--scan", s)]], None


def import_files(settings, folder):
    files = uploads("Scan result files", ["nessus", "xml", "json"], folder)
    st.caption("Nessus (.nessus), OpenVAS / Greenbone XML report, or Trivy JSON. The format is detected for you.")
    host = st.text_input("Machine name (Trivy files only)", placeholder="docker-01.lab")
    if not files:
        return None
    return ["import", *files, *opt("--host", host)], None


def enrich(settings, folder):
    cves = tools.split_ids(st.text_input("Only these CVEs (optional)", placeholder="Leave empty for every CVE"))
    nvd = st.toggle("Include NVD details (slow without an NVD_API_KEY)", value=True)
    exploits = st.toggle("Check Exploit-DB and Metasploit for public exploits", value=True)
    return ["enrich", *[a for c in cves for a in ("--cve", c)], "--nvd" if nvd else "--no-nvd",
            "--exploits" if exploits else "--no-exploits"], None


def cve_lookup(settings, folder):
    cve = st.text_input("CVE ID", placeholder="CVE-2021-44228").strip()
    return (["cve", cve], None) if cve else None


def deps(settings, folder):
    files = uploads("Dependency files", ["txt", "json"], folder)
    st.caption("requirements.txt, package.json or package-lock.json.")
    save = st.toggle("Also add the results to the database as findings")
    host = st.text_input("Machine this project runs on") if save else ""
    if not files:
        return None
    return ["deps", *files, *opt("--save", save), *opt("--host", host)], None


def alert(settings, folder):
    channels = settings.section("alerts").get("channels", ["console"])
    st.caption(f"Alert channels from config.toml: {', '.join(channels)}. "
               "Console alerts are also written to data/alerts.log.")
    dry_run = st.toggle("Preview only: show what would be sent, send nothing", value=True)
    refresh = st.toggle("Download fresh KEV and EPSS data first", value=True)
    outside = [c for c in channels if c != "console"]
    warning = f"I understand this sends real alerts to {', '.join(outside)}" if outside and not dry_run else None
    return ["alert", *opt("--dry-run", dry_run), "--refresh" if refresh else "--no-refresh"], warning


def prioritize(settings, folder):
    c1, c2 = st.columns(2)
    top = c1.number_input("How many to show", min_value=1, value=20)
    machine = c2.text_input("Only this machine (optional)")
    explain = st.number_input("Explain why one finding ranks where it does (finding ID, optional)",
                              min_value=1, value=None)
    return ["prioritize", "--top", str(top), *opt("--machine", machine), *opt("--explain", explain)], None


def plan(settings, folder):
    target = st.slider("Cover this much of the total risk", min_value=10, max_value=100, value=80, step=5,
                       format="%d%%")
    c1, c2 = st.columns(2)
    max_fixes = c1.number_input("At most this many fixes (optional)", min_value=1, value=None)
    explain = c2.number_input("Explain fix number (optional)", min_value=1, value=None)
    return ["plan", "--target", str(target), *opt("--max-fixes", max_fixes), *opt("--explain", explain)], None


def dedupe(settings, folder):
    st.caption("No options. Run it after importing results from more than one scanner.")
    return ["dedupe"], None


def tickets(settings, folder):
    max_fixes = st.number_input("Only the top N fixes from the patch plan (optional)", min_value=1, value=None)
    push = st.radio("Where to put them", ["files", "jira", "servicenow"], horizontal=True,
                    format_func={"files": "Files only (data/vmt-tickets)", "jira": "Also send to Jira",
                                 "servicenow": "Also send to ServiceNow"}.get)
    push = None if push == "files" else push
    warning = f"I understand this creates real tickets in {push}" if push else None
    return ["tickets", *opt("--max-fixes", max_fixes), *opt("--push", push)], warning


def exploit_model(settings, folder):
    action = st.radio("What to do", ["evaluate", "train", "score"],
                      format_func={"evaluate": "Test it: compare with EPSS on the past year",
                                   "train": "Train it on all CVEs",
                                   "score": "Score the CVEs in this database"}.get)
    if action == "evaluate":
        c1, c2 = st.columns(2)
        cutoff = c1.number_input("Pretend it is this many days ago", min_value=30, value=365)
        window = c2.number_input("Only CVEs published this many days before that (0 = all)", min_value=0, value=0)
        return ["exploit-model", "evaluate", "--cutoff-days", str(cutoff), "--window-days", str(window)], None
    if action == "train":
        mode = st.radio("Data to learn from", ["strict", "full"], horizontal=True,
                        format_func={"strict": "Strict: issuer data only (recommended)",
                                     "full": "Full: adds NVD's later analysis"}.get)
        return ["exploit-model", "train", "--mode", mode], None
    st.caption("Train the model first.")
    return ["exploit-model", "score"], None


def accept_risk(settings, folder):
    from datetime import date, timedelta

    from vmtoolkit.acceptance import max_days

    action = st.radio("What to do", ["list", "add", "revoke"],
                      format_func={"list": "Show accepted risks", "add": "Accept a risk",
                                   "revoke": "End an acceptance"}.get)
    if action == "list":
        show_all = st.toggle("Include ended acceptances")
        return ["accept", "list", *opt("--all", show_all)], None
    if action == "revoke":
        number = st.number_input("Acceptance number (the # in the list)", min_value=1, value=None)
        return (["accept", "revoke", str(number)], None) if number else None
    ids = tools.split_ids(st.text_input("Finding IDs", placeholder="412, 413 (shown on the Prioritize page)"))
    reason = st.text_area("Why it is acceptable", placeholder="Only reachable from the management VLAN; vendor "
                                                              "patch due in the next release")
    approver = st.text_input("Approved by", placeholder="Name or role, e.g. CISO")
    until = st.date_input("Accepted until", value=date.today() + timedelta(days=90),
                          min_value=date.today() + timedelta(days=1),
                          max_value=date.today() + timedelta(days=max_days(settings)))
    if not (ids and reason.strip() and approver.strip()):
        return None
    return (["accept", "add", *ids, "--reason", reason.strip(), "--approver", approver.strip(),
             "--until", until.isoformat()],
            f"I confirm {approver.strip()} approved leaving these findings unfixed until {until:%B %d, %Y}")


def fp(settings, folder):
    action = st.radio("What to do", ["list", "predict", "mark", "unmark"],
                      format_func={"list": "Show my marks", "predict": "Find likely false positives",
                                   "mark": "Mark findings", "unmark": "Remove marks"}.get)
    if action == "predict":
        top = st.number_input("How many to show", min_value=1, value=20)
        return ["fp", "predict", "--top", str(top)], None
    if action == "list":
        return ["fp", "list"], None
    ids = tools.split_ids(st.text_input("Finding IDs", placeholder="412, 413 (shown on the Prioritize page)"))
    if action == "unmark":
        return (["fp", "unmark", *ids], None) if ids else None
    real = st.radio("Mark them as", ["false positive", "real issue"], horizontal=True) == "real issue"
    reason = st.text_input("Reason (optional)", placeholder="banner check; Debian backports the fix")
    return (["fp", "mark", *ids, *opt("--real", real), *opt("--reason", reason)], None) if ids else None


def forecast(settings, folder):
    show_all = st.toggle("Show every open finding, not only the ones at risk")
    backtest = st.number_input("Check how forecasts made this many days ago turned out", min_value=1, value=90)
    return ["forecast", *opt("--all", show_all), "--backtest-days", str(backtest)], None


def classify(settings, folder):
    action = st.radio("What to do", ["evaluate", "train", "predict"],
                      format_func={"evaluate": "Test it on the past year", "train": "Train and save it",
                                   "predict": "Predict for CVEs NVD hasn't analysed yet"}.get)
    if action == "evaluate":
        cutoff = st.number_input("Test on CVEs newer than this many days", min_value=30, value=365)
        return ["classify", "evaluate", "--cutoff-days", str(cutoff)], None
    return ["classify", action], None


def extract(settings, folder):
    kind = st.radio("Advisory source", ["URL", "File"], horizontal=True,
                    format_func={"URL": "Web page", "File": "Upload a file"}.get)
    if kind == "URL":
        source = st.text_input("Advisory URL", placeholder="https://httpd.apache.org/security/vulnerabilities_24.html")
    else:
        files = uploads("Advisory file (HTML, text, Markdown or PDF)", ["html", "htm", "txt", "md", "pdf"], folder,
                        multiple=False)
        source = files[0] if files else ""
    use_llm = st.toggle("Use the LLM instead of the offline rules (better on messy pages)")
    warning = "I understand this sends the advisory text to the AI provider and costs a few cents" if use_llm else None
    return (["extract", source.strip(), *opt("--llm", use_llm)], warning) if source.strip() else None


def monitor(settings, folder):
    st.caption("No options. Without a GITHUB_TOKEN it checks about 10 CVEs a minute. "
               "Afterwards, open Alerts to send any spikes it found.")
    return ["monitor"], None


def triage(settings, folder):
    target = st.text_input("CVE ID or finding number", placeholder="CVE-2021-44228").strip()
    preview = st.toggle("Preview only: show exactly what would be sent (free, sends nothing)", value=True)
    refresh = st.toggle("Ask again even if a saved answer exists")
    if not target:
        return None
    return ["triage", target, *opt("--show-prompt", preview), *opt("--refresh", refresh)], None if preview else LLM_COST


def notes(settings, folder):
    action = st.radio("What to do", ["list", "add"], horizontal=True,
                      format_func={"list": "Show notes", "add": "Add a note"}.get)
    target = st.text_input("CVE ID or finding number" + (" (optional)" if action == "list" else ""),
                           placeholder="CVE-2024-3400").strip()
    if action == "list":
        return ["notes", "list", *([target] if target else [])], None
    text = st.text_area("Note", placeholder="GlobalProtect is disabled on our firewall")
    return (["notes", "add", target, text], None) if target and text.strip() else None


def ask(settings, folder):
    question = st.text_area("Your question", placeholder="Which machines have known-exploited vulnerabilities "
                                                         "older than 30 days?").strip()
    run_eval = st.toggle("Instead, run the 20-question accuracy test (20 API calls)")
    if run_eval:
        return ["ask", "--eval"], "I understand this makes 20 calls to the AI provider and costs money"
    warning = ("I understand this sends my question and the database's table layout (not its contents) "
               "to the AI provider and costs a little money")
    return (["ask", question], warning) if question else None


def fake_data(settings, folder):
    st.caption("Clearly labelled FAKE scan history for trying things out. It is always written to "
               "data/fake.db, never to your real database.")
    c1, c2, c3 = st.columns(3)
    machines = c1.number_input("Machines", min_value=1, value=40)
    days = c2.number_input("Days of history", min_value=7, value=365)
    seed = c3.number_input("Seed", min_value=0, value=7, help="The same seed always gives the same data.")
    force = st.toggle("Replace the existing demo database")
    return ["fake-data", "--machines", str(machines), "--days", str(days), "--seed", str(seed),
            *opt("--force", force)], None


GROUPS = {
    "data": "Bring in data",
    "risk": "Understand the risk",
    "fix": "Fix and report",
    "intel": "Threat intelligence",
    "ai": "AI assistant",
    "settings": "Settings",
}
NESSUS = ["Nessus connector (API keys)", "Nessus connector (username and password)"]
LLM = ["LLM features: extract --llm, triage, ask"]

TOOLS = [
    Tool("nessus", "Nessus scanner", ":material/radar:", "data",
         "Download finished scans from your Nessus server and add them to the database.",
         nessus, needs=NESSUS, tags=["internet", "writes"]),
    Tool("import", "Import scan files", ":material/upload_file:", "data",
         "Add results you exported from Nessus, OpenVAS / Greenbone or Trivy.", import_files, tags=["writes"]),
    Tool("deps", "Check dependencies", ":material/inventory_2:", "data",
         "Check a project's Python or JavaScript dependency list for packages with known vulnerabilities.",
         deps, tags=["internet"]),
    Tool("enrich", "Enrich CVEs", ":material/travel_explore:", "risk",
         "Add exploit likelihood (EPSS), CISA's known-exploited list, NVD details and public exploits to every "
         "CVE. Run it after each import.", enrich, tags=["internet", "writes"]),
    Tool("cve", "Look up a CVE", ":material/search:", "risk",
         "Everything stored about one CVE, in plain words.", cve_lookup),
    Tool("prioritize", "Prioritize", ":material/sort:", "risk",
         "Rank open findings by how likely they are to be exploited, how bad they are, and how important the "
         "machine is. Every rank comes with its reasons.", prioritize, tags=["writes"]),
    Tool("dedupe", "Find duplicates", ":material/join:", "risk",
         "Spot findings that two scanners reported for the same problem on the same machine.",
         dedupe, tags=["writes"]),
    Tool("fp", "False positives", ":material/rule:", "risk",
         "Mark findings that aren't real, and find others that look like them.", fp, tags=["writes"]),
    Tool("forecast", "Deadline forecast", ":material/event_upcoming:", "risk",
         "Predict which open findings will miss their fix deadline, based on how long similar ones took.", forecast),
    Tool("plan", "Patch plan", ":material/checklist:", "fix",
         "Group open findings into fixes, and show the fewest fixes that remove the most risk.",
         plan, tags=["writes"]),
    Tool("tickets", "Tickets", ":material/confirmation_number:", "fix",
         "Write one remediation ticket per fix in the patch plan, and optionally send them to Jira or ServiceNow.",
         tickets, tags=["writes"]),
    Tool("accept", "Risk acceptance", ":material/verified_user:", "fix",
         "Record a risk you've agreed to leave unfixed for now: why, who approved it, and until when. Accepted "
         "findings stay visible but don't count as overdue, and come back when the acceptance ends.",
         accept_risk, tags=["writes"]),
    Tool("alerts", "Alerts", ":material/notifications:", "fix",
         "Alert when a CVE you have becomes known-exploited, its EPSS score jumps, or chatter about it spikes.",
         alert, tags=["internet", "writes"]),
    Tool("exploit-model", "Exploit prediction", ":material/model_training:", "intel",
         "A model that predicts which CVEs will end up on CISA's known-exploited list. The first run downloads "
         "about 300 MB from NVD and takes several minutes.", exploit_model, tags=["internet", "slow"]),
    Tool("classify", "Weakness classifier", ":material/category:", "intel",
         "Predicts the weakness type and attack vector for CVEs that NVD hasn't analysed yet.",
         classify, tags=["internet", "slow"]),
    Tool("extract", "Read an advisory", ":material/article:", "intel",
         "Pull CVEs, affected and fixed versions, and exploitation status out of a vendor advisory or article.",
         extract, tags=["internet", "writes"]),
    Tool("monitor", "GitHub and news", ":material/podcasts:", "intel",
         "Watch GitHub and security news for new mentions of your open CVEs, and flag sudden spikes.",
         monitor, tags=["internet", "writes", "slow"]),
    Tool("triage", "Triage a CVE", ":material/psychology:", "ai",
         "Get a plain-English assessment of one CVE for your environment: what it is, whether it matters, how to fix it "
         "and how to check the fix.", triage, needs=LLM, tags=["cost"]),
    Tool("notes", "Notes", ":material/sticky_note_2:", "ai",
         "Your own notes about CVEs and findings. Triage reads them.", notes, tags=["writes"]),
    Tool("ask", "Ask a question", ":material/forum:", "ai",
         "Ask about your data in plain English. The LLM writes a read-only database query and explains the answer.",
         ask, needs=LLM, tags=["cost"]),
    Tool("demo-data", "Demo data", ":material/science:", "settings",
         "Generate a year of fake scan history for 40 made-up machines, to try every tool safely.", fake_data),
]

TAG_BADGES = {
    "internet": ("Uses the internet", ":material/language:", "gray"),
    "writes": ("Updates the database", ":material/database:", "blue"),
    "slow": ("Takes minutes", ":material/hourglass_top:", "violet"),
    "cost": ("Can cost money", ":material/payments:", "red"),
}


def ready(tool: Tool) -> tuple[bool, list[str]]:
    if not tool.needs:
        return True, []
    status = dict(tools.secret_status())
    rows = [status[purpose] for purpose in tool.needs]
    if any(all(keys.values()) for keys in rows):
        return True, []
    return False, [name for name, ok in rows[0].items() if not ok]


def execute(cmd: list[str], cwd: Path) -> tuple[str, int, float]:
    started = time.monotonic()
    lines, last = [], 0.0
    holder = st.empty()
    with holder.status("Running...", expanded=True):
        box = st.empty()

        def on_line(line):
            nonlocal last
            lines.append(line)
            # Redrawing on every line makes chatty commands crawl; a few times a second is enough to follow along.
            if time.monotonic() - last > 0.3:
                box.code("".join(lines[-40:]), language=None)
                last = time.monotonic()

        st.caption("Keep this page open until it finishes.")
        code = tools.run(cmd, cwd, on_line, user=st.session_state.get("user"))
    # The Results section below takes over once the command ends.
    holder.empty()
    return "".join(lines), code, time.monotonic() - started


def render_tool(tool: Tool, settings: Settings, db_path: Path, offline: bool):
    st.title(tool.title)
    st.markdown(tool.summary)
    ok, missing = ready(tool)
    with st.container(horizontal=True, gap="small"):
        if ok:
            st.badge("Ready", icon=":material/check_circle:", color="green")
        else:
            st.badge("Needs " + " and ".join(missing) + " in .env", icon=":material/key:", color="orange")
        for tag in tool.tags:
            label, icon, color = TAG_BADGES[tag]
            st.badge(label, icon=icon, color=color)
        if offline:
            st.badge("Offline mode", icon=":material/cloud_off:", color="gray")

    if "upload_dir" not in st.session_state:
        st.session_state.upload_dir = Path(tempfile.mkdtemp(prefix="vmt-uploads-"))
    with st.container(border=True):
        request = tool.form(settings, st.session_state.upload_dir)
        if request is None:
            args, warning = None, None
        else:
            args, warning = request
        confirmed = st.checkbox(warning) if warning else True
        clicked = st.button("Run", type="primary", icon=":material/play_arrow:",
                            disabled=args is None or not confirmed)
        if args is None:
            st.caption("Fill in the fields above to run this tool.")

    if args is not None:
        shown = ["vmt", "--db", str(db_path), *(["--offline"] if offline else []), *args]
        with st.expander("Run it from a terminal instead"):
            st.code(shlex.join(shown), language="bash")
        if clicked:
            logging.getLogger("vmtoolkit.audit").info("%s ran: %s", st.session_state.get("user", "local user"),
                                                      shlex.join(shown))
            output, code, seconds = execute(tools.base_command(settings, db_path, offline) + args, settings.base_dir)
            st.session_state.setdefault("runs", {})[tool.key] = (output, code, seconds, db_path.name)

    last = st.session_state.get("runs", {}).get(tool.key)
    if last:
        output, code, seconds, db_name = last
        st.subheader("Results")
        took = "under a second" if seconds < 1 else f"{seconds:.0f} s"
        if code == 0:
            st.success(f"Finished in {took} on {db_name}.", icon=":material/check_circle:")
        else:
            st.error(f"Failed (exit code {code}) after {took} on {db_name}. The output below says why.",
                     icon=":material/error:")
        st.code(output or "(no output)", language=None, height=520 if output.count("\n") > 25 else "content")


def render_setup(settings: Settings):
    st.title("Setup status")
    st.markdown(f"API keys and passwords live in `{settings.base_dir / '.env'}`. Fill in only the ones for the "
                "tools you use, then restart the dashboard. Values are never shown here.")
    for purpose, keys in tools.secret_status():
        with st.container(border=True, horizontal=True, vertical_alignment="center"):
            done = all(keys.values())
            st.markdown(f"**{purpose}**  \n" + " ".join(f"`{k}`" for k in keys), width="stretch")
            if done:
                st.badge("Ready", icon=":material/check_circle:", color="green")
            else:
                st.badge("Not set", icon=":material/radio_button_unchecked:", color="gray")
    st.caption("Other settings (Nessus URL, fix deadlines, alert channels, machine importance) are in "
               f"{settings.base_dir / 'config.toml'}.")
