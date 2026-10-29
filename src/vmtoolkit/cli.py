import logging
import shutil
import sys
from importlib import resources
from pathlib import Path

import typer

from . import db
from .config import ConfigError, RedactSecrets, Settings, load_settings, redact

# Showing locals in tracebacks could print API keys, so pretty exceptions stay off.
app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False, add_completion=False,
                  help="Vulnerability management toolkit.")
nessus_app = typer.Typer(no_args_is_help=True, help="Pull scan results from the Nessus API.")
app.add_typer(nessus_app, name="nessus")
exploit_app = typer.Typer(no_args_is_help=True,
                          help="Predict which CVEs get exploited (trained on NVD + CISA KEV) and compare with EPSS.")
app.add_typer(exploit_app, name="exploit-model")
fp_app = typer.Typer(no_args_is_help=True, help="Mark false positives and flag findings that look like them.")
app.add_typer(fp_app, name="fp")
classify_app = typer.Typer(no_args_is_help=True,
                           help="Predict CWE and attack vector from descriptions, for CVEs NVD hasn't analysed.")
app.add_typer(classify_app, name="classify")
notes_app = typer.Typer(no_args_is_help=True, help="Your own notes about CVEs and findings (used by vmt triage).")
app.add_typer(notes_app, name="notes")
users_app = typer.Typer(no_args_is_help=True, help="Dashboard accounts.")
app.add_typer(users_app, name="users")
schedule_app = typer.Typer(no_args_is_help=True, help="Run `vmt daily` automatically every day.")
app.add_typer(schedule_app, name="schedule")
history_app = typer.Typer(no_args_is_help=True, help="Day-by-day history of your numbers, rankings and plans.")
app.add_typer(history_app, name="history")


@app.callback()
def main_options(
    ctx: typer.Context,
    config: Path = typer.Option(None, "--config", "-c", help="Path to config.toml (default: ./config.toml)."),
    db_path: Path = typer.Option(None, "--db", help="Use this database file instead of the configured one."),
    offline: bool = typer.Option(False, "--offline", help="Use cached web data only; make no network calls."),
):
    ctx.obj = {"config": config, "db": db_path, "offline": offline}


def settings_from(ctx: typer.Context) -> Settings:
    if "settings" not in ctx.obj:
        root = ctx.find_root().obj
        ctx.obj["settings"] = load_settings(root["config"], offline=root["offline"], db=root["db"])
    return ctx.obj["settings"]


@app.command()
def init(folder: Path = typer.Argument(Path("."), help="Where to create config.toml and .env.")):
    """Create config.toml and .env from the templates (existing files are left alone)."""
    templates = resources.files("vmtoolkit") / "templates"
    for template, target in (("config.example.toml", "config.toml"), ("env.example", ".env")):
        dest = folder / target
        if dest.exists():
            typer.echo(f"{dest} already exists, left unchanged")
            continue
        with resources.as_file(templates / template) as src:
            shutil.copyfile(src, dest)
        typer.echo(f"Created {dest}")


@nessus_app.command("check")
def nessus_check(ctx: typer.Context):
    """Log in to Nessus and show its version."""
    from .nessus import NessusClient

    client = NessusClient.from_settings(settings_from(ctx))
    try:
        props = client.server_properties()
        typer.echo(f"Connected to {client.url}: Nessus {props.get('server_version', '?')} "
                   f"({props.get('nessus_type', 'unknown edition')})")
    finally:
        client.close()


@nessus_app.command("scans")
def nessus_scans(ctx: typer.Context):
    """List scans and how many runs each one has."""
    from .nessus import NessusClient

    client = NessusClient.from_settings(settings_from(ctx))
    try:
        scans = client.list_scans()
        if not scans:
            typer.echo("No scans found.")
        for scan in scans:
            runs = client.scan_details(scan["id"]).get("history") or []
            done = sum(1 for r in runs if r.get("status") == "completed")
            typer.echo(f"{scan['id']:>6}  {scan.get('name', '')}  ({done} completed runs of {len(runs)})")
    finally:
        client.close()


@nessus_app.command("pull")
def nessus_pull(
    ctx: typer.Context,
    scan: list[int] = typer.Option(None, "--scan", help="Only pull this scan ID (repeatable)."),
):
    """Download every completed run of every scan, back up the raw files and import them."""
    from .nessus import NessusClient, pull

    settings = settings_from(ctx)
    client = NessusClient.from_settings(settings)
    conn = db.connect(settings.db_path)
    try:
        for line in pull(client, settings, conn, scan_ids=scan or None):
            typer.echo(line)
        typer.echo(f"Raw backups: {settings.raw_dir / 'nessus'}")
        typer.echo(f"Database:    {settings.db_path}")
    finally:
        conn.close()
        client.close()


@nessus_app.command("reimport")
def nessus_reimport(ctx: typer.Context):
    """Load every saved raw backup into the database without contacting Nessus."""
    from .nessus import reimport

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        for line in reimport(settings, conn) or ["No backups found."]:
            typer.echo(line)
    finally:
        conn.close()


@app.command("import")
def import_files(
    ctx: typer.Context,
    files: list[Path] = typer.Argument(..., exists=True, dir_okay=False, help="Scan result files."),
    fmt: str = typer.Option(None, "--format", help="nessus, openvas or trivy (detected if omitted)."),
    host: str = typer.Option(None, "--host", help="Trivy only: the machine these findings belong to."),
):
    """Import .nessus, OpenVAS/GVM XML or Trivy JSON files into the database."""
    from .normalize import store_scan
    from .parsers import parse_file

    settings = settings_from(ctx)
    include_info = settings.section("import").get("include_info", False)
    conn = db.connect(settings.db_path)
    failed = False
    try:
        for path in files:
            try:
                result = parse_file(path, fmt=fmt, host=host)
            except ValueError as e:
                typer.echo(f"{path}: {e}", err=True)
                failed = True
                continue
            typer.echo(store_scan(conn, result, include_info=include_info).describe())
    finally:
        conn.close()
    if failed:
        raise typer.Exit(1)


@app.command()
def enrich(
    ctx: typer.Context,
    cve: list[str] = typer.Option(None, "--cve", help="Only enrich this CVE (repeatable)."),
    nvd: bool = typer.Option(True, "--nvd/--no-nvd", help="Look up NVD details (slow without an API key)."),
    exploits: bool = typer.Option(True, "--exploits/--no-exploits", help="Check Exploit-DB and Metasploit."),
):
    """Add EPSS, CISA KEV, NVD and public-exploit data to every CVE in the database."""
    from .config import get_secret
    from .enrich import enrich as run_enrich
    from .web import web_session

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        for line in run_enrich(conn, web_session(settings), cves=cve or None, nvd=nvd, exploits=exploits,
                               nvd_api_key=get_secret("NVD_API_KEY")):
            typer.echo(line)
    finally:
        conn.close()


@app.command("cve")
def show_cve(ctx: typer.Context, cve_id: str = typer.Argument(..., help="For example CVE-2021-44228.")):
    """Show everything stored about one CVE, in plain words."""
    from .enrich import describe_cve

    conn = db.connect(settings_from(ctx).db_path)
    try:
        for line in describe_cve(conn, cve_id):
            typer.echo(line)
    finally:
        conn.close()


@app.command()
def deps(
    ctx: typer.Context,
    paths: list[Path] = typer.Argument(..., exists=True, help="Files or folders to check."),
    save: bool = typer.Option(False, "--save", help="Store the results in the database as findings."),
    host: str = typer.Option(None, "--host", help="With --save: the machine this project runs on."),
):
    """Check requirements.txt, package.json and package-lock.json files against OSV.dev."""
    from . import deps as dep_check
    from .normalize import store_scan
    from .web import web_session

    settings = settings_from(ctx)
    reports = dep_check.parse_files(paths)
    if not reports:
        typer.echo("No requirements*.txt, package.json or package-lock.json files found.")
        raise typer.Exit(1)
    all_deps = [d for r in reports for d in r.deps]
    found = dep_check.check(web_session(settings), all_deps) if all_deps else {}

    index = 0
    for report in reports:
        exact = sum(d.exact for d in report.deps)
        typer.echo(f"{report.path}: " + (report.note or
                   f"{len(report.deps)} packages checked ({exact} exact, {len(report.deps) - exact} ranges)"))
        for item in report.skipped:
            typer.echo(f"  skipped {item}")
        for dep in report.deps:
            if found.get(index):
                typer.echo(f"  {dep_check.describe(dep)}")
            for v in found.get(index, []):
                typer.echo(f"    {dep_check.describe_vuln(v)}")
            index += 1
    total = sum(len(v) for v in found.values())
    typer.echo(f"{total} vulnerabilities in {len(found)} of {len(all_deps)} packages.")

    if save:
        conn = db.connect(settings.db_path)
        try:
            scan = dep_check.to_scan(reports, all_deps, found, paths[0], host)
            typer.echo(store_scan(conn, scan).describe())
        finally:
            conn.close()


@app.command()
def alert(
    ctx: typer.Context,
    refresh: bool = typer.Option(True, "--refresh/--no-refresh", help="Download fresh KEV and EPSS data first."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be sent without sending or recording it."),
):
    """Alert on open CVEs newly on CISA KEV or whose EPSS score jumped. Meant to run daily."""
    from .alerts import open_cves, run_alerts
    from .enrich import update_epss, update_kev
    from .web import web_session

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        if refresh:
            session = web_session(settings)
            update_kev(conn, session)
            update_epss(conn, session, sorted(open_cves(conn)))
        for line in run_alerts(conn, settings, dry_run=dry_run, echo=typer.echo):
            typer.echo(line)
    finally:
        conn.close()


@app.command("fake-data")
def fake_data(
    ctx: typer.Context,
    out: Path = typer.Option(None, "--out", help="Database file to create (default: <data_dir>/fake.db)."),
    machines: int = typer.Option(40, help="Number of fake machines."),
    days: int = typer.Option(365, help="Days of weekly scan history."),
    seed: int = typer.Option(7, help="Random seed; the same seed gives the same data."),
    force: bool = typer.Option(False, "--force", help="Replace an existing fake database."),
):
    """Generate a separate database of clearly labelled FAKE scan history for demos and testing."""
    from .config import production
    from .fakedata import generate

    if production():
        raise ConfigError("Demo data is turned off in production (VMT_ENV=production).")

    settings = settings_from(ctx)
    path = out or settings.data_dir / "fake.db"
    real_db = settings.data_dir / "vmt.db"
    typer.echo(generate(path, real_db, machines=machines, days=days, seed=seed, force=force))
    typer.echo(f"Use it with: vmt --db {path} dashboard")


def _need_dashboard():
    from importlib.util import find_spec

    if find_spec("streamlit") is None:
        typer.echo('The dashboard needs extra packages: pip install -e ".[dashboard]"', err=True)
        raise typer.Exit(1)


@app.command()
def dashboard(
    ctx: typer.Context,
    port: int = typer.Option(8501, help="Port for the web page."),
    host: str = typer.Option("localhost", help="Address to listen on. Only change it behind sign-in and HTTPS."),
):
    """Start the dashboard on http://localhost:<port>: charts, plus a page to run every tool."""
    import subprocess

    from .serve import dashboard_command

    _need_dashboard()
    raise typer.Exit(subprocess.call(dashboard_command(settings_from(ctx), port, host)))


@app.command()
def serve(
    ctx: typer.Context,
    port: int = typer.Option(None, envvar="PORT", help="Port to listen on (default $PORT, else 8501)."),
    host: str = typer.Option("0.0.0.0", help="Address to listen on."),
):
    """Run the dashboard, plus the daily routine and a backup at the daily time in config.toml. For containers."""
    from .config import production
    from .serve import serve as run

    _need_dashboard()
    if not production():
        typer.echo("Warning: VMT_ENV isn't 'production', so the dashboard only asks for a password once an "
                   "account exists. Create one with `vmt users add`.", err=True)
    raise typer.Exit(run(settings_from(ctx), port or 8501, host))


@app.command("backup")
def backup_cmd(ctx: typer.Context, keep: int = typer.Option(14, help="How many dated copies to keep.")):
    """Copy the database to data/backups/, keeping the newest copies. `vmt serve` does this daily."""
    from .backup import backup

    target, removed = backup(settings_from(ctx), keep=keep)
    typer.echo(f"Backed up to {target}" + (f"; removed {len(removed)} older copies." if removed else "."))


@users_app.command("add")
def users_add(ctx: typer.Context, username: str = typer.Argument(...)):
    """Create a dashboard account. Asks for the password twice."""
    from .users import add_user

    password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    conn = db.connect(settings_from(ctx).db_path)
    try:
        add_user(conn, username, password)
    finally:
        conn.close()
    typer.echo(f"Created {username.strip().lower()}.")


@users_app.command("passwd")
def users_passwd(ctx: typer.Context, username: str = typer.Argument(...)):
    """Set a new password for an account (also clears a lockout)."""
    from .users import set_password

    password = typer.prompt("New password", hide_input=True, confirmation_prompt=True)
    conn = db.connect(settings_from(ctx).db_path)
    try:
        set_password(conn, username, password)
    finally:
        conn.close()
    typer.echo(f"Password changed for {username.strip().lower()}.")


@users_app.command("remove")
def users_remove(ctx: typer.Context, username: str = typer.Argument(...)):
    """Delete a dashboard account."""
    from .users import remove_user

    conn = db.connect(settings_from(ctx).db_path)
    try:
        typer.echo(f"Removed {username}." if remove_user(conn, username) else f"No user called {username}.")
    finally:
        conn.close()


@users_app.command("list")
def users_list(ctx: typer.Context):
    """Show dashboard accounts and when each last signed in."""
    from .users import list_users

    conn = db.connect(settings_from(ctx).db_path)
    try:
        rows = list_users(conn)
    finally:
        conn.close()
    if not rows:
        typer.echo("No accounts yet. Create one with `vmt users add <name>`.")
    for r in rows:
        locked = f"  locked until {r['locked_until']}" if r["locked_until"] else ""
        typer.echo(f"{r['username']:<24} created {r['created_at'][:10]}  last sign-in "
                   f"{(r['last_login_at'] or 'never')[:16]}{locked}")


@app.command("dedupe")
def dedupe_cmd(ctx: typer.Context):
    """Find findings from different scanners that are the same problem on the same machine."""
    from .dedupe import dedupe

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        for line in dedupe(conn, settings):
            typer.echo(line)
    finally:
        conn.close()


@app.command("prioritize")
def prioritize_cmd(
    ctx: typer.Context,
    top: int = typer.Option(20, help="How many to show."),
    explain: int = typer.Option(None, "--explain", help="Show the full reasoning for this finding ID."),
    machine: str = typer.Option(None, help="Only show findings on this machine."),
):
    """Rank open findings by exploit likelihood, impact and machine importance, with reasons."""
    from .prioritize import prioritize

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        ranked = prioritize(conn, settings)
    finally:
        conn.close()
    if explain is not None:
        match = next((r for r in ranked if r.finding_id == explain), None)
        typer.echo(match.explain() if match else
                   f"Finding {explain} isn't ranked: it is fixed, info-level, a duplicate, or doesn't exist.")
        return
    shown = [r for r in ranked if not machine or r.machine == machine.lower()][:top]
    if not shown:
        typer.echo("No open findings to rank.")
        return
    typer.echo(f"{'rank':>4} {'score':>5}  {'id':>5}  {'machine':<20} {'severity':<8} title")
    for r in shown:
        flag = "  [KEV]" if r.on_kev else ""
        typer.echo(f"{r.rank:>4} {r.score:>5.1f}  {r.finding_id:>5}  {r.machine[:20]:<20} {r.severity:<8} "
                   f"{r.title[:60]}{flag}")
    typer.echo(f"{len(ranked)} open findings ranked. Run `vmt prioritize --explain <id>` to see why.")


@app.command("plan")
def plan_cmd(
    ctx: typer.Context,
    target: float = typer.Option(None, help="Stop once this percent of total risk is covered (default 80)."),
    max_fixes: int = typer.Option(None, "--max-fixes", help="Show at most this many fixes."),
    explain: int = typer.Option(None, "--explain", help="Show the full reasoning for fix number N."),
):
    """Group open findings into fixes and show the fewest fixes that remove the most risk."""
    from .plan import plan

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        chosen, rest, summary = plan(conn, settings, target=target / 100 if target is not None else None,
                                     max_fixes=max_fixes)
    finally:
        conn.close()
    if explain is not None:
        match = next((f for f in chosen + rest if f.rank == explain), None)
        typer.echo(match.explain() if match else f"There is no fix number {explain}.")
        return
    if chosen:
        typer.echo(f"{'fix':>3} {'risk':>6} {'cum':>5} {'findings':>8} {'machines':>8}  action")
        for f in chosen:
            typer.echo(f"{f.rank:>3} {f.risk:>6.1f} {f.cumulative:>5.0%} {len(f.findings):>8} "
                       f"{len(f.machines):>8}  {f.action[:80]}")
    typer.echo(summary)
    if chosen:
        typer.echo("Run `vmt plan --explain <fix>` to see what a fix closes and why it ranks where it does.")


@app.command("tickets")
def tickets_cmd(
    ctx: typer.Context,
    max_fixes: int = typer.Option(None, "--max-fixes", help="Only make tickets for the top N fixes."),
    push: str = typer.Option(None, "--push", help="Also send tickets to 'jira' or 'servicenow'."),
):
    """Write one remediation ticket per fix to data/vmt-tickets/, and optionally push them to Jira or ServiceNow."""
    from .tickets import generate, push_jira, push_servicenow

    if push not in (None, "jira", "servicenow"):
        raise ConfigError("--push must be 'jira' or 'servicenow'")
    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        for line in generate(conn, settings, max_fixes=max_fixes):
            typer.echo(line)
        if push:
            for line in (push_jira if push == "jira" else push_servicenow)(conn, settings):
                typer.echo(line)
    finally:
        conn.close()


def _nvd_records(settings: Settings) -> list[dict]:
    from datetime import date

    from .ml.feeds import download_feeds, load_records

    years = list(range(int(settings.section("exploit_model").get("first_year", 2015)), date.today().year + 1))
    typer.echo(f"Loading NVD feeds {years[0]}-{years[-1]} (first run downloads about 25 MB per year)...")
    return load_records(download_feeds(settings, years), settings.data_dir / "models" / "nvd-records")


def _exploit_inputs(settings: Settings):
    """Feeds, records and KEV dates shared by the exploit-model commands."""
    from .enrich import update_kev
    from .web import web_session

    conn = db.connect(settings.db_path)
    try:
        update_kev(conn, web_session(settings))
        kev = {r["cve"]: r["date_added"] for r in conn.execute("SELECT cve, date_added FROM kev")}
    finally:
        conn.close()
    records = _nvd_records(settings)
    typer.echo(f"{len(records):,} CVEs loaded, {sum(1 for r in records if r['cve'] in kev):,} of them on KEV.")
    return records, kev


def _need_ml():
    from importlib.util import find_spec

    if find_spec("sklearn") is None:
        typer.echo('The ML tools need extra packages: pip install -e ".[ml]"', err=True)
        raise typer.Exit(1)


@exploit_app.command("evaluate")
def exploit_evaluate(
    ctx: typer.Context,
    cutoff_days: int = typer.Option(365, help="Pretend it is this many days ago, then check what happened since."),
    window_days: int = typer.Option(0, help="Only test CVEs published this many days before the cutoff (0 = all)."),
):
    """Backtest the model against EPSS as of a past date, for both feature sets."""
    _need_ml()
    from datetime import date, timedelta

    from .ml.exploit_model import MODES, evaluate
    from .ml.feeds import epss_on

    settings = settings_from(ctx)
    records, kev = _exploit_inputs(settings)
    cutoff = date.today() - timedelta(days=cutoff_days)
    epss = epss_on(settings, cutoff)
    reports = []
    for mode in MODES:
        typer.echo(f"Training and testing the {mode} feature set...")
        reports.append(evaluate(records, kev, epss, cutoff, mode=mode, window_days=window_days or None).report())
    text = "\n\n".join(reports)
    out = settings.data_dir / "models" / "exploit-evaluation.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text + "\n", encoding="utf-8")
    typer.echo("\n" + text + f"\n\nSaved to {out}")


@exploit_app.command("train")
def exploit_train(
    ctx: typer.Context,
    mode: str = typer.Option("strict", help="strict (issuer data only) or full (adds NVD's later analysis)."),
):
    """Train on every CVE with today's KEV labels and save the model for scoring."""
    _need_ml()
    import numpy as np

    from .ml.exploit_model import ExploitModel, save

    settings = settings_from(ctx)
    records, kev = _exploit_inputs(settings)
    labels = np.array([1 if r["cve"] in kev else 0 for r in records])
    model = ExploitModel(mode).fit(records, labels)
    path = save(model, settings.data_dir / "models", {
        "trained_at": db.utcnow(), "mode": mode, "cves": len(records), "kev_positive": int(labels.sum())})
    typer.echo(f"Saved {path} ({mode} features, {len(records):,} CVEs, {int(labels.sum()):,} on KEV).")


@exploit_app.command("score")
def exploit_score(ctx: typer.Context):
    """Score the CVEs in your database with the saved model, next to their EPSS scores."""
    _need_ml()
    from .ml.exploit_model import load, score_mine
    from .ml.feeds import load_records

    settings = settings_from(ctx)
    model, meta = load(settings.data_dir / "models")
    cache = settings.data_dir / "models" / "nvd-records"
    feeds = sorted((settings.raw_dir / "nvd-feeds").glob("*.json.gz"))
    records = {r["cve"]: r for r in load_records(feeds, cache)}
    conn = db.connect(settings.db_path)
    try:
        rows, missing = score_mine(conn, model, meta, records, db.utcnow())
    finally:
        conn.close()
    base = meta["kev_positive"] / meta["cves"]
    typer.echo(f"Model trained {meta['trained_at'][:10]} ({meta['mode']} features). "
               "Probability = chance the CVE is on CISA KEV, judged only from how it was described at publication. "
               f"For scale: {base:.2%} of all CVEs are on KEV, so 5% is already about {0.05 / base:.0f}x the average.")
    for r in sorted(rows, key=lambda r: -r["probability"]):
        epss = f"{r['epss']:.3f}" if r["epss"] is not None else "  n/a"
        typer.echo(f"{r['cve']:<16} model {r['probability']:6.1%}  EPSS {epss}  {r['reason']}")
    if missing:
        typer.echo(f"{len(missing)} CVEs aren't in the downloaded NVD feeds (too new, or outside the years "
                   f"trained on): {', '.join(missing[:10])}{' ...' if len(missing) > 10 else ''}")


@fp_app.command("mark")
def fp_mark(
    ctx: typer.Context,
    ids: list[int] = typer.Argument(..., help="Finding IDs (shown by `vmt prioritize`)."),
    real: bool = typer.Option(False, "--real", help="Confirm these are real issues instead."),
    reason: str = typer.Option(None, help="Why, in your words."),
):
    """Mark findings as false positives (or --real). False positives drop out of rankings and alerts."""
    from .fp import mark

    conn = db.connect(settings_from(ctx).db_path)
    try:
        for line in mark(conn, ids, real, reason):
            typer.echo(line)
    finally:
        conn.close()


@fp_app.command("unmark")
def fp_unmark(ctx: typer.Context, ids: list[int] = typer.Argument(...)):
    """Remove your mark from findings."""
    from .fp import unmark

    conn = db.connect(settings_from(ctx).db_path)
    try:
        for line in unmark(conn, ids):
            typer.echo(line)
    finally:
        conn.close()


@fp_app.command("list")
def fp_list(ctx: typer.Context):
    """Show every finding you have marked."""
    conn = db.connect(settings_from(ctx).db_path)
    try:
        rows = conn.execute(
            """SELECT l.*, f.title, f.status, a.name FROM fp_labels l JOIN findings f ON f.id = l.finding_id
               JOIN assets a ON a.id = f.asset_id ORDER BY l.label, l.labeled_at""").fetchall()
    finally:
        conn.close()
    if not rows:
        typer.echo("Nothing marked yet.")
    for r in rows:
        label = "FALSE POSITIVE" if r["label"] == "false_positive" else "REAL"
        typer.echo(f"{r['finding_id']:>6}  {label:<14} {r['name']:<20} {r['title'][:50]}"
                   + (f"  ({r['reason']})" if r["reason"] else ""))


@fp_app.command("predict")
def fp_predict(ctx: typer.Context, top: int = typer.Option(20, help="How many to show.")):
    """Flag open findings that look like the ones you marked as false positives."""
    from .fp import predict

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        flagged, note = predict(conn, settings)
    finally:
        conn.close()
    typer.echo(note)
    for p in flagged[:top]:
        typer.echo(f"{p.finding_id:>6}  {p.probability:5.0%} likely false positive  {p.machine:<20} {p.title[:50]}")
        typer.echo(f"        {p.reason}")
    if flagged:
        typer.echo(f"{len(flagged)} flagged. Confirm with `vmt fp mark <id>` or `vmt fp mark <id> --real`.")


@app.command("forecast")
def forecast_cmd(
    ctx: typer.Context,
    show_all: bool = typer.Option(False, "--all", help="Show every open finding, not just the at-risk ones."),
    backtest_days: int = typer.Option(90, help="Also check how forecasts made this many days ago turned out."),
):
    """Forecast fix times and warn about open findings likely to miss their deadline."""
    from .forecast import backtest, forecast

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        results = forecast(conn, settings)
        check = backtest(conn, settings, days_back=backtest_days) if backtest_days else None
    finally:
        conn.close()
    shown = results if show_all else [f for f in results if f.at_risk]
    overdue = sum(1 for f in results if f.p_on_time is None and f.age > f.deadline_days)
    typer.echo(f"{len(results)} open findings: {sum(f.at_risk for f in results)} likely to miss their deadline, "
               f"{overdue} already overdue.")
    for f in shown:
        chance = f"{f.p_on_time:4.0%} on time" if f.p_on_time is not None else "   no forecast"
        typer.echo(f"{f.finding_id:>6}  {chance}  due {f.due}  {f.severity:<8} {f.machine:<20} {f.title[:45]}")
        typer.echo(f"        {f.reason}")
    if check:
        typer.echo("\n" + check)


@app.command("report")
def report_cmd(
    ctx: typer.Context,
    audience: str = typer.Option("both", help="ceo (one page), ciso (with detail) or both."),
    days: int = typer.Option(7, min=1, help="Length of the reporting period in days (7 weekly, 30 monthly)."),
):
    """Write the CEO and CISO reports as PDF to data/reports/, for any period."""
    from importlib.util import find_spec

    if audience not in ("ceo", "ciso", "both"):
        raise ConfigError("--audience must be ceo, ciso or both")
    if find_spec("reportlab") is None:
        typer.echo('Reports need an extra package: pip install -e ".[report]"', err=True)
        raise typer.Exit(1)
    from .report import build, report_path
    from .report_pdf import render

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        data = build(conn, settings, days=days)
    finally:
        conn.close()
    for who in (["ceo", "ciso"] if audience == "both" else [audience]):
        path = render(data, who, report_path(settings, who, data.generated_at, days), settings.db_path.name)
        typer.echo(f"{who.upper()} report: {path}")
    typer.echo(f"Status {data.status.upper()}: {data.status_reason}")


@app.command("daily")
def daily_cmd(ctx: typer.Context):
    """Pull from Nessus, refresh threat data, rank, plan, alert, and write the weekly reports when due."""
    from .daily import run_daily

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        status = run_daily(conn, settings, echo=typer.echo)
    finally:
        conn.close()
    raise typer.Exit(0 if status == "ok" else 1)


@history_app.command("save")
def history_save(
    ctx: typer.Context,
    backfill: int = typer.Option(0, help="Also rebuild counts for this many past days that have no snapshot."),
):
    """Save today's headline numbers. `vmt daily` does this every day."""
    from .history import backfill as run_backfill, save_snapshot

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        if backfill:
            typer.echo(run_backfill(conn, settings, backfill))
        typer.echo(save_snapshot(conn, settings))
    finally:
        conn.close()


@history_app.command("show")
def history_show(ctx: typer.Context, days: int = typer.Option(30, help="How many days back.")):
    """Headline numbers for each day."""
    from .history import snapshots

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        rows = snapshots(conn, days)
    finally:
        conn.close()
    if not rows:
        typer.echo("No history yet. Run `vmt history save`, or `vmt history save --backfill 365` to rebuild past days.")
        return
    typer.echo(f"{'day':<10}  {'open':>5} {'crit+high':>9} {'overdue':>7} {'exploited':>9} {'new':>4} {'fixed':>5}"
               f"  {'on time':>7}  status")
    for r in rows:
        on_time = f"{r['on_time_rate']:.0%}" if r["on_time_rate"] is not None else ""
        status = "(rebuilt)" if r["reconstructed"] else (r["status"] or "").upper()
        typer.echo(f"{r['day']:<10}  {r['open']:>5} {r['critical_high']:>9} {r['overdue']:>7} {r['known_exploited']:>9} "
                   f"{r['new']:>4} {r['fixed']:>5}  {on_time:>7}  {status}")


@history_app.command("on")
def history_on(ctx: typer.Context, day: str = typer.Argument(..., help="A date, for example 2026-10-01.")):
    """What the numbers, top risks and patch plan were on one day."""
    from .history import plan_on, ranking_on

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        snap = conn.execute("SELECT * FROM history_snapshots WHERE day = ?", (day,)).fetchone()
        ranking, fixes = ranking_on(conn, day), plan_on(conn, day)
    finally:
        conn.close()
    if snap:
        typer.echo(f"{day}: {snap['open']} open, {snap['critical_high']} critical or high, {snap['overdue']} past "
                   f"deadline, {snap['known_exploited']} actively exploited"
                   + (" (rebuilt from scan dates)." if snap["reconstructed"] else f". Status {snap['status'].upper()}."))
    else:
        typer.echo(f"No snapshot saved for {day}.")
    if ranking:
        typer.echo(f"\nTop risks (ranking from {ranking[0]['day']}):")
        for r in ranking:
            fixed = f"  fixed {r['fixed_on']}" if r["fixed_on"] else ""
            typer.echo(f"{r['rank']:>4} {r['score']:>5.1f}  {r['machine'][:20]:<20} {r['severity']:<8} {r['title'][:55]}{fixed}")
    if fixes:
        typer.echo(f"\nPatch plan (from {fixes[0]['day']}):")
        for f in fixes[:10]:
            typer.echo(f"{f['rank']:>4} {f['share']:>4.0%}  {f['findings']:>3} findings  {f['action'][:70]}")


@schedule_app.command("install")
def schedule_install(ctx: typer.Context, time: str = typer.Option("07:00", help="Time of day, 24-hour clock.")):
    """Run `vmt daily` every day at this time, on the database in config.toml."""
    from .schedule import install

    typer.echo(install(settings_from(ctx), time))


@schedule_app.command("remove")
def schedule_remove():
    """Stop running `vmt daily` automatically."""
    from .schedule import remove

    typer.echo(remove())


@schedule_app.command("status")
def schedule_status():
    """Show whether `vmt daily` is scheduled, and when."""
    from .schedule import status

    typer.echo(status())


@classify_app.command("evaluate")
def classify_evaluate(ctx: typer.Context, cutoff_days: int = typer.Option(365, help="Test on CVEs newer than this.")):
    """Train on older CVEs, test on the newest, and compare with always guessing the most common answer."""
    _need_ml()
    from datetime import date, timedelta

    from .ml.classifier import evaluate

    settings = settings_from(ctx)
    records = _nvd_records(settings)
    typer.echo("Training and testing...")
    text = evaluate(records, date.today() - timedelta(days=cutoff_days)).report()
    out = settings.data_dir / "models" / "classifier-evaluation.txt"
    out.write_text(text + "\n", encoding="utf-8")
    typer.echo("\n" + text + f"\n\nSaved to {out}")


@classify_app.command("train")
def classify_train(ctx: typer.Context):
    """Train on every NVD CVE that has a CWE or attack vector, and save the model."""
    _need_ml()
    import joblib

    from .ml.classifier import DescriptionClassifier

    settings = settings_from(ctx)
    model = DescriptionClassifier().fit(_nvd_records(settings))
    folder = settings.data_dir / "models"
    joblib.dump({"model": model, "trained_at": db.utcnow()}, folder / "classifier.joblib")
    typer.echo(f"Saved {folder / 'classifier.joblib'} (trained on {model.trained_on:,} CVEs).")


@classify_app.command("predict")
def classify_predict(ctx: typer.Context):
    """Predict CWE and attack vector for your CVEs that NVD hasn't given them yet."""
    _need_ml()
    import joblib

    from .ml.classifier import predict_mine
    from .ml.feeds import load_records

    settings = settings_from(ctx)
    path = settings.data_dir / "models" / "classifier.joblib"
    if not path.exists():
        typer.echo("No trained classifier yet. Run `vmt classify train` first.", err=True)
        raise typer.Exit(1)
    saved = joblib.load(path)
    feeds = sorted((settings.raw_dir / "nvd-feeds").glob("*.json.gz"))
    records = {r["cve"]: r for r in load_records(feeds, settings.data_dir / "models" / "nvd-records")}
    conn = db.connect(settings.db_path)
    try:
        rows, missing = predict_mine(conn, saved["model"], saved["trained_at"], db.utcnow(), records)
    finally:
        conn.close()
    if not rows and not missing:
        typer.echo("Every CVE in your database already has a CWE and attack vector from NVD.")
    for r in rows:
        typer.echo(f"{r['cve']:<16} {r['explanation']}")
    if missing:
        typer.echo(f"No description stored for {len(missing)} CVEs (run `vmt enrich` first): {', '.join(missing[:10])}")


@app.command("extract")
def extract_cmd(
    ctx: typer.Context,
    source: str = typer.Argument(..., help="A file (HTML, text, Markdown, PDF) or an http(s) URL."),
    use_llm: bool = typer.Option(False, "--llm", help="Use the LLM instead of the offline rules (costs a few cents)."),
):
    """Pull CVEs, affected and fixed versions, and exploitation status out of an advisory or article."""
    from . import extract as ex

    settings = settings_from(ctx)
    try:
        text, title = ex.load(source, settings)
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    if use_llm:
        from .llm import client

        result, usage = ex.extract_llm(text, source, title, client(settings), settings)
    else:
        result, usage = ex.extract_rules(text, source, title), None
    conn = db.connect(settings.db_path)
    try:
        ex.save(conn, result, text)
        for line in ex.describe(conn, result):
            typer.echo(line)
    finally:
        conn.close()
    if usage:
        typer.echo(usage)


@app.command("monitor")
def monitor_cmd(ctx: typer.Context):
    """Check GitHub and security news feeds for mentions of your open CVEs, and flag spikes."""
    from .monitor import monitor
    from .web import web_session

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        for line in monitor(conn, settings, web_session(settings)):
            typer.echo(line)
    finally:
        conn.close()


def _note_target(target: str) -> str:
    if target.upper().startswith("CVE-"):
        return target.upper()
    if target.isdigit():
        return f"finding:{target}"
    raise ConfigError(f"{target!r} is neither a CVE ID nor a finding number")


@notes_app.command("add")
def notes_add(ctx: typer.Context, target: str = typer.Argument(..., help="A CVE ID or finding number."),
              text: str = typer.Argument(...)):
    """Add a note, e.g. vmt notes add CVE-2024-3400 "GlobalProtect is disabled on our firewall"."""
    conn = db.connect(settings_from(ctx).db_path)
    try:
        with conn:
            conn.execute("INSERT INTO notes (target, text, created_at) VALUES (?, ?, ?)",
                         (_note_target(target), text, db.utcnow()))
    finally:
        conn.close()
    typer.echo(f"Note added to {_note_target(target)}.")


@notes_app.command("list")
def notes_list(ctx: typer.Context, target: str = typer.Argument(None)):
    """List notes, for one CVE or finding or all of them."""
    conn = db.connect(settings_from(ctx).db_path)
    try:
        rows = conn.execute("SELECT * FROM notes" + (" WHERE target = ?" if target else "") + " ORDER BY created_at",
                            (_note_target(target),) if target else ()).fetchall()
    finally:
        conn.close()
    for r in rows:
        typer.echo(f"{r['id']:>4}  {r['created_at'][:10]}  {r['target']:<16} {r['text']}")
    if not rows:
        typer.echo("No notes yet.")


@app.command("triage")
def triage_cmd(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="A CVE ID or finding number."),
    show_prompt: bool = typer.Option(False, "--show-prompt", help="Print exactly what would be sent; send nothing."),
    refresh: bool = typer.Option(False, "--refresh", help="Ask again even if a saved answer exists."),
):
    """Explain a vulnerability in plain English with fix steps, citing NVD, KEV, your scans and your notes."""
    from .triage import triage

    settings = settings_from(ctx)
    conn = db.connect(settings.db_path)
    try:
        typer.echo(triage(conn, settings, target, refresh=refresh, show_prompt=show_prompt))
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    finally:
        conn.close()


@app.command("ask")
def ask_cmd(
    ctx: typer.Context,
    question: str = typer.Argument(None, help='For example "which machines have KEV vulnerabilities older than 30 days?"'),
    run_eval: bool = typer.Option(False, "--eval", help="Run the 20-question test set against the database (calls the API 20 times)."),
):
    """Ask a question in plain English; the LLM writes one read-only SQL query and it runs locally."""
    from .ask import Answer, QueryError, ask, run_eval as evaluate

    settings = settings_from(ctx)
    if run_eval:
        for line in evaluate(settings, settings.db_path):
            typer.echo(line)
        return
    if not question:
        typer.echo("Give a question, or --eval.", err=True)
        raise typer.Exit(1)
    conn = db.connect(settings.db_path)
    try:
        result = ask(conn, settings, question)
    except QueryError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    finally:
        conn.close()
    typer.echo(result.render() if isinstance(result, Answer) else result)


def main():
    handler = logging.StreamHandler()
    handler.addFilter(RedactSecrets())
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", handlers=[handler])
    from .llm import LLMError
    from .fakedata import FakeDataError
    from .nessus import NessusError
    from .tickets import TicketError
    from .web import WebError

    try:
        app()
    except (ConfigError, NessusError, WebError, FakeDataError, TicketError, LLMError) as e:
        typer.echo(f"Error: {redact(str(e))}", err=True)
        sys.exit(1)
