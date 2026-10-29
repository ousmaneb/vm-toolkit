import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    ip TEXT,
    fqdn TEXT,
    os TEXT,
    is_fake INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    scanner TEXT NOT NULL,
    source_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    name TEXT,
    started_at TEXT,
    finished_at TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    source_file TEXT,
    is_fake INTEGER NOT NULL DEFAULT 0,
    UNIQUE (scanner, source_id, run_id)
);

-- Which hosts a scan actually reached. A finding only counts as fixed when a later
-- scan of the same host by the same scanner no longer reports it.
CREATE TABLE IF NOT EXISTS scan_hosts (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    credentialed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, asset_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    scanner TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL,
    port INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT '',
    service TEXT,
    package TEXT NOT NULL DEFAULT '',
    installed_version TEXT,
    fixed_version TEXT,
    description TEXT,
    solution TEXT,
    evidence TEXT,
    first_seen TEXT,
    last_seen TEXT,
    fixed_at TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    status_note TEXT,
    is_fake INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS findings_asset ON findings (asset_id, scanner);

CREATE TABLE IF NOT EXISTS finding_cves (
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    cve TEXT NOT NULL,
    PRIMARY KEY (finding_id, cve)
);
CREATE INDEX IF NOT EXISTS finding_cves_cve ON finding_cves (cve);

CREATE TABLE IF NOT EXISTS observations (
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, scan_id)
);

CREATE TABLE IF NOT EXISTS cves (
    cve TEXT PRIMARY KEY,
    description TEXT,
    cvss_score REAL,
    cvss_version TEXT,
    cvss_vector TEXT,
    attack_vector TEXT,
    cwes TEXT,
    published TEXT,
    last_modified TEXT,
    nvd_status TEXT,
    nvd_fetched_at TEXT
);

-- The whole KEV catalog. first_seen_at is when this toolkit first saw the entry in the feed.
CREATE TABLE IF NOT EXISTS kev (
    cve TEXT PRIMARY KEY,
    vendor TEXT,
    product TEXT,
    name TEXT,
    date_added TEXT,
    due_date TEXT,
    ransomware TEXT,
    required_action TEXT,
    first_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS epss_history (
    cve TEXT NOT NULL,
    date TEXT NOT NULL,
    epss REAL NOT NULL,
    percentile REAL NOT NULL,
    PRIMARY KEY (cve, date)
);

-- Findings that repeat another scanner's report of the same problem. The primary is counted;
-- these are not. Rebuilt from scratch by `vmt dedupe`.
CREATE TABLE IF NOT EXISTS duplicates (
    finding_id INTEGER PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    primary_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    confidence TEXT NOT NULL,
    reason TEXT NOT NULL
);

-- Latest ranking from `vmt prioritize`, rebuilt on every run.
CREATE TABLE IF NOT EXISTS priorities (
    finding_id INTEGER PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    rank INTEGER NOT NULL,
    score REAL NOT NULL,
    likelihood REAL NOT NULL,
    impact REAL NOT NULL,
    weight REAL NOT NULL,
    exposure REAL NOT NULL,
    explanation TEXT NOT NULL,
    computed_at TEXT NOT NULL
);

-- Latest plan from `vmt plan`: fixes in order of risk removed, and the findings each one closes.
CREATE TABLE IF NOT EXISTS plan_fixes (
    fix_key TEXT PRIMARY KEY,
    rank INTEGER NOT NULL,
    action TEXT NOT NULL,
    risk REAL NOT NULL,
    share REAL NOT NULL,
    explanation TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plan_items (
    fix_key TEXT NOT NULL REFERENCES plan_fixes(fix_key) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (fix_key, finding_id)
);

-- Remediation tickets, one per fix. ticket_items remembers which findings a ticket covered,
-- so it can be resolved once they are all fixed.
CREATE TABLE IF NOT EXISTS tickets (
    ticket_id TEXT PRIMARY KEY,
    fix_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    priority TEXT NOT NULL,
    due_date TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    status_note TEXT,
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    jira_key TEXT,
    jira_hash TEXT,
    servicenow_sys_id TEXT,
    servicenow_number TEXT,
    servicenow_hash TEXT
);

CREATE TABLE IF NOT EXISTS ticket_items (
    ticket_id TEXT NOT NULL REFERENCES tickets(ticket_id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (ticket_id, finding_id)
);

-- Latest scores from `vmt exploit-model score`, next to (not replacing) EPSS.
CREATE TABLE IF NOT EXISTS exploit_predictions (
    cve TEXT PRIMARY KEY,
    probability REAL NOT NULL,
    model_trained TEXT NOT NULL,
    explanation TEXT NOT NULL,
    scored_at TEXT NOT NULL
);

-- Your own judgement of findings. Marked false positives are left out of rankings, plans,
-- tickets, alerts and the dashboard, but never deleted.
CREATE TABLE IF NOT EXISTS fp_labels (
    finding_id INTEGER PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    label TEXT NOT NULL CHECK (label IN ('false_positive', 'real')),
    reason TEXT,
    labeled_at TEXT NOT NULL,
    is_fake INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fp_predictions (
    finding_id INTEGER PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    probability REAL NOT NULL,
    method TEXT NOT NULL,
    reason TEXT NOT NULL,
    predicted_at TEXT NOT NULL
);

-- Predicted CWE and attack vector for CVEs NVD hasn't analysed (`vmt classify predict`).
-- Kept apart from the cves table so a prediction is never mistaken for NVD data.
CREATE TABLE IF NOT EXISTS cve_predictions (
    cve TEXT PRIMARY KEY,
    cwe TEXT NOT NULL,
    cwe_confidence REAL NOT NULL,
    cwe_alternatives TEXT NOT NULL,
    attack_vector TEXT NOT NULL,
    vector_confidence REAL NOT NULL,
    explanation TEXT NOT NULL,
    model_trained TEXT NOT NULL,
    predicted_at TEXT NOT NULL
);

-- Advisories read by `vmt extract`, and the facts pulled from them (each with its source sentence).
CREATE TABLE IF NOT EXISTS advisories (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    title TEXT,
    method TEXT NOT NULL,
    text_hash TEXT NOT NULL,
    text TEXT NOT NULL,
    extracted_at TEXT NOT NULL,
    UNIQUE (source, method)
);

CREATE TABLE IF NOT EXISTS advisory_items (
    advisory_id INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    cve TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    evidence TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'sentence'
);
CREATE INDEX IF NOT EXISTS advisory_items_cve ON advisory_items (cve);

-- Mentions of your CVEs on GitHub and in news feeds (`vmt monitor`), and the spikes found in them.
CREATE TABLE IF NOT EXISTS mentions (
    cve TEXT NOT NULL,
    source TEXT NOT NULL,
    item TEXT NOT NULL,
    title TEXT,
    published TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    PRIMARY KEY (cve, item)
);
CREATE INDEX IF NOT EXISTS mentions_published ON mentions (published);

CREATE TABLE IF NOT EXISTS chatter_spikes (
    cve TEXT NOT NULL,
    day TEXT NOT NULL,
    count INTEGER NOT NULL,
    explanation TEXT NOT NULL,
    PRIMARY KEY (cve, day)
);

-- Your own notes about a CVE ("CVE-...") or a finding ("finding:<id>"), used as a source by `vmt triage`.
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    target TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS notes_target ON notes (target);

-- Saved `vmt triage` answers. Reused until the sources change.
CREATE TABLE IF NOT EXISTS triage_results (
    target TEXT NOT NULL,
    sources_hash TEXT NOT NULL,
    model TEXT NOT NULL,
    answer TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (target, sources_hash)
);

-- One row per alert per channel, so a failed Slack post is retried without repeating email.
CREATE TABLE IF NOT EXISTS alerts_sent (
    alert_key TEXT NOT NULL,
    channel TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    message TEXT NOT NULL,
    PRIMARY KEY (alert_key, channel)
);

CREATE TABLE IF NOT EXISTS exploits (
    cve TEXT NOT NULL,
    source TEXT NOT NULL,
    ref TEXT NOT NULL,
    title TEXT,
    PRIMARY KEY (cve, source, ref)
);
-- History. priorities and plan_fixes only hold the latest run; these keep every day's version.
-- One row per day; a later run on the same day replaces it.
CREATE TABLE IF NOT EXISTS history_snapshots (
    day TEXT PRIMARY KEY,
    taken_at TEXT NOT NULL,
    open INTEGER NOT NULL,
    critical_high INTEGER NOT NULL,
    overdue INTEGER NOT NULL,
    known_exploited INTEGER NOT NULL,
    new INTEGER NOT NULL,
    fixed INTEGER NOT NULL,
    on_time_rate REAL,
    total_risk REAL,
    status TEXT,
    status_reason TEXT,
    -- 1 when rebuilt afterwards from first-seen and fixed dates: counts only, no status or risk.
    reconstructed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS priority_history (
    day TEXT NOT NULL,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    rank INTEGER NOT NULL,
    score REAL NOT NULL,
    PRIMARY KEY (day, finding_id)
);

CREATE TABLE IF NOT EXISTS plan_history (
    day TEXT NOT NULL,
    rank INTEGER NOT NULL,
    action TEXT NOT NULL,
    risk REAL NOT NULL,
    share REAL NOT NULL,
    findings INTEGER NOT NULL,
    machines INTEGER NOT NULL,
    PRIMARY KEY (day, rank)
);

-- One row per `vmt daily` run. A failed run is also sent as an alert.
CREATE TABLE IF NOT EXISTS daily_runs (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    failed_steps TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    log_path TEXT NOT NULL,
    reports TEXT NOT NULL DEFAULT ''
);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


# All timestamps are stored as UTC ISO strings in this exact format so they sort as text.
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(TIME_FORMAT)


def from_epoch(seconds: int | float | str) -> str:
    return to_iso(datetime.fromtimestamp(float(seconds), tz=timezone.utc))


def parse_iso(value: str) -> datetime:
    return datetime.strptime(value, TIME_FORMAT).replace(tzinfo=timezone.utc)


def normalize_timestamp(value: str) -> str:
    """Convert scanner timestamps like '2026-10-01T12:00:00.123456789Z' to the stored format."""
    value = value.strip().replace("Z", "+00:00")
    # Python 3.10 can't parse a trailing Z or more than 6 fractional digits.
    value = re.sub(r"(\.\d{1,6})\d*", r"\1", value)
    return to_iso(datetime.fromisoformat(value))


def utcnow() -> str:
    return to_iso(datetime.now(timezone.utc))
