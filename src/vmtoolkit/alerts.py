"""Alert when a CVE on an open finding is added to CISA KEV or its EPSS score jumps."""

import logging
import smtplib
import sqlite3
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

import requests

from .acceptance import expiry_alerts
from .config import ConfigError, Settings, get_secret
from .db import utcnow

log = logging.getLogger(__name__)

CHANNELS = ("console", "slack", "email")


@dataclass
class Alert:
    key: str
    cve: str
    message: str


def open_cves(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """CVE -> sorted machine names, for findings that are still open."""
    machines: dict[str, set[str]] = {}
    for row in conn.execute(
        """SELECT fc.cve, a.name FROM finding_cves fc
           JOIN findings f ON f.id = fc.finding_id JOIN assets a ON a.id = f.asset_id
           WHERE f.status = 'open' AND f.id NOT IN (SELECT finding_id FROM fp_labels WHERE label = 'false_positive')"""
    ):
        machines.setdefault(row["cve"], set()).add(row["name"])
    return {cve: sorted(names) for cve, names in machines.items()}


def find_alerts(conn: sqlite3.Connection, epss_jump: float) -> list[Alert]:
    alerts = []
    cves = open_cves(conn)
    for cve, machines in sorted(cves.items()):
        on = ", ".join(machines)
        kev = conn.execute("SELECT * FROM kev WHERE cve = ?", (cve,)).fetchone()
        if kev:
            ransomware = " It is known to be used in ransomware campaigns." if kev["ransomware"] == "Known" else ""
            alerts.append(Alert(
                key=f"kev:{cve}", cve=cve,
                message=(f"{cve} is on the CISA Known Exploited Vulnerabilities list (added {kev['date_added']}), "
                         f"so attackers are actively using it. Open on: {on}.{ransomware} "
                         f"CISA's required action: {kev['required_action'] or 'see the KEV entry'}"),
            ))
        scores = conn.execute(
            "SELECT date, epss FROM epss_history WHERE cve = ? ORDER BY date DESC LIMIT 2", (cve,)
        ).fetchall()
        if len(scores) < 2:
            continue
        latest, previous = scores
        if latest["epss"] - previous["epss"] >= epss_jump:
            alerts.append(Alert(
                key=f"epss:{cve}:{latest['date']}", cve=cve,
                message=(f"{cve} EPSS jumped from {previous['epss']:.3f} ({previous['date']}) to "
                         f"{latest['epss']:.3f} ({latest['date']}), a rise of {latest['epss'] - previous['epss']:.3f}, "
                         f"which is at or above your alert threshold of {epss_jump}. "
                         f"Exploitation is now more likely. Open on: {on}."),
            ))
    return alerts


def deadline_alerts(conn: sqlite3.Connection, settings: Settings) -> list[Alert]:
    """Critical and high findings that will probably miss their fix deadline."""
    from .forecast import forecast

    return [Alert(key=f"deadline:{f.finding_id}:{f.due}", cve="",
                  message=(f"Finding {f.finding_id} ({f.title}, {f.severity}) on {f.machine} is due {f.due} and "
                           f"will probably miss it. {f.reason}"))
            for f in forecast(conn, settings) if f.at_risk and f.severity in ("critical", "high")]


def _unsent(conn: sqlite3.Connection, alerts: list[Alert], channel: str) -> list[Alert]:
    sent = {r[0] for r in conn.execute("SELECT alert_key FROM alerts_sent WHERE channel = ?", (channel,))}
    return [a for a in alerts if a.key not in sent]


def _digest(alerts: list[Alert]) -> str:
    return f"vmtoolkit: {len(alerts)} new alert(s)\n\n" + "\n\n".join(f"- {a.message}" for a in alerts)


def send_console(alerts: list[Alert], log_path: Path, echo=print) -> None:
    text = _digest(alerts)
    echo(text)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(f"[{utcnow()}]\n{text}\n\n")


def send_slack(alerts: list[Alert], webhook_url: str) -> None:
    resp = requests.post(webhook_url, json={"text": _digest(alerts)}, timeout=30)
    if resp.status_code != 200:
        # The webhook URL is a secret, so it is left out of the error.
        raise RuntimeError(f"Slack webhook returned HTTP {resp.status_code}")


def send_email(alerts: list[Alert], cfg: dict, username: str | None, password: str | None) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"vmtoolkit: {len(alerts)} new vulnerability alert(s)"
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"]) if isinstance(cfg["to"], list) else cfg["to"]
    msg.set_content(_digest(alerts))
    port = int(cfg.get("port", 587))
    smtp_class = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
    with smtp_class(cfg["host"], port, timeout=30) as smtp:
        if port != 465 and cfg.get("starttls", True):
            smtp.starttls()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(msg)


def run_alerts(conn: sqlite3.Connection, settings: Settings, dry_run: bool = False, echo=print) -> list[str]:
    cfg = settings.section("alerts")
    channels = cfg.get("channels", ["console"])
    unknown = set(channels) - set(CHANNELS)
    if unknown:
        raise ConfigError(f"Unknown alert channel(s) {', '.join(sorted(unknown))}; use {', '.join(CHANNELS)}")

    alerts = find_alerts(conn, float(cfg.get("epss_jump", 0.10)))
    if cfg.get("deadline_warnings", True):
        alerts += deadline_alerts(conn, settings)
    # Spikes found by `vmt monitor` (run it before `vmt alert`).
    alerts += [Alert(key=f"chatter:{r['cve']}:{r['day']}", cve=r["cve"], message=r["explanation"])
               for r in conn.execute("SELECT * FROM chatter_spikes ORDER BY day, cve")]
    alerts += [Alert(key=key, cve="", message=message) for key, message in expiry_alerts(conn)]
    from .inventory import stale_alerts

    alerts += [Alert(key=key, cve="", message=message) for key, message in stale_alerts(conn, settings)]
    # Failed `vmt daily` runs from the last week; older ones would be stale news to a newly added channel.
    alerts += [Alert(key=f"daily-run:{r['id']}", cve="", message=r["message"])
               for r in conn.execute("""SELECT id, message FROM daily_runs WHERE status = 'failed'
                                        AND started_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-7 days')""")]
    lines = []
    for channel in channels:
        pending = _unsent(conn, alerts, channel)
        if not pending:
            lines.append(f"{channel}: no new alerts")
            continue
        if dry_run:
            lines.append(f"{channel}: would send {len(pending)} alert(s) (dry run)")
            lines += [f"  - {a.message}" for a in pending]
            continue
        try:
            if channel == "console":
                send_console(pending, settings.data_dir / "alerts.log", echo)
            elif channel == "slack":
                send_slack(pending, get_secret("SLACK_WEBHOOK_URL", required=True))
            elif channel == "email":
                send_email(pending, settings.section("email"), get_secret("SMTP_USERNAME"), get_secret("SMTP_PASSWORD"))
        except requests.RequestException as e:
            # requests errors include the URL path, which for Slack is the secret part of the webhook.
            lines.append(f"{channel}: failed ({type(e).__name__}); will retry next run")
            continue
        except (OSError, RuntimeError, smtplib.SMTPException) as e:
            # Not recorded as sent, so the next run tries this channel again.
            lines.append(f"{channel}: failed ({type(e).__name__}: {e}); will retry next run")
            continue
        with conn:
            conn.executemany(
                "INSERT INTO alerts_sent (alert_key, channel, sent_at, message) VALUES (?, ?, ?, ?)",
                [(a.key, channel, utcnow(), a.message) for a in pending],
            )
        lines.append(f"{channel}: sent {len(pending)} alert(s)")
    return lines
