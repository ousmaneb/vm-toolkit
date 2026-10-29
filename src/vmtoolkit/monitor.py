"""Watch GitHub and security news feeds for mentions of your CVEs, and flag when mentions spike.

New GitHub repositories naming a CVE are often proof-of-concept exploits, so a burst of them is an
early warning that exploitation is getting easier. Only CVE IDs are sent anywhere.
"""

import math
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import requests
from defusedxml import ElementTree

from .config import Settings, get_secret
from .db import TIME_FORMAT, utcnow
from .web import WebError, fetch

GITHUB_SEARCH = "https://api.github.com/search/{kind}"
DEFAULT_FEEDS = {
    "CISA advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "SANS ISC": "https://isc.sans.edu/rssfeed_full.xml",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
BASELINE_DAYS = 14
SPIKE_MIN = 3
SPIKE_SIGMAS = 3.0


@dataclass
class Spike:
    cve: str
    day: str
    count: int
    mean: float
    std: float
    by_source: dict[str, int]

    def explain(self) -> str:
        sources = ", ".join(f"{n} {src}" for src, n in sorted(self.by_source.items(), key=lambda kv: -kv[1]))
        return (f"{self.cve}: {self.count} new mentions in the 24 hours to {self.day} ({sources}), against an average of "
                f"{self.mean:.1f} a day over the previous {BASELINE_DAYS} days. That is at least {SPIKE_MIN} and "
                f"more than {SPIKE_SIGMAS:g} standard deviations above normal, so attention on it is rising.")


def watched_cves(conn: sqlite3.Connection, limit: int) -> list[str]:
    """Open CVEs, highest priority first (or most severe, before `vmt prioritize` has run)."""
    rows = conn.execute(
        """SELECT fc.cve, max(coalesce(p.score, 0)) AS score,
                  max(CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) AS sev
           FROM finding_cves fc JOIN findings f ON f.id = fc.finding_id
           LEFT JOIN priorities p ON p.finding_id = f.id
           WHERE f.status = 'open' AND f.id NOT IN (SELECT finding_id FROM fp_labels WHERE label = 'false_positive')
           GROUP BY fc.cve ORDER BY score DESC, sev DESC, fc.cve"""
    ).fetchall()
    return [r["cve"] for r in rows][:limit]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(TIME_FORMAT)


def _store(conn: sqlite3.Connection, mentions: list[tuple]) -> int:
    before = conn.total_changes
    conn.executemany(
        "INSERT OR IGNORE INTO mentions (cve, source, item, title, published, first_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
        mentions)
    conn.commit()
    return conn.total_changes - before


def search_github(conn: sqlite3.Connection, session: requests.Session, cves: list[str], now: datetime,
                  token: str | None, sleep=time.sleep) -> tuple[int, list[str]]:
    since = (now - timedelta(days=BASELINE_DAYS + 1)).strftime("%Y-%m-%d")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    # GitHub allows 10 search requests a minute without a token and 30 with one.
    delay = 2.1 if token else 6.1
    new, problems = 0, []
    for cve in cves:
        for kind, source, query in (("repositories", "github repo", f'"{cve}" created:>={since}'),
                                    ("issues", "github issue/PR", f'"{cve}" created:>={since}')):
            resp = fetch(session, "GET", GITHUB_SEARCH.format(kind=kind), headers=headers,
                         params={"q": query, "per_page": 100, "sort": "updated"})
            if resp.status_code in (403, 429):
                problems.append(f"GitHub rate limit hit at {cve}; the rest are checked next run.")
                return new, problems
            if resp.status_code != 200:
                problems.append(f"GitHub search for {cve} returned HTTP {resp.status_code}.")
                continue
            items = resp.json().get("items", [])
            new += _store(conn, [(cve, source, item["html_url"], (item.get("full_name") or item.get("title") or "")[:200],
                                  _iso(datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))), utcnow())
                                 for item in items])
            if not getattr(resp, "from_cache", False):
                sleep(delay)
    return new, problems


def _text(el, *tags) -> str:
    for tag in tags:
        found = el.find(tag)
        if found is not None:
            return (found.text or found.get("href") or "").strip()
    return ""


def parse_feed(xml: bytes) -> list[dict]:
    """RSS 2.0 or Atom -> [{title, link, summary, published}]."""
    root = ElementTree.fromstring(xml)
    atom = "{http://www.w3.org/2005/Atom}"
    out = []
    for item in root.iter("item"):
        out.append({"title": _text(item, "title"), "link": _text(item, "link", "guid"),
                    "summary": _text(item, "description", "{http://purl.org/rss/1.0/modules/content/}encoded"),
                    "published": _text(item, "pubDate", "{http://purl.org/dc/elements/1.1/}date")})
    for entry in root.iter(f"{atom}entry"):
        link = entry.find(f"{atom}link")
        out.append({"title": _text(entry, f"{atom}title"), "link": link.get("href", "") if link is not None else "",
                    "summary": _text(entry, f"{atom}summary", f"{atom}content"),
                    "published": _text(entry, f"{atom}published", f"{atom}updated")})
    return out


def _parse_date(value: str, fallback: datetime) -> datetime:
    if not value:
        return fallback
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return fallback
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def scan_feeds(conn: sqlite3.Connection, session: requests.Session, feeds: dict[str, str], cves: set[str],
               now: datetime) -> tuple[int, list[str]]:
    new, problems = 0, []
    for name, url in feeds.items():
        try:
            resp = fetch(session, "GET", url)
        except WebError as e:
            problems.append(f"{name}: {e}")
            continue
        if resp.status_code != 200:
            problems.append(f"{name}: HTTP {resp.status_code}")
            continue
        try:
            items = parse_feed(resp.content)
        except ElementTree.ParseError:
            problems.append(f"{name}: not a valid RSS or Atom feed")
            continue
        rows = []
        for item in items:
            mentioned = {c.upper() for c in CVE_RE.findall(f"{item['title']} {item['summary']}")} & cves
            published = _iso(_parse_date(item["published"], now))
            rows += [(cve, f"news: {name}", item["link"], item["title"][:200], published, utcnow()) for cve in mentioned]
        new += _store(conn, rows)
    return new, problems


def find_spikes(conn: sqlite3.Connection, now: datetime) -> list[Spike]:
    """Compare the last 24 hours with each of the previous 14 24-hour windows, per CVE."""
    edges = [_iso(now - timedelta(days=d)) for d in range(BASELINE_DAYS + 2)]  # edges[0] is now
    counts: dict[str, list[int]] = {}
    sources: dict[str, dict[str, int]] = {}
    for r in conn.execute("SELECT cve, source, published FROM mentions WHERE published >= ? AND published <= ?",
                          (edges[-1], edges[0])):
        window = next(i for i in range(BASELINE_DAYS + 1) if r["published"] >= edges[i + 1])
        counts.setdefault(r["cve"], [0] * (BASELINE_DAYS + 1))[window] += 1
        if window == 0:
            sources.setdefault(r["cve"], {}).setdefault(r["source"], 0)
            sources[r["cve"]][r["source"]] += 1
    spikes = []
    for cve, windows in counts.items():
        current, history = windows[0], windows[1:]
        mean = sum(history) / len(history)
        std = math.sqrt(sum((h - mean) ** 2 for h in history) / len(history))
        if current >= SPIKE_MIN and current > mean + SPIKE_SIGMAS * std:
            spikes.append(Spike(cve, now.strftime("%Y-%m-%d"), current, mean, std, sources.get(cve, {})))
    return sorted(spikes, key=lambda s: -s.count)


def monitor(conn: sqlite3.Connection, settings: Settings, session: requests.Session, now: datetime | None = None,
            sleep=time.sleep) -> list[str]:
    now = now or datetime.now(timezone.utc)
    cfg = settings.section("monitor")
    limit = int(cfg.get("max_cves", 50))
    cves = watched_cves(conn, limit=10_000)
    if not cves:
        return ["No open CVEs to watch."]
    lines, problems = [], []
    if cfg.get("github", True):
        token = get_secret("GITHUB_TOKEN")
        new, issues = search_github(conn, session, cves[:limit], now, token, sleep)
        problems += issues
        lines.append(f"GitHub: checked the top {min(limit, len(cves))} of {len(cves)} open CVEs"
                     f"{'' if token else ' (no GITHUB_TOKEN, so at 10 searches a minute)'}; {new} new mentions.")
    feeds = cfg.get("feeds", DEFAULT_FEEDS)
    new, issues = scan_feeds(conn, session, feeds, set(cves), now)
    problems += issues
    lines.append(f"News: read {len(feeds)} feeds for all {len(cves)} open CVEs; {new} new mentions.")
    spikes = find_spikes(conn, now)
    with conn:
        conn.executemany("INSERT OR IGNORE INTO chatter_spikes (cve, day, count, explanation) VALUES (?, ?, ?, ?)",
                         [(s.cve, s.day, s.count, s.explain()) for s in spikes])
    lines += [s.explain() for s in spikes] or ["No spikes today."]
    return lines + problems
