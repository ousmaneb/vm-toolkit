import dataclasses
from datetime import datetime, timedelta, timezone

import responses

from vmtoolkit.alerts import run_alerts
from vmtoolkit.db import to_iso
from vmtoolkit.monitor import GITHUB_SEARCH, find_spikes, monitor, parse_feed
from vmtoolkit.normalize import Finding, Host, ScanResult, store_scan
from vmtoolkit.web import web_session

NOW = datetime(2099, 6, 1, 12, 0, tzinfo=timezone.utc)
FEED = "https://news.invalid/feed.xml"

RSS = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>FAKE news</title>
<item><title>FAKE: attackers exploit CVE-2099-0001 in FakeHTTPd</title><link>https://news.invalid/a</link>
<description>Synthetic story about CVE-2099-0001 and CVE-2099-5555.</description>
<pubDate>{(NOW - timedelta(hours=2)).strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate></item>
<item><title>FAKE: unrelated story</title><link>https://news.invalid/b</link><description>nothing</description></item>
</channel></rss>""".encode()

ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>FAKE</title>
<entry><title>FAKE CVE-2099-0002 write-up</title><link href="https://blog.invalid/x"/>
<summary>details</summary><published>2099-05-31T10:00:00Z</published></entry></feed>"""


def lab(conn):
    store_scan(conn, ScanResult("nessus", "fake", "1", "2099-05-01T00:00:00Z", hosts=[Host("fake-web-01", findings=[
        Finding("1", "FAKE hot", "critical", cves=["CVE-2099-0001"]),
        Finding("2", "FAKE quiet", "high", cves=["CVE-2099-0002"])])]))


def repos(n, hours_ago=1):
    return {"items": [{"html_url": f"https://github.com/fake/poc-{i}", "full_name": f"fake/poc-{i}",
                       "created_at": to_iso(NOW - timedelta(hours=hours_ago))} for i in range(n)]}


def test_parse_rss_and_atom():
    rss = parse_feed(RSS)
    assert rss[0]["link"] == "https://news.invalid/a" and "CVE-2099-5555" in rss[0]["summary"]
    atom = parse_feed(ATOM)
    assert atom == [{"title": "FAKE CVE-2099-0002 write-up", "link": "https://blog.invalid/x",
                     "summary": "details", "published": "2099-05-31T10:00:00Z"}]


@responses.activate
def test_burst_of_new_repos_is_a_spike_with_reason(conn, settings):
    lab(conn)
    responses.get(GITHUB_SEARCH.format(kind="repositories"), json=repos(5),
                  match=[responses.matchers.query_param_matcher({"q": '"CVE-2099-0001" created:>=2099-05-17',
                                                                 "per_page": "100", "sort": "updated"})])
    responses.get(GITHUB_SEARCH.format(kind="repositories"), json={"items": []})
    responses.get(GITHUB_SEARCH.format(kind="issues"), json={"items": []})
    responses.get(FEED, body=RSS)
    s = dataclasses.replace(settings, raw={**settings.raw, "monitor": {"feeds": {"FAKE news": FEED}}})
    sleeps = []
    lines = monitor(conn, s, web_session(s), now=NOW, sleep=sleeps.append)
    assert lines[0].startswith("GitHub: checked the top 2 of 2 open CVEs (no GITHUB_TOKEN")
    assert sleeps and set(sleeps) == {6.1}
    assert "News: read 1 feeds for all 2 open CVEs; 1 new mentions." in lines
    spike = next(line for line in lines if line.startswith("CVE-2099-0001"))
    assert "6 new mentions" in spike and "5 github repo" in spike and "1 news: FAKE news" in spike
    assert "average of 0.0 a day" in spike
    # Not one of your CVEs, so not stored.
    assert conn.execute("SELECT count(*) FROM mentions WHERE cve = 'CVE-2099-5555'").fetchone()[0] == 0


def test_steady_chatter_is_not_a_spike(conn):
    rows = [("CVE-2099-0001", "github repo", f"https://github.com/fake/{d}-{i}", "x",
             to_iso(NOW - timedelta(days=d, hours=1)), "x") for d in range(15) for i in range(4)]
    conn.executemany("INSERT INTO mentions VALUES (?, ?, ?, ?, ?, ?)", rows)
    assert find_spikes(conn, NOW) == []


def test_two_mentions_are_too_few(conn):
    conn.executemany("INSERT INTO mentions VALUES (?, ?, ?, ?, ?, ?)",
                     [("CVE-2099-0001", "github repo", f"u{i}", "x", to_iso(NOW - timedelta(hours=1)), "x")
                      for i in range(2)])
    assert find_spikes(conn, NOW) == []


@responses.activate
def test_rate_limit_stops_cleanly_and_token_is_sent(conn, settings, monkeypatch):
    lab(conn)
    monkeypatch.setenv("GITHUB_TOKEN", "fake-gh-token")
    responses.get(GITHUB_SEARCH.format(kind="repositories"), status=403)
    s = dataclasses.replace(settings, raw={**settings.raw, "monitor": {"feeds": {}}})
    lines = monitor(conn, s, web_session(s), now=NOW, sleep=lambda x: None)
    assert any("rate limit hit at CVE-2099-0001" in line for line in lines)
    assert responses.calls[0].request.headers["Authorization"] == "Bearer fake-gh-token"
    assert b"fake-gh-token" not in s.cache_path.read_bytes()


def test_spikes_flow_into_alerts(conn, settings):
    lab(conn)
    conn.execute("INSERT INTO chatter_spikes VALUES ('CVE-2099-0001', '2099-06-01', 6, 'FAKE spike explanation')")
    conn.commit()
    printed = []
    run_alerts(conn, settings, echo=printed.append)
    assert "FAKE spike explanation" in printed[0]
