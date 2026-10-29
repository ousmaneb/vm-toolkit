from datetime import datetime, timedelta, timezone

import pytest

from vmtoolkit import acceptance
from vmtoolkit.acceptance import accept, active_ids, expiry_alerts, listing, revoke
from vmtoolkit.config import ConfigError
from vmtoolkit.db import to_iso
from vmtoolkit.plan import plan
from vmtoolkit.report import build

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def day(offset: int) -> str:
    return (NOW + timedelta(days=offset)).strftime("%Y-%m-%d")


def add(conn, fid, severity, first_days_ago, package="fakepkg"):
    first = to_iso(NOW - timedelta(days=first_days_ago))
    conn.execute("INSERT OR IGNORE INTO assets (id, name, is_fake) VALUES (1, 'fake-web-01', 1)")
    conn.execute(
        """INSERT INTO findings (id, fingerprint, asset_id, scanner, rule_id, title, severity, status, package,
                                 fixed_version, first_seen, last_seen, is_fake)
           VALUES (?, ?, 1, 'trivy', ?, ?, ?, 'open', ?, '2.0', ?, ?, 1)""",
        (fid, f"fp{fid}", str(fid), f"FAKE {fid}", severity, package, first, first))
    conn.commit()


@pytest.fixture
def lab(conn):
    add(conn, 1, "critical", 40)            # 25 days past a 15-day deadline
    add(conn, 2, "high", 5, package="other")
    return conn


def test_acceptance_needs_reason_approver_and_a_sensible_date(lab, settings):
    with pytest.raises(ConfigError, match="reason and the name"):
        accept(lab, settings, [1], " ", "CISO", day(30), "alice")
    with pytest.raises(ConfigError, match="end in the future"):
        accept(lab, settings, [1], "isolated VLAN", "CISO", day(-1), "alice")
    with pytest.raises(ConfigError, match="at most 365 days"):
        accept(lab, settings, [1], "isolated VLAN", "CISO", day(400), "alice")
    with pytest.raises(ConfigError, match="doesn't exist"):
        accept(lab, settings, [999], "isolated VLAN", "CISO", day(30), "alice")


def test_accepted_findings_leave_deadlines_plans_and_tickets(lab, settings):
    from vmtoolkit.prioritize import prioritize

    prioritize(lab, settings)
    assert build(lab, settings).now.overdue == 1
    assert any(f.findings and f.findings[0]["id"] == 1 for f in plan(lab, settings)[0])

    lines = accept(lab, settings, [1], "on an isolated VLAN until the vendor patch", "CISO", day(30), "alice")
    assert lines[0].startswith("Accepted finding 1") and active_ids(lab) == {1}
    d = build(lab, settings)
    assert d.now.overdue == 0 and d.now.open == 2  # still open and visible, just not overdue
    assert d.accepted[0]["approved_by"] == "CISO"
    assert not any(any(item["id"] == 1 for item in f.findings) for f in plan(lab, settings)[0])


def test_acceptance_only_covers_the_days_it_was_active(lab, settings, monkeypatch):
    accept(lab, settings, [1], "isolated", "CISO", day(30), "alice")
    # Seen from a week ago, before the acceptance existed, the finding was overdue.
    assert build(lab, settings, now=NOW - timedelta(days=7)).now.overdue == 1
    # Seen from after it ends, it is overdue again (and by then the high finding is past its 30 days too).
    assert build(lab, settings, now=NOW + timedelta(days=31)).now.overdue == 2


def test_revoking_and_replacing(lab, settings):
    accept(lab, settings, [1], "isolated", "CISO", day(30), "alice")
    accept(lab, settings, [1], "still isolated", "CISO", day(60), "alice")  # replaces the first
    rows = listing(lab, include_ended=True)
    assert [r["state"] for r in rows] == ["revoked", "active"]
    assert revoke(lab, rows[1]["id"], "bob") and active_ids(lab) == set()
    assert not revoke(lab, rows[1]["id"], "bob")


def test_expiry_alerts(lab, settings, monkeypatch):
    accept(lab, settings, [1], "isolated", "CISO", day(3), "alice")
    [(key, message)] = expiry_alerts(lab)
    assert key.startswith("accept-expiring:") and "Fix it or have CISO renew" in message
    later = to_iso(NOW + timedelta(days=4))
    monkeypatch.setattr(acceptance, "utcnow", lambda: later)
    [(key, message)] = expiry_alerts(lab)
    assert key.startswith("accept-expired:") and "counts toward deadlines" in message
    # A month later it is old news and no longer alerts.
    much_later = to_iso(NOW + timedelta(days=40))
    monkeypatch.setattr(acceptance, "utcnow", lambda: much_later)
    assert expiry_alerts(lab) == []


def test_forecast_skips_accepted_findings(lab, settings):
    from vmtoolkit.forecast import forecast

    accept(lab, settings, [2], "test system", "CISO", day(30), "alice")
    assert 2 not in {f.finding_id for f in forecast(lab, settings)}


def test_dashboard_overdue_table_skips_accepted(lab, settings):
    pd = pytest.importorskip("pandas")  # noqa: F841
    from vmtoolkit.dashboard import metrics

    sla = {"critical": 15, "high": 30, "medium": 90, "low": 180}
    assert len(metrics.overdue(metrics.load_findings(lab), sla, NOW)) == 1
    accept(lab, settings, [1], "isolated", "CISO", day(30), "alice")
    assert len(metrics.overdue(metrics.load_findings(lab), sla, NOW)) == 0


def test_ticket_closes_with_the_reason_when_its_findings_are_accepted(lab, settings):
    from vmtoolkit.prioritize import prioritize
    from vmtoolkit.tickets import generate

    prioritize(lab, settings)
    generate(lab, settings)
    accept(lab, settings, [1], "isolated", "CISO", day(30), "alice")
    generate(lab, settings)
    notes = {r["status_note"] for r in lab.execute("SELECT status_note FROM tickets WHERE status = 'resolved'")}
    assert notes == {"its open findings are accepted risks (see vmt accept list)"}
