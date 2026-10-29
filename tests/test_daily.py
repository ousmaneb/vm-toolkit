import plistlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vmtoolkit import schedule
from vmtoolkit.alerts import run_alerts
from vmtoolkit.config import ConfigError
from vmtoolkit.daily import report_due, run_daily

MONDAY = datetime(2099, 3, 2, 7, 0, tzinfo=timezone.utc)
TUESDAY = datetime(2099, 3, 3, 7, 0, tzinfo=timezone.utc)


class FakeVmt:
    """Stands in for running `vmt <args>`; fails any command whose first words are in `fail`."""

    def __init__(self, fail=()):
        self.calls, self.fail = [], set(fail)

    def __call__(self, args):
        self.calls.append(" ".join(args))
        if " ".join(args[:2]) in self.fail or args[0] in self.fail:
            return 1, "Error: No Nessus credentials found.\n"
        if args[0] == "report":
            return 0, "CEO report: /r/2099-03-02-ceo.pdf\nCISO report: /r/2099-03-02-ciso.pdf\nStatus GREEN: fine\n"
        return 0, "ok\n"


def test_full_run_on_report_day(conn, settings):
    vmt = FakeVmt()
    assert run_daily(conn, settings, run=vmt, now=MONDAY, echo=lambda *_: None) == "ok"
    assert vmt.calls == ["nessus pull", "enrich", "dedupe", "prioritize --top 10", "plan",
                         "forecast --backtest-days 0", "history save", "monitor", "backup", "alert --no-refresh",
                         "report"]
    row = conn.execute("SELECT * FROM daily_runs").fetchone()
    assert (row["status"], row["reports"]) == ("ok", "/r/2099-03-02-ceo.pdf, /r/2099-03-02-ciso.pdf")
    assert "=== exit code 0" in Path(row["log_path"]).read_text(encoding="utf-8")


def test_nessus_failure_stops_processing_and_alerts(conn, settings):
    vmt = FakeVmt(fail={"nessus pull"})
    assert run_daily(conn, settings, run=vmt, now=MONDAY, echo=lambda *_: None) == "failed"
    # The backup and the alert still run: one protects the existing data, the other carries the failure
    # notice. No report from stale data.
    assert vmt.calls == ["nessus pull", "backup", "alert --no-refresh"]
    row = conn.execute("SELECT * FROM daily_runs").fetchone()
    assert row["failed_steps"] == "Pull from Nessus" and "Nothing was refreshed" in row["message"]
    lines = run_alerts(conn, settings, dry_run=True)
    assert any("automatic daily run on 2099-03-02 had problems" in line for line in lines)


def test_other_failures_still_run_the_rest_but_skip_the_report(conn, settings):
    vmt = FakeVmt(fail={"enrich"})
    assert run_daily(conn, settings, run=vmt, now=MONDAY, echo=lambda *_: None) == "failed"
    assert "plan" in vmt.calls and "alert --no-refresh" in vmt.calls and "report" not in vmt.calls


def test_settings_turn_steps_off(conn, settings):
    settings.raw["daily"] = {"nessus": False, "monitor": False}
    vmt = FakeVmt()
    run_daily(conn, settings, run=vmt, now=TUESDAY, echo=lambda *_: None)
    assert "nessus pull" not in vmt.calls and "monitor" not in vmt.calls


def test_report_due_on_weekday_or_when_a_week_old(settings):
    assert report_due(settings, MONDAY)
    assert report_due(settings, TUESDAY)  # no report yet
    reports = settings.data_dir / "reports"
    reports.mkdir(parents=True)
    (reports / "2099-03-02-ceo.pdf").touch()
    (reports / "2099-03-02-fake-ceo.pdf").touch()
    assert not report_due(settings, TUESDAY)
    (reports / "2099-03-02-ceo.pdf").unlink()
    assert report_due(settings, TUESDAY)  # only the demo database's report exists


def test_schedule_files(tmp_path):
    cmd = ["/venv/bin/python", "-m", "vmtoolkit", "--config", "/lab/config.toml", "daily"]
    plist = plistlib.loads(schedule.launchd_plist(cmd, 7, 30, tmp_path / "s.log", Path("/lab")))
    assert plist["ProgramArguments"] == cmd and plist["StartCalendarInterval"] == {"Hour": 7, "Minute": 30}
    assert schedule.cron_line(cmd, 7, 30, Path("/lab/s.log")).startswith("30 7 * * * '/venv/bin/python' '-m'")
    assert schedule.windows_script(cmd, Path("C:/lab/s.log")).startswith('@echo off\r\n"/venv/bin/python" "-m"')


@pytest.mark.parametrize("text", ["7", "25:00", "07:61", "seven"])
def test_schedule_time_is_checked(text):
    with pytest.raises(ConfigError):
        schedule.parse_time(text)
