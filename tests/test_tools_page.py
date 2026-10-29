import sys
from pathlib import Path

import pytest

pytest.importorskip("streamlit")

from vmtoolkit.dashboard import tools, tools_page  # noqa: E402
from vmtoolkit.fakedata import generate  # noqa: E402

# Renders one tool's page on its own, with the config, database and tool passed in by the test.
PAGE = """
import sys
from pathlib import Path
from vmtoolkit.config import load_settings
from vmtoolkit.dashboard import tools_page
config, db, key = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
settings = load_settings(Path(config), db=db)
if key == "setup":
    tools_page.render_setup(settings)
elif key == "history":
    from vmtoolkit.dashboard import history_page
    history_page.render(settings, db, offline=False)
elif key in ("reports", "automation"):
    from vmtoolkit.dashboard import reports_page
    getattr(reports_page, "render_" + key)(settings, db, offline=False)
else:
    tools_page.render_tool(next(t for t in tools_page.TOOLS if t.key == key), settings, db, offline=False)
"""


@pytest.fixture
def page(settings, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    # The Automation page asks the real scheduler otherwise.
    monkeypatch.setattr("vmtoolkit.schedule.status", lambda: "Not installed.")
    db_path = settings.data_dir / "fake.db"
    generate(db_path, settings.db_path, machines=3, days=30)

    def open_page(key):
        monkeypatch.setattr("sys.argv", ["page", str(settings.base_dir / "config.toml"), str(db_path), key])
        return testing.AppTest.from_string(PAGE, default_timeout=60).run()
    return open_page


def test_save_upload_keeps_only_the_file_name(tmp_path):
    assert tools.save_upload(tmp_path, "../../etc/requirements.txt", b"x") == tmp_path / "requirements.txt"
    assert tools.save_upload(tmp_path, "..", b"x") == tmp_path / "upload"


def test_secret_status_shows_names_not_values(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "sk-test-value")
    status = dict(tools.secret_status())
    assert status["LLM features: extract --llm, triage, ask"] == {"LLM_API_KEY": True}
    assert status["Slack alerts"] == {"SLACK_WEBHOOK_URL": False}
    assert "sk-test-value" not in repr(status)


def test_database_choices_lists_each_file_once(settings):
    settings.data_dir.mkdir()
    (settings.data_dir / "fake.db").touch()
    (settings.data_dir / "vmt.db").touch()
    choices = tools.database_choices(settings, settings.data_dir / "fake.db")
    assert [p.name for p in choices] == ["fake.db", "vmt.db"]


def test_base_command_runs_this_python_with_the_chosen_database(settings, tmp_path):
    cmd = tools.base_command(settings, tmp_path / "x.db", offline=True)
    assert cmd[:3] == [sys.executable, "-m", "vmtoolkit"]
    assert cmd[3:] == ["--config", str(settings.base_dir / "config.toml"), "--db", str(tmp_path / "x.db"), "--offline"]


def test_run_streams_output_and_returns_exit_code(tmp_path):
    lines = []
    code = tools.run([sys.executable, "-c", "print('one'); print('two'); raise SystemExit(3)"], tmp_path, lines.append)
    assert lines == ["one\n", "two\n"] and code == 3


def test_page_runs_a_tool_and_shows_its_output(page):
    at = page("dedupe")
    assert at.title[0].value == "Find duplicates"
    assert at.code[0].value.startswith("vmt --db ") and at.code[0].value.endswith(" dedupe")
    at.button[0].click().run()
    assert not at.exception
    assert at.success[0].value.startswith("Finished in")
    assert "duplicates of another scanner's report" in at.code[-1].value


def test_paid_and_outward_actions_need_a_tick(page):
    at = page("ask")
    at.text_area[0].input("how many open findings?").run()
    assert at.button[0].disabled
    at.checkbox[0].check().run()
    assert not at.button[0].disabled


def test_triage_defaults_to_the_free_prompt_preview(page):
    at = page("triage")
    at.text_input[0].input("CVE-2099-0001").run()
    assert at.code[0].value.endswith("triage CVE-2099-0001 --show-prompt")
    assert not at.button[0].disabled


def test_run_is_disabled_until_required_fields_are_filled(page):
    at = page("cve")
    assert at.button[0].disabled
    at.text_input[0].input("CVE-2099-0001").run()
    assert not at.button[0].disabled


@pytest.mark.parametrize("key", [t.key for t in tools_page.TOOLS] + ["setup", "reports", "automation", "history"])
def test_every_page_renders(page, key):
    assert not page(key).exception


def test_reports_page_lists_saved_reports(page, settings):
    folder = settings.data_dir / "reports"
    folder.mkdir(parents=True)
    for name in ("2099-03-02-fake-ceo.pdf", "2099-03-02-fake-ciso.pdf", "2099-03-02-fake-ceo-30d.pdf",
                 "2099-03-02-ceo.pdf"):
        (folder / name).write_bytes(b"%PDF-1.4")
    at = page("reports")
    labels = [m.value for m in at.markdown]
    assert "**Week ending 2099-03-02**" in labels and "**30 days ending 2099-03-02**" in labels
    # This database's three reports, not the main database's.
    assert len(at.get("download_button")) == 3


def test_reports_page_creates_and_offers_a_report(page):
    pytest.importorskip("reportlab")
    at = page("reports")
    next(b for b in at.button if b.label == "Create report").click().run()
    assert not at.exception
    assert at.success[0].value.startswith("Ready")
    assert len(at.get("download_button")) >= 2


def test_schedule_install_needs_a_tick(page):
    at = page("automation")
    install = next(b for b in at.button if b.label == "Install schedule")
    assert install.disabled


def test_history_page_rebuilds_and_looks_back(page, settings):
    from vmtoolkit import db
    from vmtoolkit.history import backfill, save_snapshot
    from vmtoolkit.plan import plan

    conn = db.connect(settings.data_dir / "fake.db")
    plan(conn, settings)  # also saves today's ranking
    backfill(conn, type(settings)(raw=settings.raw, base_dir=settings.base_dir,
                                  db_override=settings.data_dir / "fake.db"), 30)
    save_snapshot(conn, settings)
    conn.close()
    at = page("history")
    assert not at.exception
    assert [m.label for m in at.metric] == ["Open", "Critical or high", "Past deadline", "Actively exploited"]
    assert len(at.dataframe) == 3  # top risks, plan, all days
    assert at.get("download_button")[0].label == "Download history as CSV"
