import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from vmtoolkit import db
from vmtoolkit.ask import Answer, QueryError, ask, load_eval, run_eval, run_readonly
from vmtoolkit.fakedata import generate


class FakeLLM:
    """Answers each question with a canned SQL query, and records the prompts it was sent."""

    def __init__(self, answer_for):
        self.answer_for, self.prompts = answer_for, []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        prompt = kwargs["messages"][0]["content"]
        self.prompts.append(prompt)
        payload = self.answer_for(prompt.rsplit("Question: ", 1)[1])
        return SimpleNamespace(stop_reason="end_turn", stop_details=None, model=kwargs["model"],
                               content=[SimpleNamespace(type="text", text=json.dumps(payload))],
                               usage=SimpleNamespace(input_tokens=2500, output_tokens=150))


@pytest.fixture(scope="module")
def fake_db(tmp_path_factory):
    folder = tmp_path_factory.mktemp("ask")
    path = folder / "fake.db"
    generate(path, folder / "vmt.db", machines=12, days=120, end=datetime.now(timezone.utc))
    return path


@pytest.mark.parametrize("sql", [
    "DELETE FROM findings",
    "UPDATE findings SET status = 'fixed'",
    "INSERT INTO notes (target, text, created_at) VALUES ('x', 'y', 'z')",
    "DROP TABLE findings",
    "WITH x AS (SELECT 1) DELETE FROM findings",
    "ATTACH DATABASE 'other.db' AS other",
    "PRAGMA writable_schema = 1",
    "SELECT 1; DELETE FROM findings",
    "SELECT load_extension('evil')",
])
def test_anything_but_reading_is_blocked(fake_db, sql):
    before = run_readonly(fake_db, "SELECT count(*) FROM findings")[1]
    with pytest.raises(QueryError):
        run_readonly(fake_db, sql)
    assert run_readonly(fake_db, "SELECT count(*) FROM findings")[1] == before


def test_semicolon_inside_a_string_is_fine(fake_db):
    assert run_readonly(fake_db, "SELECT 'a;b'")[1] == [("a;b",)]


def test_runaway_query_is_stopped(fake_db):
    with pytest.raises(QueryError, match="longer than"):
        run_readonly(fake_db, "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n) "
                              "SELECT count(*) FROM n", time_limit=0.3)


def test_row_limit(fake_db):
    columns, rows, truncated = run_readonly(fake_db, "SELECT id FROM findings", max_rows=5)
    assert columns == ["id"] and len(rows) == 5 and truncated


def test_every_reference_query_runs(fake_db):
    cases = load_eval()
    assert len(cases) == 20
    for case in cases:
        run_readonly(fake_db, case["sql"], max_rows=10_000)


def test_question_flow_redacts_and_never_sends_rows(fake_db, settings):
    import dataclasses

    s = dataclasses.replace(settings, db_override=fake_db)
    conn = db.connect(fake_db)
    title = conn.execute("SELECT title FROM findings LIMIT 1").fetchone()[0]
    llm = FakeLLM(lambda q: {
        "sql": "SELECT count(*) AS open_findings FROM findings f JOIN assets a ON a.id = f.asset_id "
               "WHERE a.name = 'MACHINE_1' AND f.status = 'open'",
        "explanation": "Counts open findings on MACHINE_1.", "cannot_answer": ""})
    answer = ask(conn, s, "How many open findings does fake-web-01 have?", api=llm)
    conn.close()
    prompt = llm.prompts[0]
    assert "Question: How many open findings does MACHINE_1 have?" in prompt
    assert "fake-web-01" not in prompt and title not in prompt and "CREATE TABLE findings" in prompt
    assert isinstance(answer, Answer)
    assert "a.name = 'fake-web-01'" in answer.sql and answer.explanation == "Counts open findings on fake-web-01."
    assert answer.columns == ["open_findings"] and answer.rows[0][0] > 0
    assert "What this query does: Counts open findings on fake-web-01." in answer.render()


def test_cannot_answer(fake_db, settings):
    conn = db.connect(fake_db)
    llm = FakeLLM(lambda q: {"sql": "", "explanation": "", "cannot_answer": "There is no cost data."})
    assert ask(conn, settings, "How much did patching cost?", api=llm) == \
        "Can't answer that from the database: There is no cost data."
    conn.close()


def test_eval_harness_scores_reference_answers_as_right(fake_db, settings):
    reference = {case["question"]: case["sql"] for case in load_eval()}

    def answer(question):
        # Echo the reference query back, with fake-web-01 swapped for its placeholder as the LLM would see it.
        q = question.replace("MACHINE_1", "fake-web-01")
        sql = reference[q].replace("'fake-web-01'", "'MACHINE_1'")
        return {"sql": sql, "explanation": "x", "cannot_answer": ""}

    lines = run_eval(settings, fake_db, api=FakeLLM(answer))
    assert lines[-1] == "20 of 20 questions answered correctly (100%)."


def test_eval_harness_catches_wrong_answers(fake_db, settings):
    lines = run_eval(settings, fake_db, api=FakeLLM(
        lambda q: {"sql": "SELECT 'nonsense'", "explanation": "x", "cannot_answer": ""}))
    assert lines[-1].startswith("0 of 20")
