"""Turn a plain-English question into one read-only SQL query, run it locally, and show the answer.

The LLM only sees the database layout and your question (with machine names replaced by
placeholders); it never sees any rows. The query runs on a read-only connection with an
authorizer that only allows reading, so even a bad query can't change anything.
"""

import json
import re
import sqlite3
import time
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from .config import Settings
from .privacy import Redactor

MAX_ROWS = 200
TIME_LIMIT = 10.0
CONVENTIONS = """Conventions:
- Timestamps are UTC ISO strings like '2026-10-01T12:00:00Z'; compare with julianday(), e.g.
  julianday('now') - julianday(first_seen) > 30 for "older than 30 days".
- findings.severity is one of critical, high, medium, low, info. findings.status is 'open' or 'fixed'.
- A finding's CVEs are in finding_cves; join on finding_cves.finding_id = findings.id.
- "Known exploited" means the CVE is in the kev table (join kev.cve = finding_cves.cve).
- Leave out findings the user marked as false positives unless asked:
  findings.id NOT IN (SELECT finding_id FROM fp_labels WHERE label = 'false_positive').
- Leave out findings that duplicate another scanner's report unless asked:
  findings.id NOT IN (SELECT finding_id FROM duplicates).
- Machines are in assets (name, ip); findings.asset_id = assets.id.
- The latest EPSS score of a CVE is the row in epss_history with the greatest date for that CVE.
- Placeholders such as MACHINE_1 or IP_1 stand for real machine names and IP addresses; use them as
  string literals exactly as written (e.g. assets.name = 'MACHINE_1') and they will be filled in."""
SYSTEM = ("You turn questions about an organization's vulnerability database into one SQLite SELECT statement. "
          "Only read: never write, attach, or change settings. Use only tables and columns in the schema. If "
          "the question can't be answered from this data, say why in cannot_answer and leave sql empty. "
          "In explanation, describe in one or two plain sentences what the query returns, so a non-expert can "
          "check it matches what they meant.")
SCHEMA = {
    "type": "object",
    "properties": {"sql": {"type": "string"}, "explanation": {"type": "string"},
                   "cannot_answer": {"type": "string"}},
    "required": ["sql", "explanation", "cannot_answer"], "additionalProperties": False,
}
# Tables that hold bulky text or bookkeeping a question never needs.
HIDDEN_TABLES = {"advisories", "triage_results", "alerts_sent"}
ALLOWED_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}
BLOCKED_FUNCTIONS = {"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer"}


class QueryError(Exception):
    pass


@dataclass
class Answer:
    question: str
    sql: str
    explanation: str
    columns: list[str]
    rows: list[tuple]
    truncated: bool

    def render(self) -> str:
        lines = [f"What this query does: {self.explanation}", "", self.sql, ""]
        if not self.rows:
            return "\n".join(lines + ["No rows matched."])
        widths = [max(len(str(c)), *(len(str(r[i])) for r in self.rows)) for i, c in enumerate(self.columns)]
        widths = [min(w, 50) for w in widths]
        lines.append("  ".join(str(c)[:50].ljust(w) for c, w in zip(self.columns, widths)))
        lines.append("  ".join("-" * w for w in widths))
        for row in self.rows:
            lines.append("  ".join(str(v if v is not None else "")[:50].ljust(w) for v, w in zip(row, widths)))
        lines.append(f"\n{len(self.rows)} row(s)" + (f", stopped at {MAX_ROWS}" if self.truncated else "") + ".")
        return "\n".join(lines)


def schema_text(conn: sqlite3.Connection) -> str:
    rows = conn.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table' AND sql IS NOT NULL ORDER BY name")
    return "\n\n".join(r["sql"] for r in rows if r["name"] not in HIDDEN_TABLES)


def _authorizer(action, arg1, arg2, db_name, trigger):
    if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in BLOCKED_FUNCTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK if action in ALLOWED_ACTIONS else sqlite3.SQLITE_DENY


def run_readonly(path: Path, sql: str, max_rows: int = MAX_ROWS, time_limit: float = TIME_LIMIT):
    sql = sql.strip().rstrip(";").strip()
    if not re.match(r"(?is)^(with|select)\b", sql):
        raise QueryError("Only SELECT queries are allowed.")
    if ";" in re.sub(r"'(?:[^']|'')*'", "''", sql):
        raise QueryError("Only one statement is allowed.")
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        conn.set_authorizer(_authorizer)
        deadline = time.monotonic() + time_limit
        conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
        try:
            cur = conn.execute(sql)
            rows = cur.fetchmany(max_rows + 1)
        except sqlite3.DatabaseError as e:
            if "interrupted" in str(e):
                raise QueryError(f"The query took longer than {time_limit:g} seconds and was stopped.") from None
            if "not authorized" in str(e):
                raise QueryError("The query tried to do something other than read, and was blocked.") from None
            raise QueryError(f"SQLite rejected the query: {e}") from None
        columns = [d[0] for d in cur.description or []]
    finally:
        conn.close()
    return columns, rows[:max_rows], len(rows) > max_rows


def ask(conn: sqlite3.Connection, settings: Settings, question: str, api=None) -> Answer | str:
    from .llm import client, create_json, options

    redactor = Redactor(conn, enabled=not options(settings)["send_hostnames"])
    prompt = f"{schema_text(conn)}\n\n{CONVENTIONS}\n\nQuestion: {redactor.redact(question)}"
    data, resp = create_json(api or client(settings), settings, SCHEMA, max_tokens=4000, system=SYSTEM,
                             messages=[{"role": "user", "content": prompt}])
    if data["cannot_answer"] and not data["sql"]:
        return f"Can't answer that from the database: {data['cannot_answer']}"
    sql = redactor.restore(data["sql"])
    columns, rows, truncated = run_readonly(settings.db_path, sql)
    return Answer(question, sql, redactor.restore(data["explanation"]), columns, rows, truncated)


def load_eval() -> list[dict]:
    return json.loads((resources.files("vmtoolkit") / "templates" / "ask_eval.json").read_text(encoding="utf-8"))


def _matches(expected: set, answer: "Answer") -> bool:
    """Right if any column of the answer holds exactly the expected values (column choice may differ)."""
    columns = list(zip(*answer.rows)) if answer.rows else []
    if not expected:
        return not answer.rows
    return any(set(col) == expected for col in columns)


def run_eval(settings: Settings, path: Path, api=None) -> list[str]:
    """Ask every question in the eval set against `path` and compare with the reference query's answer."""
    import dataclasses

    from .llm import client

    api = api or client(settings)
    settings = dataclasses.replace(settings, db_override=path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    lines, right = [], 0
    try:
        for case in load_eval():
            expected = {row[0] for row in run_readonly(path, case["sql"], max_rows=10_000)[1]}
            try:
                answer = ask(conn, settings, case["question"], api=api)
                ok = isinstance(answer, Answer) and _matches(expected, answer)
                problem = "" if isinstance(answer, Answer) else f" ({answer})"
            except QueryError as e:
                ok, problem = False, f" ({e})"
            right += ok
            lines.append(f"{'PASS' if ok else 'FAIL'}  {case['question']}{'' if ok else problem}")
    finally:
        conn.close()
    return lines + [f"{right} of {len(lines)} questions answered correctly ({right / len(lines):.0%})."]
