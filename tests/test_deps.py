import json

import responses
from typer.testing import CliRunner

from vmtoolkit import deps
from vmtoolkit.cli import app
from vmtoolkit.normalize import store_scan
from vmtoolkit.web import web_session

# Package names are made up so these tests can never match a real advisory.
FAKE_VULN = {
    "id": "GHSA-fake-aaaa-0001",
    "summary": "FAKE remote code execution in fakepkg.",
    "aliases": ["CVE-2099-3001"],
    "database_specific": {"severity": "MODERATE"},
    "affected": [{"package": {"name": "fakepkg", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [
                      {"introduced": "0"}, {"fixed": "1.2.5"}, {"introduced": "2.0"}, {"fixed": "2.0.3"}]}]}],
}


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_requirements_parsing(tmp_path):
    write(tmp_path / "base.txt", "fakebase==0.1\n")
    req = write(tmp_path / "requirements.txt", "\n".join([
        "# comment",
        "-r base.txt",
        "--index-url https://example.invalid/simple",
        "fakepkg==1.2.3  # pinned",
        "fake-extra[socks]>=2.0,<3",
        "fakewild==1.4.*",
        "fakebare",
        "fakemarker==3.0; python_version >= '3.8'",
        "git+https://example.invalid/repo.git",
    ]))
    report = deps.parse_requirements(req)
    got = {d.name: (d.version, d.exact) for d in report.deps}
    assert got == {"fakebase": ("0.1", True), "fakepkg": ("1.2.3", True), "fake-extra": ("2.0", False),
                   "fakewild": ("1.4", False), "fakemarker": ("3.0", True)}
    assert any("fakebare" in s for s in report.skipped)
    assert any("git+" in s for s in report.skipped)


def test_requirements_include_loop_is_safe(tmp_path):
    write(tmp_path / "a.txt", "-r b.txt\nfakea==1.0\n")
    write(tmp_path / "b.txt", "-r a.txt\nfakeb==1.0\n")
    assert {d.name for d in deps.parse_requirements(tmp_path / "a.txt").deps} == {"fakea", "fakeb"}


def test_package_json_ranges(tmp_path):
    pkg = write(tmp_path / "package.json", json.dumps({
        "dependencies": {"fake-exact": "1.2.3", "fake-caret": "^4.17.0", "fake-git": "git+https://x/y.git"},
        "devDependencies": {"fake-tilde": "~0.5.1", "fake-latest": "latest"},
    }))
    report = deps.parse_package_json(pkg)
    got = {d.name: (d.version, d.exact) for d in report.deps}
    assert got == {"fake-exact": ("1.2.3", True), "fake-caret": ("4.17.0", False), "fake-tilde": ("0.5.1", False)}
    assert len(report.skipped) == 2


def test_package_lock_v1_and_v3(tmp_path):
    v3 = write(tmp_path / "v3" / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "root"},
        "node_modules/fake-a": {"version": "1.0.0"},
        "node_modules/fake-a/node_modules/fake-b": {"version": "2.0.0"},
        "node_modules/fake-c": {"version": "1.0.0"},
        "node_modules/fake-x/node_modules/fake-c": {"version": "1.0.0"},
        "node_modules/local": {"link": True},
    }}))
    assert sorted((d.name, d.version) for d in deps.parse_package_lock(v3).deps) == [
        ("fake-a", "1.0.0"), ("fake-b", "2.0.0"), ("fake-c", "1.0.0")]
    v1 = write(tmp_path / "v1" / "package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
        "fake-a": {"version": "1.0.0", "dependencies": {"fake-b": {"version": "2.0.0"}}}}}))
    assert {d.name for d in deps.parse_package_lock(v1).deps} == {"fake-a", "fake-b"}


def test_folder_scan_prefers_lockfile_and_skips_node_modules(tmp_path):
    write(tmp_path / "web" / "package.json", '{"dependencies": {"fake-a": "^1.0.0"}}')
    write(tmp_path / "web" / "package-lock.json", '{"packages": {"node_modules/fake-a": {"version": "1.0.4"}}}')
    write(tmp_path / "web" / "node_modules" / "x" / "package.json", '{"dependencies": {"fake-z": "1.0.0"}}')
    write(tmp_path / "api" / "requirements-dev.txt", "fakepkg==1.2.3\n")
    reports = deps.parse_files([tmp_path])
    names = sorted(str(r.path.relative_to(tmp_path)).replace("\\", "/") for r in reports)
    assert names == ["api/requirements-dev.txt", "web/package-lock.json", "web/package.json"]
    note = next(r for r in reports if r.path.name == "package.json")
    assert "package-lock.json" in note.note and not note.deps


@responses.activate
def test_osv_check_picks_next_fixed_version(settings):
    responses.post(deps.QUERYBATCH_URL, json={"results": [{"vulns": [{"id": "GHSA-fake-aaaa-0001"}]}, {}]})
    responses.get(deps.VULN_URL.format("GHSA-fake-aaaa-0001"), json=FAKE_VULN)
    dep_list = [deps.Dependency("fakepkg", "PyPI", "2.0.1", "==2.0.1", True, settings.base_dir / "r.txt"),
                deps.Dependency("fakesafe", "PyPI", "1.0", "==1.0", True, settings.base_dir / "r.txt")]
    found = deps.check(web_session(settings), dep_list)
    assert list(found) == [0]
    v = found[0][0]
    assert (v.severity, v.cves, v.fixed) == ("medium", ["CVE-2099-3001"], "2.0.3")
    body = json.loads(responses.calls[0].request.body)
    assert body["queries"][0] == {"package": {"name": "fakepkg", "ecosystem": "PyPI"}, "version": "2.0.1"}


@responses.activate
def test_cli_report_and_save(settings, tmp_path):
    responses.post(deps.QUERYBATCH_URL, json={"results": [{"vulns": [{"id": "GHSA-fake-aaaa-0001"}]}]})
    responses.get(deps.VULN_URL.format("GHSA-fake-aaaa-0001"), json=FAKE_VULN)
    project = tmp_path / "fakeproj"
    write(project / "requirements.txt", "fakepkg>=1.0\n")
    result = CliRunner().invoke(app, ["--config", str(settings.base_dir / "config.toml"), "deps", str(project), "--save"])
    assert result.exit_code == 0, result.output
    assert "1 packages checked (0 exact, 1 ranges)" in result.output
    assert "  fakepkg >=1.0 (a range, not an exact version: checked the lowest allowed version 1.0" in result.output
    assert ("    MEDIUM   GHSA-fake-aaaa-0001 (CVE-2099-3001) FAKE remote code execution in fakepkg. "
            "Fixed in 1.2.5.") in result.output
    assert "osv dependencies in fakeproj" in result.output and "1 new" in result.output


def test_upgrade_marks_dependency_finding_fixed(tmp_path, conn):
    req = write(tmp_path / "requirements.txt", "fakepkg==1.2.3\n")
    reports = deps.parse_files([req])
    dep_list = reports[0].deps
    vuln = deps.Vulnerability("GHSA-fake-aaaa-0001", "FAKE", "medium", ["CVE-2099-3001"], "1.2.5")
    first = deps.to_scan(reports, dep_list, {0: [vuln]}, tmp_path, "fake-app-01.lab")
    first.run_id, first.finished_at = "1", "2099-01-01T00:00:00Z"
    second = deps.to_scan(reports, dep_list, {}, tmp_path, "fake-app-01.lab")
    second.run_id, second.finished_at = "2", "2099-01-02T00:00:00Z"
    store_scan(conn, first)
    store_scan(conn, second)
    row = conn.execute("SELECT * FROM findings").fetchone()
    assert (row["status"], row["package"], row["fixed_at"]) == ("fixed", "fakepkg", "2099-01-02T00:00:00Z")


def test_alias_duplicates_are_merged_keeping_the_rated_entry():
    ghsa = deps.Vulnerability("GHSA-fake-1", "FAKE", "high", ["CVE-2099-1"], "2.0", {"GHSA-fake-1", "CVE-2099-1"})
    pysec = deps.Vulnerability("PYSEC-fake-1", "FAKE", None, ["CVE-2099-1"], "2.0",
                               {"PYSEC-fake-1", "CVE-2099-1", "GHSA-fake-1"})
    unrated = deps.Vulnerability("PYSEC-fake-2", "FAKE other", None, [], None, {"PYSEC-fake-2"})
    merged = deps.merge_aliases([pysec, unrated, ghsa])
    assert [v.id for v in merged] == ["GHSA-fake-1", "PYSEC-fake-2"]
    assert deps.describe_vuln(merged[1]).startswith("UNRATED  PYSEC-fake-2")
