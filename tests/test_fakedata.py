from datetime import datetime, timezone

import pytest

from helpers import make_nessus
from vmtoolkit import db
from vmtoolkit.fakedata import FakeDataError, generate
from vmtoolkit.normalize import store_scan
from vmtoolkit.parsers.nessus import parse_nessus_file

END = datetime(2099, 6, 30, tzinfo=timezone.utc)


def make(tmp_path, **kw):
    return generate(tmp_path / "fake.db", tmp_path / "vmt.db", machines=5, days=70, end=END, **kw)


def test_everything_is_labelled_fake(tmp_path):
    summary = make(tmp_path)
    assert summary.startswith("Wrote FAKE data")
    conn = db.connect(tmp_path / "fake.db")
    assert conn.execute("SELECT count(*) FROM scans WHERE is_fake = 0").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM findings WHERE is_fake = 0").fetchone()[0] == 0
    assert all(name.startswith("fake-") for (name,) in conn.execute("SELECT name FROM assets"))
    assert all(ip.startswith("192.0.2.") for (ip,) in conn.execute("SELECT ip FROM assets"))
    assert all(t.startswith("FAKE:") for (t,) in conn.execute("SELECT title FROM findings"))
    assert all(c.startswith("CVE-2099-") for (c,) in conn.execute("SELECT cve FROM finding_cves"))
    assert conn.execute("SELECT count(*) FROM scans").fetchone()[0] == 11
    assert conn.execute("SELECT count(*) FROM findings WHERE status = 'fixed'").fetchone()[0] > 0
    conn.close()


def test_same_seed_same_data(tmp_path):
    make(tmp_path)
    conn = db.connect(tmp_path / "fake.db")
    first = conn.execute("SELECT fingerprint, status, first_seen, fixed_at FROM findings ORDER BY 1").fetchall()
    conn.close()
    make(tmp_path, force=True)
    conn = db.connect(tmp_path / "fake.db")
    assert conn.execute("SELECT fingerprint, status, first_seen, fixed_at FROM findings ORDER BY 1").fetchall() == first
    conn.close()


def test_refuses_real_database_and_existing_files(tmp_path):
    with pytest.raises(FakeDataError, match="real database"):
        generate(tmp_path / "vmt.db", tmp_path / "vmt.db")
    make(tmp_path)
    with pytest.raises(FakeDataError, match="--force"):
        make(tmp_path)


def test_never_deletes_a_database_with_real_scans(tmp_path):
    conn = db.connect(tmp_path / "fake.db")
    path = tmp_path / "real.nessus"
    path.write_bytes(make_nessus({"fake-h1": [{"id": 1}]}))
    store_scan(conn, parse_nessus_file(path))
    conn.close()
    with pytest.raises(FakeDataError, match="1 real scans"):
        make(tmp_path, force=True)
    assert (tmp_path / "fake.db").exists()
