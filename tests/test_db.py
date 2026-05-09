"""Tests for the unified SQLite context manager (db.py)."""

from authmcp_gateway.db import get_db


def test_get_db_creates_dirs(tmp_path):
    """Parent directories are auto-created for new db_path."""
    db_path = str(tmp_path / "sub" / "dir" / "test.db")
    with get_db(db_path, row_factory=None) as conn:
        conn.execute("CREATE TABLE t (id INTEGER)")
    # File should exist after context exits
    assert (tmp_path / "sub" / "dir" / "test.db").exists()


def test_get_db_default_row_factory(db_path):
    """Default row_factory is sqlite3.Row."""
    with get_db(db_path) as conn:
        conn.execute("CREATE TABLE t (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO t VALUES (1, 'alice')")
    with get_db(db_path) as conn:
        row = conn.execute("SELECT * FROM t").fetchone()
        assert row["id"] == 1
        assert row["name"] == "alice"


def test_get_db_none_row_factory(db_path):
    """row_factory=None returns raw tuples."""
    with get_db(db_path, row_factory=None) as conn:
        conn.execute("CREATE TABLE t (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO t VALUES (1, 'bob')")
    with get_db(db_path, row_factory=None) as conn:
        row = conn.execute("SELECT * FROM t").fetchone()
        assert row == (1, "bob")


def test_get_db_auto_commit(db_path):
    """Changes persist after clean exit (auto-commit)."""
    with get_db(db_path, row_factory=None) as conn:
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.execute("INSERT INTO t VALUES (42)")

    # Reopen — data should be there
    with get_db(db_path, row_factory=None) as conn:
        row = conn.execute("SELECT id FROM t").fetchone()
        assert row[0] == 42


def test_get_db_rollback_on_exception(db_path):
    """Changes are rolled back when an exception is raised."""
    with get_db(db_path, row_factory=None) as conn:
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.execute("INSERT INTO t VALUES (1)")

    try:
        with get_db(db_path, row_factory=None) as conn:
            conn.execute("INSERT INTO t VALUES (2)")
            raise ValueError("forced error")
    except ValueError:
        pass

    # Only the first row should exist
    with get_db(db_path, row_factory=None) as conn:
        rows = conn.execute("SELECT id FROM t").fetchall()
        assert len(rows) == 1
        assert rows[0][0] == 1


def test_get_db_connection_closed(db_path):
    """Connection is closed after context exits."""
    with get_db(db_path, row_factory=None) as conn:
        conn.execute("CREATE TABLE t (id INTEGER)")

    # Attempting to use the connection after close should fail
    try:
        conn.execute("SELECT 1")
        closed = False
    except Exception:
        closed = True
    assert closed


def test_get_db_relative_path(tmp_path, monkeypatch):
    """Relative paths are converted to absolute."""
    monkeypatch.chdir(tmp_path)
    with get_db("relative.db", row_factory=None) as conn:
        conn.execute("CREATE TABLE t (id INTEGER)")
    assert (tmp_path / "relative.db").exists()


def test_get_db_reentrant(db_path):
    """Multiple sequential contexts work correctly."""
    with get_db(db_path, row_factory=None) as conn:
        conn.execute("CREATE TABLE t (id INTEGER)")

    for i in range(5):
        with get_db(db_path, row_factory=None) as conn:
            conn.execute("INSERT INTO t VALUES (?)", (i,))

    with get_db(db_path, row_factory=None) as conn:
        count = conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]
        assert count == 5
