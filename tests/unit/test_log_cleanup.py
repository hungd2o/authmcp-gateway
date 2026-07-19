import json
import sqlite3
from datetime import datetime, timezone

from authmcp_gateway.security import logger as sec_logger


def _create_tables(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            severity TEXT,
            details TEXT,
            user_id INTEGER,
            username TEXT,
            ip_address TEXT,
            endpoint TEXT,
            method TEXT
        )
        """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mcp_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user_id INTEGER,
            mcp_server_id INTEGER,
            method TEXT,
            tool_name TEXT,
            success INTEGER,
            error_message TEXT,
            response_time_ms INTEGER,
            ip_address TEXT,
            is_suspicious INTEGER
        )
        """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS auth_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user_id INTEGER,
            action TEXT
        )
        """)
    conn.commit()


def _insert_old_rows(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    old_ts = "2000-01-01T00:00:00+00:00"
    cur.execute(
        "INSERT INTO security_events (timestamp, event_type, severity) VALUES (?, ?, ?)",
        (old_ts, "test", "low"),
    )
    cur.execute(
        "INSERT INTO mcp_requests (timestamp, method, success) VALUES (?, ?, ?)",
        (old_ts, "tools/list", 1),
    )
    cur.execute(
        "INSERT INTO auth_audit_log (timestamp, user_id, action) VALUES (?, ?, ?)",
        (old_ts, 1, "login"),
    )
    conn.commit()


def test_cleanup_archives_old_rows(tmp_path, monkeypatch):
    db_path = tmp_path / "logs.db"
    archive_path = tmp_path / "archive.jsonl"

    conn = sqlite3.connect(db_path)
    _create_tables(conn)
    _insert_old_rows(conn)
    conn.close()

    class _DummyConfig:
        mcp_log_db_archive_enabled = True
        mcp_log_db_archive_path = str(archive_path)

    monkeypatch.setattr("authmcp_gateway.config.get_config", lambda: _DummyConfig())

    result = sec_logger.cleanup_old_logs(str(db_path), days_to_keep=1)

    assert result["security_events"] == 1
    assert result["mcp_requests"] == 1
    assert result["auth_audit_log"] == 1
    assert archive_path.exists()

    lines = archive_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    for line in lines:
        payload = json.loads(line)
        assert "table" in payload
        assert "row" in payload


def test_cleanup_archives_management_audit_and_expires_idempotency(tmp_path, monkeypatch):
    db_path = tmp_path / "management.db"
    archive_path = tmp_path / "management-audit.jsonl"
    conn = sqlite3.connect(db_path)
    _create_tables(conn)
    old_ts = "2000-01-01T00:00:00+00:00"
    conn.execute(
        "CREATE TABLE management_audit (id INTEGER, timestamp TEXT, operation TEXT)"
    )
    conn.execute("CREATE TABLE management_idempotency (id INTEGER, expires_at TEXT)")
    conn.execute(
        "INSERT INTO management_audit VALUES (?, ?, ?)", (1, old_ts, "repository.delete")
    )
    conn.execute("INSERT INTO management_idempotency VALUES (?, ?)", (1, old_ts))
    conn.commit()
    conn.close()

    class _DummyConfig:
        mcp_log_db_archive_enabled = False
        mcp_log_db_archive_path = None
        mgmt_audit_days_to_keep = 90
        mgmt_audit_archive_enabled = True
        mgmt_audit_archive_path = str(archive_path)

    monkeypatch.setattr("authmcp_gateway.config.get_config", lambda: _DummyConfig())
    result = sec_logger.cleanup_old_logs(str(db_path), days_to_keep=1)

    assert result["management_audit"] == 1
    assert result["management_idempotency"] == 1
    assert "management_audit" in archive_path.read_text(encoding="utf-8")


def test_management_audit_capacity_archives_before_pruning_recent_rows(tmp_path, monkeypatch):
    db_path = tmp_path / "management-cap.db"
    archive_path = tmp_path / "management-cap.jsonl"
    conn = sqlite3.connect(db_path)
    _create_tables(conn)
    conn.execute("CREATE TABLE management_audit (id INTEGER, timestamp TEXT, operation TEXT)")
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO management_audit VALUES (?, ?, ?)",
        [(1, now, "a"), (2, now, "b"), (3, now, "c")],
    )
    conn.commit()
    conn.close()

    class _DummyConfig:
        mcp_log_db_archive_enabled = False
        mcp_log_db_archive_path = None
        mgmt_audit_days_to_keep = 90
        mgmt_audit_archive_enabled = True
        mgmt_audit_archive_path = str(archive_path)

    monkeypatch.setattr("authmcp_gateway.config.get_config", lambda: _DummyConfig())
    sec_logger.cleanup_old_logs(
        str(db_path), management_max_rows=1, management_max_bytes=1024 * 1024
    )
    with sqlite3.connect(db_path) as check:
        assert check.execute("SELECT COUNT(*) FROM management_audit").fetchone()[0] == 1
    assert archive_path.read_text(encoding="utf-8").count("management_audit") == 2


def test_management_writes_trigger_shared_rate_limited_maintenance(monkeypatch, initialized_db):
    from authmcp_gateway.mcp import store

    store.init_mcp_database(initialized_db)
    maintenance_calls = []
    monkeypatch.setattr(
        "authmcp_gateway.security.logger.run_log_maintenance_if_due",
        maintenance_calls.append,
    )
    server_id = store.create_mcp_server(initialized_db, "managed", "https://managed/mcp")

    store.log_management_audit(initialized_db, server_id, "repository.create")

    assert maintenance_calls == [initialized_db]


def test_management_only_maintenance_preserves_legacy_log_retention(tmp_path, monkeypatch):
    db_path = tmp_path / "management-only.db"
    conn = sqlite3.connect(db_path)
    _create_tables(conn)
    _insert_old_rows(conn)
    conn.close()

    class _DummyConfig:
        mcp_log_db_archive_enabled = False
        mcp_log_db_archive_path = None
        mgmt_audit_days_to_keep = 90
        mgmt_audit_archive_enabled = True
        mgmt_audit_archive_path = str(tmp_path / "management-audit.jsonl")

    monkeypatch.setattr("authmcp_gateway.config.get_config", lambda: _DummyConfig())
    result = sec_logger.cleanup_old_logs(str(db_path), include_legacy=False)

    assert result["security_events"] == 0
    assert result["mcp_requests"] == 0
    assert result["auth_audit_log"] == 0
    with sqlite3.connect(db_path) as check:
        assert check.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 1


def test_management_maintenance_warns_when_archive_before_prune_is_unavailable(
    tmp_path, monkeypatch, caplog
):
    db_path = tmp_path / "management-capacity.db"
    conn = sqlite3.connect(db_path)
    _create_tables(conn)
    conn.execute("CREATE TABLE management_audit (id INTEGER, timestamp TEXT)")
    conn.execute("INSERT INTO management_audit VALUES (?, ?)", (1, "2000-01-01T00:00:00+00:00"))
    conn.commit()
    conn.close()

    class _DummyConfig:
        mcp_log_db_check_interval_seconds = 1
        mcp_log_db_max_mb = 200
        mcp_log_db_max_rows = 200000
        mgmt_audit_max_mb = 200
        mgmt_audit_max_rows = 0
        mgmt_audit_archive_enabled = False
        mgmt_audit_archive_path = None
        mgmt_audit_days_to_keep = 90
        mcp_log_db_archive_enabled = False
        mcp_log_db_archive_path = None

    monkeypatch.setattr("authmcp_gateway.config.get_config", lambda: _DummyConfig())
    monkeypatch.setattr(sec_logger, "_last_mcp_db_check_ts", {})

    sec_logger.run_log_maintenance_if_due(str(db_path))

    assert "archive-before-prune is unavailable" in caplog.text


def test_maintenance_throttle_is_scoped_to_each_database(tmp_path, monkeypatch):
    checked = []
    monkeypatch.setattr(sec_logger, "_last_mcp_db_check_ts", {})
    monkeypatch.setattr(sec_logger, "cleanup_old_logs", lambda path, **_: checked.append(path) or {})

    class _DummyConfig:
        mcp_log_db_check_interval_seconds = 300
        mcp_log_db_max_mb = 200
        mcp_log_db_max_rows = 200000
        mgmt_audit_max_mb = 200
        mgmt_audit_max_rows = 200000
        mgmt_audit_archive_enabled = True
        mgmt_audit_archive_path = "audit.jsonl"

    monkeypatch.setattr("authmcp_gateway.config.get_config", lambda: _DummyConfig())
    for name in ("one.db", "two.db"):
        conn = sqlite3.connect(tmp_path / name)
        _create_tables(conn)
        conn.close()
        sec_logger.run_log_maintenance_if_due(str(tmp_path / name))

    assert len(checked) == 2
