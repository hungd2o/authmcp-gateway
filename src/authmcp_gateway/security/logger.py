"""Security and MCP request logging functions."""

import json
import logging
import math
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from authmcp_gateway.db import get_db

logger = logging.getLogger(__name__)

_last_mcp_db_check_ts: dict[str, float] = {}
_mcp_db_check_lock = threading.Lock()


def run_log_maintenance_if_due(db_path: str) -> None:
    """Run the shared, rate-limited retention and capacity check."""
    from authmcp_gateway.config import get_config

    config = get_config()
    now = time.time()
    interval = max(1, int(getattr(config, "mcp_log_db_check_interval_seconds", 300)))
    db_key = os.path.normcase(os.path.abspath(db_path))
    with _mcp_db_check_lock:
        if now - _last_mcp_db_check_ts.get(db_key, 0.0) < interval:
            return
        _last_mcp_db_check_ts[db_key] = now
    try:
        with get_db(db_path, row_factory=None) as conn_check:
            cur = conn_check.cursor()
            cur.execute("PRAGMA page_count")
            page_count = cur.fetchone()[0]
            cur.execute("PRAGMA page_size")
            page_size = cur.fetchone()[0]
            db_mb = (page_count * page_size) / (1024 * 1024)
            cur.execute("SELECT COUNT(*) FROM mcp_requests")
            mcp_rows = cur.fetchone()[0]
            cur.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'management_audit'"
            )
            management_audit_rows = 0
            if cur.fetchone():
                cur.execute("SELECT COUNT(*) FROM management_audit")
                management_audit_rows = cur.fetchone()[0]

        max_mb = getattr(config, "mcp_log_db_max_mb", 200)
        max_rows = getattr(config, "mcp_log_db_max_rows", 200000)
        management_max_mb = getattr(config, "mgmt_audit_max_mb", 200)
        management_max_rows = getattr(config, "mgmt_audit_max_rows", 200000)
        legacy_limits_exceeded = db_mb > max_mb or mcp_rows > max_rows
        management_limits_exceeded = (
            management_audit_rows > management_max_rows or db_mb > management_max_mb
        )
        if legacy_limits_exceeded:
            logger.warning(
                "MCP log DB limits exceeded (size=%.1fMB rows=%s); running cleanup",
                db_mb,
                mcp_rows,
            )
            cleanup_result = cleanup_old_logs(
                db_path,
                days_to_keep=getattr(config, "mcp_log_db_days_to_keep", 30),
                management_max_rows=management_max_rows,
                management_max_bytes=management_max_mb * 1024 * 1024,
            )
        else:
            cleanup_result = cleanup_old_logs(
                db_path,
                include_legacy=False,
                management_max_rows=management_max_rows,
                management_max_bytes=management_max_mb * 1024 * 1024,
            )
        archive_unavailable = (
            not (
                getattr(config, "mgmt_audit_archive_enabled", True)
                and getattr(config, "mgmt_audit_archive_path", None)
            )
            or "error" in cleanup_result
        )
        if management_limits_exceeded and archive_unavailable:
            logger.warning(
                "Management audit exceeds its retention capacity (rows=%s), "
                "but archive-before-prune is unavailable; retaining records",
                management_audit_rows,
            )
    except (sqlite3.Error, OSError) as exc:
        logger.debug("MCP DB maintenance check failed: %s", exc)


def log_security_event(
    db_path: str,
    event_type: str,
    severity: str,
    details: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    endpoint: Optional[str] = None,
    method: Optional[str] = None,
) -> None:
    """Log security-related event.

    Args:
        db_path: Path to SQLite database
        event_type: Type of security event (unauthorized_access, rate_limited,
                   suspicious_payload, auth_failed, etc.)
        severity: Severity level (low, medium, high, critical)
        details: Optional dictionary with additional context (will be JSON-encoded)
        user_id: Optional user ID
        username: Optional username
        ip_address: Optional IP address
        endpoint: Optional endpoint path
        method: Optional HTTP method
    """
    try:
        with get_db(db_path, row_factory=None) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO security_events (
                    event_type, severity, user_id, username, ip_address,
                    endpoint, method, details, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_type,
                    severity,
                    user_id,
                    username,
                    ip_address,
                    endpoint,
                    method,
                    json.dumps(details) if details else None,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

        logger.info(
            f"Security event logged: {event_type} (severity={severity}, "
            f"user={username or 'N/A'}, ip={ip_address or 'N/A'})"
        )

    except sqlite3.Error as e:
        logger.error(f"Failed to log security event: {e}")


def log_mcp_request(
    db_path: str,
    user_id: Optional[int],
    mcp_server_id: Optional[int],
    method: str,
    tool_name: Optional[str] = None,
    success: bool = True,
    error_message: Optional[str] = None,
    response_time_ms: Optional[int] = None,
    ip_address: Optional[str] = None,
    client_id: Optional[str] = None,
    client_name: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    path: Optional[str] = None,
    event_kind: Optional[str] = None,
    is_suspicious: bool = False,
) -> None:
    """Log MCP request to file.

    Args:
        db_path: Path to SQLite database (ignored, kept for compatibility)
        user_id: User ID making the request
        mcp_server_id: MCP server ID (if applicable)
        method: MCP method (tools/list, tools/call, initialize)
        tool_name: Tool name (if tools/call)
        success: Whether request succeeded
        error_message: Error message (if failed)
        response_time_ms: Response time in milliseconds
        ip_address: Client IP address
        is_suspicious: Whether request was flagged as suspicious
    """
    try:
        from authmcp_gateway.config import get_config
        from authmcp_gateway.logging_config import get_mcp_logger, log_mcp_request_to_file

        config = get_config()
        db_logging_enabled = getattr(config, "mcp_log_db_enabled", False)

        # Lookup username/server_name + optional DB insert in one connection
        username = None
        server_name = None

        if user_id or mcp_server_id or db_logging_enabled or client_id:
            with get_db(db_path, row_factory=None) as conn:
                cursor = conn.cursor()

                if user_id:
                    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
                    row = cursor.fetchone()
                    if row:
                        username = row[0]

                if mcp_server_id:
                    cursor.execute("SELECT name FROM mcp_servers WHERE id = ?", (mcp_server_id,))
                    row = cursor.fetchone()
                    if row:
                        server_name = row[0]

                if client_id and not client_name:
                    cursor.execute(
                        "SELECT client_name FROM oauth_clients WHERE client_id = ?",
                        (client_id,),
                    )
                    row = cursor.fetchone()
                    if row:
                        client_name = row[0]

                # DB insert in same connection (if enabled)
                if db_logging_enabled:
                    cursor.execute(
                        """
                        INSERT INTO mcp_requests (
                            user_id, mcp_server_id, method, tool_name, success,
                            error_message, response_time_ms, ip_address, client_id,
                            client_name, user_agent, request_id, path, event_kind,
                            is_suspicious
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            user_id,
                            mcp_server_id,
                            method,
                            tool_name,
                            success,
                            error_message,
                            response_time_ms,
                            ip_address,
                            client_id,
                            client_name,
                            user_agent,
                            request_id,
                            path,
                            event_kind,
                            is_suspicious,
                        ),
                    )

        # Log to file (default, low overhead)
        mcp_logger = get_mcp_logger()
        log_mcp_request_to_file(
            logger=mcp_logger,
            method=method,
            server_id=mcp_server_id,
            server_name=server_name,
            user_id=user_id,
            username=username,
            tool_name=tool_name,
            response_time_ms=response_time_ms,
            success=success,
            error=error_message,
            suspicious=is_suspicious,
            client_id=client_id,
            client_name=client_name,
            user_agent=user_agent,
            request_id=request_id,
            path=path,
            event_kind=event_kind,
        )

        # Periodic DB size/row check (runs rarely, separate connection)
        if db_logging_enabled:
            run_log_maintenance_if_due(db_path)

        logger.debug(
            f"MCP request logged: {method} (tool={tool_name or 'N/A'}, "
            f"success={success}, time={response_time_ms}ms)"
        )

    except sqlite3.Error as e:
        logger.error(f"Failed to log MCP request: {e}")


def cleanup_old_logs(
    db_path: str,
    days_to_keep: int = 30,
    *,
    include_legacy: bool = True,
    management_max_rows: int | None = None,
    management_max_bytes: int | None = None,
) -> Dict[str, Any]:
    """Delete logs older than specified number of days.

    Args:
        db_path: Path to SQLite database
        days_to_keep: Number of days to keep logs (default: 30)

    Returns:
        Dictionary with counts of deleted records per table. Set
        ``include_legacy=False`` for periodic management-only maintenance;
        legacy records then retain their historical threshold-triggered cleanup.
    """
    try:
        with get_db(db_path, row_factory=None) as conn:
            cursor = conn.cursor()

            now = datetime.now(timezone.utc)
            now_iso = now.isoformat()
            cutoff_date = (now - timedelta(days=days_to_keep)).isoformat()

            # Optional archive to file before deletion
            from authmcp_gateway.config import get_config

            config = get_config()
            archive_path = getattr(config, "mcp_log_db_archive_path", None)
            archive_enabled = getattr(config, "mcp_log_db_archive_enabled", False)

            ALLOWED_TABLES = {
                "security_events",
                "mcp_requests",
                "auth_audit_log",
                "management_audit",
            }

            def _table_exists(table_name: str) -> bool:
                row = cursor.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table_name,)
                ).fetchone()
                return row is not None

            def _archive_table(
                table_name: str, cutoff: str, enabled: bool, path: Optional[str]
            ) -> int:
                if not (enabled and path):
                    return 0
                if table_name not in ALLOWED_TABLES:
                    logger.error(f"Rejected invalid table name in cleanup: {table_name}")
                    return 0
                cursor.execute(f"SELECT * FROM {table_name} WHERE timestamp < ?", (cutoff,))
                columns = [d[0] for d in cursor.description]
                archived = 0
                with open(path, "a", encoding="utf-8") as f:
                    while True:
                        rows = cursor.fetchmany(500)
                        if not rows:
                            break
                        for row in rows:
                            payload = {"table": table_name, "row": dict(zip(columns, row))}
                            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
                            archived += 1
                return archived

            def _archive_management_ids(ids: list[int], path: Optional[str]) -> int:
                if not ids or not path:
                    return 0
                marks = ",".join("?" for _ in ids)
                cursor.execute(
                    f"SELECT * FROM management_audit WHERE id IN ({marks}) ORDER BY id", ids
                )
                columns = [item[0] for item in cursor.description]
                with open(path, "a", encoding="utf-8") as archive:
                    for row in cursor.fetchall():
                        archive.write(
                            json.dumps(
                                {"table": "management_audit", "row": dict(zip(columns, row))},
                                ensure_ascii=False,
                            )
                            + "\n"
                        )
                return len(ids)

            archived_security = archived_mcp = archived_auth = 0
            security_deleted = mcp_deleted = auth_deleted = 0
            if include_legacy:
                archived_security = _archive_table(
                    "security_events", cutoff_date, archive_enabled, archive_path
                )
                archived_mcp = _archive_table(
                    "mcp_requests", cutoff_date, archive_enabled, archive_path
                )
                archived_auth = _archive_table(
                    "auth_audit_log", cutoff_date, archive_enabled, archive_path
                )
                cursor.execute("DELETE FROM security_events WHERE timestamp < ?", (cutoff_date,))
                security_deleted = cursor.rowcount
                cursor.execute("DELETE FROM mcp_requests WHERE timestamp < ?", (cutoff_date,))
                mcp_deleted = cursor.rowcount
                cursor.execute("DELETE FROM auth_audit_log WHERE timestamp < ?", (cutoff_date,))
                auth_deleted = cursor.rowcount

            idempotency_deleted = 0
            audit_deleted = 0
            archived_management_audit = 0
            if _table_exists("management_idempotency"):
                cursor.execute(
                    "DELETE FROM management_idempotency WHERE expires_at < ?", (now_iso,)
                )
                idempotency_deleted = cursor.rowcount
            if _table_exists("management_audit"):
                audit_days = getattr(config, "mgmt_audit_days_to_keep", 90)
                audit_cutoff = (now - timedelta(days=audit_days)).isoformat()
                audit_archive_enabled = getattr(config, "mgmt_audit_archive_enabled", True)
                audit_archive_path = getattr(config, "mgmt_audit_archive_path", None)
                if audit_archive_enabled and audit_archive_path:
                    archived_management_audit = _archive_table(
                        "management_audit", audit_cutoff, True, audit_archive_path
                    )
                    cursor.execute(
                        "DELETE FROM management_audit WHERE timestamp < ?", (audit_cutoff,)
                    )
                    audit_deleted = cursor.rowcount
                    audit_columns = {
                        row[1] for row in cursor.execute("PRAGMA table_info(management_audit)")
                    }
                    # Full-row accounting plus a conservative per-record allowance
                    # keeps the configured cap below table/index storage in practice.
                    byte_terms = [
                        f"COALESCE(LENGTH(CAST({column} AS TEXT)), 0)" for column in audit_columns
                    ]
                    byte_expression = " + ".join(byte_terms) if byte_terms else "0"
                    byte_expression = f"({byte_expression}) + 256"
                    cursor.execute(
                        f"SELECT COUNT(*), COALESCE(SUM({byte_expression}), 0) FROM management_audit"
                    )
                    audit_rows, audit_bytes = cursor.fetchone()
                    max_rows = (
                        management_max_rows
                        if management_max_rows is not None
                        else getattr(config, "mgmt_audit_max_rows", 200000)
                    )
                    max_bytes = (
                        management_max_bytes
                        if management_max_bytes is not None
                        else getattr(config, "mgmt_audit_max_mb", 200) * 1024 * 1024
                    )
                    while audit_rows > max_rows or audit_bytes > max_bytes:
                        by_rows = max(1, audit_rows - max_rows)
                        by_bytes = max(
                            1,
                            int(audit_rows * max(0, audit_bytes - max_bytes) / max(audit_bytes, 1))
                            + 1,
                        )
                        cursor.execute(
                            "SELECT id FROM management_audit ORDER BY id LIMIT ?",
                            (min(max(by_rows, by_bytes), 500),),
                        )
                        ids = [row[0] for row in cursor.fetchall()]
                        archived_management_audit += _archive_management_ids(
                            ids, audit_archive_path
                        )
                        marks = ",".join("?" for _ in ids)
                        cursor.execute(f"DELETE FROM management_audit WHERE id IN ({marks})", ids)
                        audit_deleted += cursor.rowcount
                        cursor.execute(
                            f"SELECT COUNT(*), COALESCE(SUM({byte_expression}), 0) FROM management_audit"
                        )
                        audit_rows, audit_bytes = cursor.fetchone()

        result = {
            "security_events": security_deleted,
            "mcp_requests": mcp_deleted,
            "auth_audit_log": auth_deleted,
            "management_audit": audit_deleted,
            "management_idempotency": idempotency_deleted,
            "total": security_deleted
            + mcp_deleted
            + auth_deleted
            + audit_deleted
            + idempotency_deleted,
        }
        if archive_enabled and archive_path:
            result["archived"] = {
                "security_events": archived_security,
                "mcp_requests": archived_mcp,
                "auth_audit_log": archived_auth,
                "management_audit": archived_management_audit,
            }

        logger.info(
            f"Cleanup completed: deleted {result['total']} old log entries "
            f"(security={security_deleted}, mcp={mcp_deleted}, auth={auth_deleted})"
        )

        return result

    except (sqlite3.Error, OSError) as e:
        # Cleanup runs DELETE statements and may write a JSONL archive file
        # when the config enables it; either path can fail non-fatally.
        logger.error(f"Failed to cleanup old logs: {e}")
        return {"error": str(e)}


def get_security_events(
    db_path: str,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    last_hours: Optional[int] = None,
) -> list[Dict[str, Any]]:
    """Get security events with optional filters.

    Args:
        db_path: Path to SQLite database
        severity: Filter by severity (low, medium, high, critical)
        event_type: Filter by event type
        limit: Maximum number of events to return
        last_hours: Only return events from last N hours

    Returns:
        List of security event dictionaries
    """
    try:
        with get_db(db_path) as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM security_events WHERE 1=1"
            params: List[Any] = []

            if severity:
                query += " AND severity = ?"
                params.append(severity)

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)

            if last_hours:
                cutoff = (datetime.now(timezone.utc) - timedelta(hours=last_hours)).isoformat()
                query += " AND timestamp >= ?"
                params.append(cutoff)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    except sqlite3.Error as e:
        logger.error(f"Failed to get security events: {e}")
        return []


def get_mcp_request_stats(db_path: str, last_hours: int = 24) -> Dict[str, Any]:
    """Get MCP request statistics.

    Args:
        db_path: Path to SQLite database
        last_hours: Time window in hours (default: 24)

    Returns:
        Dictionary with statistics
    """
    try:
        with get_db(db_path, row_factory=None) as conn:
            cursor = conn.cursor()

            cutoff = (datetime.now(timezone.utc) - timedelta(hours=last_hours)).isoformat()

            # Total requests
            cursor.execute("SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ?", (cutoff,))
            total_requests = cursor.fetchone()[0]

            # Successful requests
            cursor.execute(
                "SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ? AND success = 1",
                (cutoff,),
            )
            successful_requests = cursor.fetchone()[0]

            # Failed requests
            cursor.execute(
                "SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ? AND success = 0",
                (cutoff,),
            )
            failed_requests = cursor.fetchone()[0]

            # Suspicious requests
            cursor.execute(
                "SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ? AND is_suspicious = 1",
                (cutoff,),
            )
            suspicious_requests = cursor.fetchone()[0]

            # Average response time
            cursor.execute(
                "SELECT AVG(response_time_ms) FROM mcp_requests "
                "WHERE timestamp >= ? AND response_time_ms IS NOT NULL",
                (cutoff,),
            )
            avg_response_time = cursor.fetchone()[0]

            # Top tools (include server info when available)
            cursor.execute(
                """
                SELECT r.tool_name, r.mcp_server_id, s.name, COUNT(*) as count
                FROM mcp_requests r
                LEFT JOIN mcp_servers s ON s.id = r.mcp_server_id
                WHERE r.timestamp >= ? AND r.tool_name IS NOT NULL
                GROUP BY r.tool_name, r.mcp_server_id, s.name
                ORDER BY count DESC
                LIMIT 5
                """,
                (cutoff,),
            )
            top_tools = [
                {
                    "tool": row[0],
                    "server_id": row[1],
                    "server_name": row[2],
                    "count": row[3],
                }
                for row in cursor.fetchall()
            ]

        return {
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
            "suspicious_requests": suspicious_requests,
            "success_rate": (
                round(successful_requests / total_requests * 100, 2) if total_requests > 0 else 0
            ),
            "avg_response_time_ms": round(avg_response_time, 2) if avg_response_time else 0,
            "top_tools": top_tools,
            "time_window_hours": last_hours,
        }

    except sqlite3.Error as e:
        logger.error(f"Failed to get MCP request stats: {e}")
        return {
            "error": str(e),
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "suspicious_requests": 0,
            "success_rate": 0,
            "avg_response_time_ms": 0,
            "top_tools": [],
            "time_window_hours": last_hours,
        }


def get_server_request_metrics(
    db_path: str, server_id: int, *, last_hours: int = 1
) -> Dict[str, Any]:
    """Return recent, per-server request metrics when DB logging is available.

    The gateway's file log is intentionally not parsed here: it can be rotated
    and does not provide a stable source for an operations dashboard.  A null
    metrics payload therefore means that request persistence is disabled or has
    not collected any samples yet, never that there was no traffic.
    """
    from authmcp_gateway.config import get_config

    if not getattr(get_config(), "mcp_log_db_enabled", False):
        return {"available": False, "window_hours": last_hours}

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=last_hours)).isoformat()
    try:
        with get_db(db_path, row_factory=None) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT success, response_time_ms, error_message, timestamp
                FROM mcp_requests
                WHERE mcp_server_id = ? AND timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT 500
                """,
                (server_id, cutoff),
            )
            rows = cursor.fetchall()
    except sqlite3.Error:
        return {"available": False, "window_hours": last_hours}

    latencies = sorted(int(row[1]) for row in rows if isinstance(row[1], int) and row[1] >= 0)

    def percentile(percent: float) -> int | None:
        if not latencies:
            return None
        index = max(0, min(len(latencies) - 1, math.ceil(len(latencies) * percent) - 1))
        return latencies[index]

    last_timeout_at = next(
        (
            row[3]
            for row in rows
            if not bool(row[0]) and isinstance(row[2], str) and "timeout" in row[2].lower()
        ),
        None,
    )
    return {
        "available": True,
        "window_hours": last_hours,
        "requests": len(rows),
        "errors": sum(not bool(row[0]) for row in rows),
        "p50_ms": percentile(0.50),
        "p95_ms": percentile(0.95),
        "last_timeout_at": last_timeout_at,
    }


def get_mcp_requests(
    db_path: str,
    limit: int = 50,
    last_seconds: int = 60,
    method: Optional[str] = None,
    success: Optional[bool] = None,
    event_kind: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get recent MCP requests from DB (fallback to log files).

    Args:
        db_path: Path to SQLite database (ignored, kept for compatibility)
        limit: Maximum number of requests to return
        last_seconds: Number of seconds to look back
        method: Filter by method (optional)
        success: Filter by success status (optional)

    Returns:
        List of MCP request records
    """
    try:
        from authmcp_gateway.config import get_config

        config = get_config()

        # Calculate time threshold (match SQLite CURRENT_TIMESTAMP format)
        threshold = datetime.now(timezone.utc) - timedelta(seconds=last_seconds)
        threshold_sql = threshold.strftime("%Y-%m-%d %H:%M:%S")

        if getattr(config, "mcp_log_db_enabled", False):
            with get_db(db_path) as conn:
                cursor = conn.cursor()

                query = """
                    SELECT
                        r.id,
                        r.user_id,
                        u.username,
                        r.mcp_server_id,
                        s.name AS server_name,
                        r.method,
                        r.tool_name,
                        r.success,
                        r.error_message,
                        r.response_time_ms,
                        r.ip_address,
                        r.client_id,
                        r.client_name,
                        r.user_agent,
                        r.request_id,
                        r.path,
                        r.event_kind,
                        r.is_suspicious,
                        r.timestamp
                    FROM mcp_requests r
                    LEFT JOIN users u ON u.id = r.user_id
                    LEFT JOIN mcp_servers s ON s.id = r.mcp_server_id
                    WHERE r.timestamp >= ?
                """
                params: List[Any] = [threshold_sql]

                if method:
                    query += " AND r.method = ?"
                    params.append(method)

                if success is not None:
                    query += " AND r.success = ?"
                    params.append(1 if success else 0)

                if event_kind:
                    if event_kind == "work":
                        query += (
                            " AND (r.event_kind = ? OR "
                            "(r.event_kind IS NULL AND r.method = 'tools/call'))"
                        )
                        params.append("work")
                    elif event_kind == "system":
                        query += (
                            " AND (r.event_kind = ? OR "
                            "(r.event_kind IS NULL AND r.method IN "
                            "('initialize','tools/list','notifications/initialized')))"
                        )
                        params.append("system")
                    else:
                        query += " AND r.event_kind = ?"
                        params.append(event_kind)

                query += " ORDER BY r.timestamp DESC LIMIT ?"
                params.append(limit)

                cursor.execute(query, params)
                rows = cursor.fetchall()

            return [
                {
                    "id": row["id"],
                    "user_id": row["user_id"],
                    "username": row["username"],
                    "mcp_server_id": row["mcp_server_id"],
                    "server_name": row["server_name"],
                    "method": row["method"],
                    "tool_name": row["tool_name"],
                    "success": bool(row["success"]),
                    "error_message": row["error_message"],
                    "response_time_ms": row["response_time_ms"],
                    "ip_address": row["ip_address"],
                    "client_id": row["client_id"],
                    "client_name": row["client_name"],
                    "user_agent": row["user_agent"],
                    "request_id": row["request_id"],
                    "path": row["path"],
                    "event_kind": row["event_kind"]
                    or ("work" if row["method"] == "tools/call" else "system"),
                    "is_suspicious": bool(row["is_suspicious"]),
                    "timestamp": row["timestamp"],
                }
                for row in rows
            ]

        # Fallback to file-based logs if DB logging disabled
        from pathlib import Path

        log_file = Path("data/logs/mcp_requests.log")
        if not log_file.exists():
            return []

        requests: List[Dict[str, Any]] = []
        with open(log_file, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())

                    timestamp_str = entry.get("timestamp", "").replace("Z", "+00:00")
                    entry_time = datetime.fromisoformat(timestamp_str)
                    if entry_time < threshold:
                        continue

                    if method and entry.get("method") != method:
                        continue

                    if success is not None and entry.get("success") != success:
                        continue

                    entry_event_kind = entry.get("event_kind") or (
                        "work" if entry.get("method") == "tools/call" else "system"
                    )
                    if event_kind and entry_event_kind != event_kind:
                        continue

                    requests.append(
                        {
                            "id": len(requests) + 1,  # Synthetic ID
                            "user_id": entry.get("user_id"),
                            "username": entry.get("username"),
                            "mcp_server_id": entry.get("server_id"),
                            "server_name": entry.get("server_name"),
                            "method": entry.get("method"),
                            "tool_name": entry.get("tool_name"),
                            "success": entry.get("success", True),
                            "error_message": entry.get("error"),
                            "response_time_ms": entry.get("response_time_ms"),
                            "ip_address": entry.get("ip_address"),
                            "client_id": entry.get("client_id"),
                            "client_name": entry.get("client_name"),
                            "user_agent": entry.get("user_agent"),
                            "request_id": entry.get("request_id"),
                            "path": entry.get("path"),
                            "event_kind": entry_event_kind,
                            "is_suspicious": entry.get("suspicious", False),
                            "timestamp": entry.get("timestamp"),
                        }
                    )
                except (json.JSONDecodeError, ValueError) as e:
                    logger.warning(f"Failed to parse MCP log entry: {e}")
                    continue

        requests.sort(key=lambda x: x["timestamp"], reverse=True)
        return requests[:limit]

    except (sqlite3.Error, OSError, KeyError) as e:
        # Reads from SQLite (DB-enabled path) and may fall through to a
        # rotating log file (OSError on missing/locked file). KeyError
        # protects the dict-access in row → dict mapping.
        logger.error(f"Error reading MCP requests: {e}")
        return []
