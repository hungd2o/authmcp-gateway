"""Database operations for MCP servers."""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, cast

from authmcp_gateway.db import get_db

from .crypto import decrypt_token_safe, encrypt_token
from .trust import (
    APPROVAL_APPROVED,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
    APPROVAL_REVOKED,
    RISK_LOW,
    build_server_fingerprint,
    build_virtual_tool_fingerprint,
    default_risk_level,
    derive_server_allowlist_policy,
    server_matches_allowlist_policy,
)

logger = logging.getLogger(__name__)


def _decrypt_server_dict(server: Dict[str, Any]) -> Dict[str, Any]:
    """Decrypt encrypted fields in a server dict (auth_token).

    Handles backward compatibility with legacy plaintext tokens.
    Also corrects risk_level and fills missing allowlist_policy for rows
    created before those columns were added.
    """
    if server.get("auth_token"):
        server["auth_token"] = decrypt_token_safe(server["auth_token"])
    if isinstance(server.get("command_args"), str):
        try:
            server["command_args"] = json.loads(server["command_args"])
        except json.JSONDecodeError:
            server["command_args"] = []
    if isinstance(server.get("env_vars"), str):
        try:
            parsed_env = json.loads(server["env_vars"])
            server["env_vars"] = parsed_env if isinstance(parsed_env, dict) else {}
        except json.JSONDecodeError:
            server["env_vars"] = {}
    if isinstance(server.get("allowlist_policy"), str):
        try:
            server["allowlist_policy"] = json.loads(server["allowlist_policy"])
        except json.JSONDecodeError:
            server["allowlist_policy"] = {}
    if isinstance(server.get("approval_metadata"), str):
        try:
            server["approval_metadata"] = json.loads(server["approval_metadata"])
        except json.JSONDecodeError:
            server["approval_metadata"] = {}
    # Recompute risk_level from transport_type — corrects rows created before the
    # column existed whose DEFAULT 'low' is wrong for stdio/pipe transports.
    server["risk_level"] = default_risk_level(server.get("transport_type"))
    # Populate allowlist_policy from live config if missing or empty — corrects rows
    # created before the column existed so that the approval flow can proceed.
    if not server.get("allowlist_policy"):
        server["allowlist_policy"] = derive_server_allowlist_policy(server)
    return server


def _db_conn(db_path: str, row_factory=None):
    """Backward-compatible wrapper: defaults to raw tuples (row_factory=None)."""
    return get_db(db_path, row_factory=row_factory)


def init_mcp_database(db_path: str) -> None:
    """Initialize MCP-related database tables.

    Creates:
    - mcp_servers: Backend MCP server configurations
    - tool_mappings: Explicit tool-to-server mappings
    - user_mcp_permissions: User access permissions to servers
    """
    with _db_conn(db_path) as conn:
        cursor = conn.cursor()

        # MCP servers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mcp_servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                url TEXT NOT NULL,
                tool_prefix TEXT,
                enabled INTEGER DEFAULT 1,
                auth_type TEXT DEFAULT 'none',
                auth_token TEXT,
                routing_strategy TEXT DEFAULT 'prefix',
                status TEXT DEFAULT 'unknown',
                last_health_check TIMESTAMP,
                last_error TEXT,
                tools_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                refresh_token_hash TEXT,
                token_expires_at TIMESTAMP,
                token_last_refreshed TIMESTAMP,
                refresh_endpoint TEXT DEFAULT '/oauth/token',
                timeout INTEGER DEFAULT NULL,
                transport_type TEXT DEFAULT 'http',
                command TEXT,
                command_args TEXT,
                pipe_path TEXT,
                expose_port INTEGER,
                working_dir TEXT,
                env_vars TEXT,
                min_workers INTEGER DEFAULT NULL,
                max_workers INTEGER DEFAULT NULL,
                approval_state TEXT DEFAULT 'pending',
                risk_level TEXT DEFAULT 'low',
                config_fingerprint TEXT,
                allowlist_policy TEXT,
                approval_metadata TEXT,
                blocked_reason TEXT
            )
        """)

        # Tool mappings for explicit routing
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tool_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_name TEXT UNIQUE NOT NULL,
                mcp_server_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS virtual_tools (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mcp_server_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                enabled INTEGER DEFAULT 1,
                approval_state TEXT DEFAULT 'pending',
                risk_level TEXT DEFAULT 'low',
                execution_type TEXT NOT NULL,
                config TEXT,
                config_fingerprint TEXT,
                approval_metadata TEXT,
                blocked_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(mcp_server_id, name),
                FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE
            )
        """)

        # User permissions for MCP servers
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_mcp_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                mcp_server_id INTEGER NOT NULL,
                can_access INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, mcp_server_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE
            )
        """)

        # Token-refresh audit log. Historically created only by
        # scripts/migrate_add_refresh_tokens.py — fresh installs that never
        # ran the migration would silently swallow log_token_audit() errors
        # via its broad except. Owning the schema here makes init idempotent
        # for fresh and migrated DBs alike.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS backend_mcp_token_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mcp_server_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                success BOOLEAN DEFAULT 1,
                error_message TEXT,
                old_expires_at TIMESTAMP,
                new_expires_at TIMESTAMP,
                triggered_by TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_backend_token_audit_server "
            "ON backend_mcp_token_audit(mcp_server_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_backend_token_audit_timestamp "
            "ON backend_mcp_token_audit(timestamp)"
        )

        # Add refresh_token_encrypted column if missing (migration for existing DBs)
        try:
            cursor.execute("ALTER TABLE mcp_servers ADD COLUMN refresh_token_encrypted TEXT")
            logger.info("Added refresh_token_encrypted column to mcp_servers")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Add timeout column if missing (migration for existing DBs)
        try:
            cursor.execute("ALTER TABLE mcp_servers ADD COLUMN timeout INTEGER DEFAULT NULL")
            logger.info("Added timeout column to mcp_servers")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Multi-transport columns (migration for existing DBs)
        transport_columns = [
            ("transport_type", "TEXT DEFAULT 'http'"),
            ("command", "TEXT"),
            ("command_args", "TEXT"),
            ("pipe_path", "TEXT"),
            ("expose_port", "INTEGER"),
            ("working_dir", "TEXT"),
            ("env_vars", "TEXT"),
            ("min_workers", "INTEGER DEFAULT NULL"),
            ("max_workers", "INTEGER DEFAULT NULL"),
            ("approval_state", "TEXT DEFAULT 'pending'"),
            ("risk_level", "TEXT DEFAULT 'low'"),
            ("config_fingerprint", "TEXT"),
            ("allowlist_policy", "TEXT"),
            ("approval_metadata", "TEXT"),
            ("blocked_reason", "TEXT"),
        ]
        for column_name, column_def in transport_columns:
            try:
                cursor.execute(f"ALTER TABLE mcp_servers ADD COLUMN {column_name} {column_def}")
                logger.info(f"Added {column_name} column to mcp_servers")
            except sqlite3.OperationalError:
                pass  # Column already exists

        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_servers_enabled ON mcp_servers(enabled)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_servers_status ON mcp_servers(status)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mcp_servers_tool_prefix ON mcp_servers(tool_prefix)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_tool_mappings_tool_name ON tool_mappings(tool_name)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_tool_mappings_mcp_server_id"
            " ON tool_mappings(mcp_server_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_user_mcp_permissions_user_id"
            " ON user_mcp_permissions(user_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_user_mcp_permissions_mcp_server_id"
            " ON user_mcp_permissions(mcp_server_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mcp_servers_approval_state ON mcp_servers(approval_state)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_virtual_tools_server_id ON virtual_tools(mcp_server_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_virtual_tools_approval_state ON virtual_tools(approval_state)"
        )

        conn.commit()
    logger.info("✓ MCP database tables initialized")

    # Backfill data for rows created before risk_level / allowlist_policy columns
    # existed. This is idempotent — safe to run on every startup.
    with _db_conn(db_path, row_factory=sqlite3.Row) as conn:
        cursor = conn.cursor()
        # Correct risk_level for stdio/pipe servers that received DEFAULT 'low'
        cursor.execute(
            "UPDATE mcp_servers SET risk_level = 'high'"
            " WHERE transport_type IN ('stdio', 'pipe') AND risk_level = 'low'"
        )
        # Populate allowlist_policy where it is NULL or an empty JSON object
        rows = cursor.execute(
            "SELECT * FROM mcp_servers"
            " WHERE allowlist_policy IS NULL OR TRIM(allowlist_policy) IN ('', '{}')"
        ).fetchall()
        for row in rows:
            server = dict(row)
            if isinstance(server.get("command_args"), str):
                try:
                    server["command_args"] = json.loads(server["command_args"])
                except (json.JSONDecodeError, TypeError):
                    server["command_args"] = []
            if isinstance(server.get("env_vars"), str):
                try:
                    parsed = json.loads(server["env_vars"])
                    server["env_vars"] = parsed if isinstance(parsed, dict) else {}
                except (json.JSONDecodeError, TypeError):
                    server["env_vars"] = {}
            policy = derive_server_allowlist_policy(server)
            cursor.execute(
                "UPDATE mcp_servers SET allowlist_policy = ? WHERE id = ?",
                (json.dumps(policy), server["id"]),
            )
        if rows:
            logger.info(f"Backfilled allowlist_policy for {len(rows)} MCP server(s)")


def create_mcp_server(
    db_path: str,
    name: str,
    url: str,
    description: Optional[str] = None,
    tool_prefix: Optional[str] = None,
    enabled: bool = True,
    auth_type: str = "none",
    auth_token: Optional[str] = None,
    routing_strategy: str = "prefix",
    timeout: Optional[int] = None,
    transport_type: str = "http",
    command: Optional[str] = None,
    command_args: Optional[List[str]] = None,
    pipe_path: Optional[str] = None,
    expose_port: Optional[int] = None,
    working_dir: Optional[str] = None,
    env_vars: Optional[Dict[str, str]] = None,
    min_workers: Optional[int] = None,
    max_workers: Optional[int] = None,
) -> int:
    """Create a new MCP server entry.

    Args:
        db_path: Path to SQLite database
        name: Server name (unique)
        url: Backend MCP server URL
        description: Optional description
        tool_prefix: Tool prefix for routing (e.g., "rag_")
        enabled: Whether server is enabled
        auth_type: Auth method for backend ("none", "bearer", "basic")
        auth_token: Token for backend auth
        routing_strategy: Routing strategy ("prefix", "explicit", "auto")
        timeout: Per-server request timeout in seconds (None = use global default)

    Returns:
        int: Created server ID

    Raises:
        sqlite3.IntegrityError: If name already exists
    """
    # Encrypt auth_token before storing
    encrypted_token = None
    if auth_token:
        try:
            encrypted_token = encrypt_token(auth_token)
        except RuntimeError:
            # Crypto not initialized — store as-is (dev/test mode)
            encrypted_token = auth_token
            logger.warning("Crypto not initialized, storing auth_token as plaintext")

    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        normalized_transport = (transport_type or "http").lower()
        config_for_fingerprint = {
            "transport_type": normalized_transport,
            "url": url,
            "command": command,
            "command_args": command_args or [],
            "pipe_path": pipe_path,
            "working_dir": working_dir,
            "env_vars": env_vars or {},
        }
        config_fingerprint = build_server_fingerprint(config_for_fingerprint)
        risk_level = default_risk_level(normalized_transport)
        allowlist_policy_obj = derive_server_allowlist_policy(config_for_fingerprint)
        approval_state = APPROVAL_PENDING
        blocked_reason = "Server is pending whitelist approval"

        cursor.execute(
            """
            INSERT INTO mcp_servers (
                name, description, url, tool_prefix, enabled,
                auth_type, auth_token, routing_strategy, timeout, updated_at,
                transport_type, command, command_args, pipe_path, expose_port, working_dir, env_vars,
                min_workers, max_workers,
                approval_state, risk_level, config_fingerprint, allowlist_policy, approval_metadata, blocked_reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                description,
                url,
                tool_prefix,
                1 if enabled else 0,
                auth_type,
                encrypted_token,
                routing_strategy,
                timeout,
                datetime.now(timezone.utc).isoformat(),
                normalized_transport,
                command,
                json.dumps(command_args or []),
                pipe_path,
                expose_port,
                working_dir,
                json.dumps(env_vars or {}),
                min_workers,
                max_workers,
                approval_state,
                risk_level,
                config_fingerprint,
                json.dumps(allowlist_policy_obj),
                json.dumps({}),
                blocked_reason,
            ),
        )

        server_id = cursor.lastrowid
        conn.commit()

    logger.info(f"Created MCP server: {name} (id={server_id})")
    return cast(int, server_id)


def get_mcp_server(db_path: str, server_id: int) -> Optional[Dict[str, Any]]:
    """Get MCP server by ID.

    Args:
        db_path: Path to SQLite database
        server_id: Server ID

    Returns:
        Dict with server data or None if not found
    """
    with _db_conn(db_path, row_factory=sqlite3.Row) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM mcp_servers WHERE id = ?", (server_id,))
        row = cursor.fetchone()

    if row:
        return _decrypt_server_dict(dict(row))
    return None


def get_mcp_server_by_name(db_path: str, name: str) -> Optional[Dict[str, Any]]:
    """Get MCP server by name.

    Args:
        db_path: Path to SQLite database
        name: Server name

    Returns:
        Dict with server data or None if not found
    """
    with _db_conn(db_path, row_factory=sqlite3.Row) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM mcp_servers WHERE name = ?", (name,))
        row = cursor.fetchone()

    if row:
        return _decrypt_server_dict(dict(row))
    return None


def list_mcp_servers(
    db_path: str, enabled_only: bool = False, user_id: Optional[int] = None
) -> List[Dict[str, Any]]:
    """List all MCP servers.

    Args:
        db_path: Path to SQLite database
        enabled_only: Filter only enabled servers
        user_id: Filter by user permissions (if provided)

    Returns:
        List of server dicts
    """
    with _db_conn(db_path, row_factory=sqlite3.Row) as conn:
        cursor = conn.cursor()

        if user_id:
            # Get servers with user permissions
            query = """
                SELECT s.* FROM mcp_servers s
                LEFT JOIN user_mcp_permissions p ON s.id = p.mcp_server_id AND p.user_id = ?
                WHERE (p.can_access = 1 OR p.id IS NULL)
            """
            params = [user_id]

            if enabled_only:
                query += " AND s.enabled = 1"

            query += " ORDER BY s.name"

        else:
            query = "SELECT * FROM mcp_servers"
            params = []

            if enabled_only:
                query += " WHERE enabled = 1"

            query += " ORDER BY name"

        cursor.execute(query, params)
        rows = cursor.fetchall()

    servers: List[Dict[str, Any]] = []
    for row in rows:
        server = _decrypt_server_dict(dict(row))
        if isinstance(server.get("allowlist_policy"), str):
            try:
                server["allowlist_policy"] = json.loads(server["allowlist_policy"])
            except json.JSONDecodeError:
                server["allowlist_policy"] = {}
        if isinstance(server.get("approval_metadata"), str):
            try:
                server["approval_metadata"] = json.loads(server["approval_metadata"])
            except json.JSONDecodeError:
                server["approval_metadata"] = {}
        servers.append(server)
    return servers


def update_mcp_server(db_path: str, server_id: int, **fields) -> bool:
    """Update MCP server fields.

    Args:
        db_path: Path to SQLite database
        server_id: Server ID
        **fields: Fields to update (must be valid column names)

    Returns:
        bool: True if updated, False if not found
    """
    if not fields:
        return False

    # Whitelist of allowed column names to prevent SQL injection
    ALLOWED_COLUMNS = {
        "name",
        "description",
        "url",
        "tool_prefix",
        "enabled",
        "auth_type",
        "auth_token",
        "routing_strategy",
        "status",
        "last_health_check",
        "last_error",
        "tools_count",
        "updated_at",
        "refresh_token_hash",
        "refresh_token_encrypted",
        "token_expires_at",
        "token_last_refreshed",
        "refresh_endpoint",
        "timeout",
        "transport_type",
        "command",
        "command_args",
        "pipe_path",
        "expose_port",
        "working_dir",
        "env_vars",
        "min_workers",
        "max_workers",
        "approval_state",
        "risk_level",
        "config_fingerprint",
        "allowlist_policy",
        "approval_metadata",
        "blocked_reason",
    }

    # Reject any keys not in the whitelist
    invalid_keys = set(fields.keys()) - ALLOWED_COLUMNS - {"updated_at"}
    if invalid_keys:
        logger.error(f"Rejected invalid column names in update_mcp_server: {invalid_keys}")
        raise ValueError(f"Invalid column names: {invalid_keys}")

    # Encrypt auth_token if being updated
    if "auth_token" in fields and fields["auth_token"]:
        try:
            fields["auth_token"] = encrypt_token(fields["auth_token"])
        except RuntimeError:
            logger.warning("Crypto not initialized, storing auth_token as plaintext")
    if "command_args" in fields and fields["command_args"] is not None:
        fields["command_args"] = json.dumps(fields["command_args"])
    if "env_vars" in fields and fields["env_vars"] is not None:
        fields["env_vars"] = json.dumps(fields["env_vars"])
    if "allowlist_policy" in fields and fields["allowlist_policy"] is not None:
        fields["allowlist_policy"] = json.dumps(fields["allowlist_policy"])
    if "approval_metadata" in fields and fields["approval_metadata"] is not None:
        fields["approval_metadata"] = json.dumps(fields["approval_metadata"])

    current = get_mcp_server(db_path, server_id)
    if current:
        merged = {**current, **fields}
        if isinstance(merged.get("command_args"), str):
            merged["command_args"] = json.loads(merged["command_args"] or "[]")
        if isinstance(merged.get("env_vars"), str):
            merged["env_vars"] = json.loads(merged["env_vars"] or "{}")
        normalized_transport = (merged.get("transport_type") or "http").lower()
        merged["transport_type"] = normalized_transport
        new_fingerprint = build_server_fingerprint(merged)
        fields["config_fingerprint"] = new_fingerprint
        fields["risk_level"] = default_risk_level(normalized_transport)
        current_fingerprint = current.get("config_fingerprint")
        current_state = (current.get("approval_state") or APPROVAL_PENDING).lower()
        fingerprint_changed = current_fingerprint != new_fingerprint
        
        if current_state == APPROVAL_APPROVED and fingerprint_changed:
            fields["approval_state"] = APPROVAL_PENDING
            fields["blocked_reason"] = "Configuration changed and requires whitelist re-approval"

    # Add updated_at timestamp
    fields["updated_at"] = datetime.now(timezone.utc).isoformat()

    # Build SET clause (safe — keys validated against whitelist)
    set_clause = ", ".join([f"{key} = ?" for key in fields.keys()])
    values = list(fields.values()) + [server_id]

    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(f"UPDATE mcp_servers SET {set_clause} WHERE id = ?", values)
        rows_affected = cursor.rowcount
        conn.commit()

    if rows_affected > 0:
        logger.info(f"Updated MCP server {server_id}: {fields}")
        return True

    return False


def update_server_health(
    db_path: str,
    server_id: int,
    status: str,
    tools_count: Optional[int] = None,
    error: Optional[str] = None,
):
    """Update server health status.

    Args:
        db_path: Path to SQLite database
        server_id: Server ID
        status: Status ("online", "offline", "error")
        tools_count: Number of tools available
        error: Error message if any
    """
    fields: Dict[str, Any] = {
        "status": status,
        "last_health_check": datetime.now(timezone.utc).isoformat(),
        "last_error": error,
    }

    if tools_count is not None:
        fields["tools_count"] = tools_count

    update_mcp_server(db_path, server_id, **fields)


def mark_server_online_if_active(db_path: str, server_id: int, tools_count: int) -> bool:
    """Record healthy STDIO discovery only while the server remains active."""
    now = datetime.now(timezone.utc).isoformat()
    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE mcp_servers
            SET status = ?, last_health_check = ?, last_error = NULL,
                tools_count = ?, updated_at = ?
            WHERE id = ? AND enabled = 1 AND approval_state = ?
            """,
            ("online", now, tools_count, now, server_id, APPROVAL_APPROVED),
        )
        return cursor.rowcount > 0


def delete_mcp_server(db_path: str, server_id: int) -> bool:
    """Delete MCP server.

    Args:
        db_path: Path to SQLite database
        server_id: Server ID

    Returns:
        bool: True if deleted, False if not found
    """
    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM mcp_servers WHERE id = ?", (server_id,))
        rows_affected = cursor.rowcount
        conn.commit()

    if rows_affected > 0:
        logger.info(f"Deleted MCP server {server_id}")
        return True

    return False


# Tool mappings


def create_tool_mapping(db_path: str, tool_name: str, mcp_server_id: int) -> int:
    """Create explicit tool to MCP server mapping.

    Args:
        db_path: Path to SQLite database
        tool_name: Tool name
        mcp_server_id: MCP server ID

    Returns:
        int: Mapping ID
    """
    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO tool_mappings (tool_name, mcp_server_id, created_at)
            VALUES (?, ?, ?)
            """,
            (tool_name, mcp_server_id, datetime.now(timezone.utc).isoformat()),
        )
        mapping_id = cursor.lastrowid
        conn.commit()

    logger.info(f"Created tool mapping: {tool_name} -> server {mcp_server_id}")
    return cast(int, mapping_id)


def get_tool_mapping(db_path: str, tool_name: str) -> Optional[int]:
    """Get MCP server ID for a tool.

    Args:
        db_path: Path to SQLite database
        tool_name: Tool name

    Returns:
        MCP server ID or None
    """
    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT mcp_server_id FROM tool_mappings WHERE tool_name = ?", (tool_name,))
        row = cursor.fetchone()

    if row:
        return cast(int, row[0])
    return None


def list_tool_mappings(db_path: str, mcp_server_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """List tool mappings.

    Args:
        db_path: Path to SQLite database
        mcp_server_id: Filter by MCP server ID (optional)

    Returns:
        List of mapping dicts
    """
    with _db_conn(db_path, row_factory=sqlite3.Row) as conn:
        cursor = conn.cursor()

        if mcp_server_id:
            cursor.execute(
                "SELECT * FROM tool_mappings WHERE mcp_server_id = ? ORDER BY tool_name",
                (mcp_server_id,),
            )
        else:
            cursor.execute("SELECT * FROM tool_mappings ORDER BY tool_name")

        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def delete_tool_mapping(db_path: str, tool_name: str) -> bool:
    """Delete tool mapping.

    Args:
        db_path: Path to SQLite database
        tool_name: Tool name

    Returns:
        bool: True if deleted
    """
    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tool_mappings WHERE tool_name = ?", (tool_name,))
        rows_affected = cursor.rowcount
        conn.commit()

    return bool(rows_affected > 0)


# User permissions


def set_user_mcp_permission(
    db_path: str, user_id: int, mcp_server_id: int, can_access: bool = True
) -> int:
    """Set user permission for MCP server.

    Args:
        db_path: Path to SQLite database
        user_id: User ID
        mcp_server_id: MCP server ID
        can_access: Whether user can access this server

    Returns:
        int: Permission ID
    """
    now = datetime.now(timezone.utc).isoformat()

    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO user_mcp_permissions (user_id, mcp_server_id, can_access, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id, mcp_server_id) DO UPDATE SET
                can_access = excluded.can_access,
                updated_at = excluded.updated_at
            """,
            (user_id, mcp_server_id, 1 if can_access else 0, now, now),
        )
        permission_id = cursor.lastrowid
        conn.commit()

    logger.info(f"Set MCP permission: user {user_id} -> server {mcp_server_id} = {can_access}")
    return cast(int, permission_id)


def get_user_mcp_permissions(db_path: str, user_id: int) -> List[Dict[str, Any]]:
    """Get all MCP permissions for a user.

    Args:
        db_path: Path to SQLite database
        user_id: User ID

    Returns:
        List of permission dicts
    """
    with _db_conn(db_path, row_factory=sqlite3.Row) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT p.*, s.name as server_name
            FROM user_mcp_permissions p
            JOIN mcp_servers s ON p.mcp_server_id = s.id
            WHERE p.user_id = ?
            ORDER BY s.name
            """,
            (user_id,),
        )
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def check_user_mcp_access(db_path: str, user_id: int, mcp_server_id: int) -> bool:
    """Check if user has access to MCP server.

    Args:
        db_path: Path to SQLite database
        user_id: User ID
        mcp_server_id: MCP server ID

    Returns:
        bool: True if user has access (or no explicit permission exists)
    """
    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT can_access FROM user_mcp_permissions WHERE user_id = ? AND mcp_server_id = ?",
            (user_id, mcp_server_id),
        )
        row = cursor.fetchone()

    # If no explicit permission, default to True (allow access)
    if row is None:
        return True

    return bool(row[0])


# Token Management & Audit (NEW)


def log_token_audit(
    db_path: str,
    mcp_server_id: int,
    event_type: str,
    success: bool = True,
    error_message: Optional[str] = None,
    old_expires_at: Optional[datetime] = None,
    new_expires_at: Optional[datetime] = None,
    triggered_by: str = "manual",
) -> None:
    """Log token refresh operation to audit table.

    Args:
        db_path: Path to SQLite database
        mcp_server_id: MCP server ID
        event_type: Event type ('refresh', 'manual_refresh', 'refresh_failed')
        success: Whether operation succeeded
        error_message: Error message if failed
        old_expires_at: Previous expiration time
        new_expires_at: New expiration time
        triggered_by: What triggered refresh ('proactive', 'reactive_401', 'manual', 'startup')
    """
    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO backend_mcp_token_audit
                (mcp_server_id, event_type, success, error_message,
                 old_expires_at, new_expires_at, triggered_by, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mcp_server_id,
                    event_type,
                    1 if success else 0,
                    error_message,
                    old_expires_at.isoformat() if old_expires_at else None,
                    new_expires_at.isoformat() if new_expires_at else None,
                    triggered_by,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

            conn.commit()
            logger.debug(
                f"Token audit logged: server={mcp_server_id}, "
                f"event={event_type}, success={success}, triggered_by={triggered_by}"
            )

        except Exception as e:
            logger.error(f"Failed to log token audit: {e}")
            conn.rollback()


def get_token_audit_logs(
    db_path: str, mcp_server_id: Optional[int] = None, limit: int = 100
) -> List[Dict[str, Any]]:
    """Get token audit logs.

    Args:
        db_path: Path to SQLite database
        mcp_server_id: Filter by MCP server ID (optional)
        limit: Maximum number of logs to return

    Returns:
        List of audit log dicts with server name joined
    """
    with _db_conn(db_path, row_factory=sqlite3.Row) as conn:
        cursor = conn.cursor()

        if mcp_server_id:
            cursor.execute(
                """
                SELECT a.*, s.name as server_name
                FROM backend_mcp_token_audit a
                JOIN mcp_servers s ON a.mcp_server_id = s.id
                WHERE a.mcp_server_id = ?
                ORDER BY a.timestamp DESC
                LIMIT ?
                """,
                (mcp_server_id, limit),
            )
        else:
            cursor.execute(
                """
                SELECT a.*, s.name as server_name
                FROM backend_mcp_token_audit a
                JOIN mcp_servers s ON a.mcp_server_id = s.id
                ORDER BY a.timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )

        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def update_mcp_server_token(
    db_path: str,
    server_id: int,
    access_token: str,
    token_expires_at: datetime,
    refresh_token_hash: Optional[str] = None,
) -> None:
    """Update MCP server tokens after refresh.

    Args:
        db_path: Path to SQLite database
        server_id: MCP server ID
        access_token: New access token
        token_expires_at: New expiration time
        refresh_token_hash: New refresh token hash if backend rotated it
    """
    now = datetime.now(timezone.utc).isoformat()

    # Encrypt access token before storing
    encrypted_access_token = access_token
    try:
        encrypted_access_token = encrypt_token(access_token)
    except RuntimeError:
        logger.warning("Crypto not initialized, storing access_token as plaintext")

    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        try:
            if refresh_token_hash:
                # Backend rotated refresh token - update both
                cursor.execute(
                    """
                    UPDATE mcp_servers
                    SET auth_token = ?,
                        token_expires_at = ?,
                        refresh_token_hash = ?,
                        token_last_refreshed = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        encrypted_access_token,
                        token_expires_at.isoformat(),
                        refresh_token_hash,
                        now,
                        now,
                        server_id,
                    ),
                )
            else:
                # Only update access token
                cursor.execute(
                    """
                    UPDATE mcp_servers
                    SET auth_token = ?,
                        token_expires_at = ?,
                        token_last_refreshed = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (encrypted_access_token, token_expires_at.isoformat(), now, now, server_id),
                )

            rows_affected = cursor.rowcount
            conn.commit()

            if rows_affected > 0:
                logger.info(
                    f"Updated tokens for server {server_id}: "
                    f"expires_at={token_expires_at.isoformat()}, "
                    f"rotated_refresh={refresh_token_hash is not None}"
                )
            else:
                logger.warning(f"No server found with id {server_id} to update tokens")

        except Exception as e:
            logger.error(f"Failed to update server tokens: {e}")
            conn.rollback()
            raise


def get_servers_needing_refresh(db_path: str, threshold_minutes: int = 5) -> List[Dict[str, Any]]:
    """Get MCP servers whose tokens will expire soon.

    Args:
        db_path: Path to SQLite database
        threshold_minutes: Refresh if expires within N minutes

    Returns:
        List of server dicts with expiring tokens
    """
    from datetime import timedelta

    threshold = datetime.now(timezone.utc) + timedelta(minutes=threshold_minutes)

    with _db_conn(db_path, row_factory=sqlite3.Row) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM mcp_servers
            WHERE enabled = 1
              AND refresh_token_hash IS NOT NULL
              AND token_expires_at IS NOT NULL
              AND datetime(token_expires_at) <= datetime(?)
            ORDER BY token_expires_at ASC
            """,
            (threshold.isoformat(),),
        )
        rows = cursor.fetchall()

    return [_decrypt_server_dict(dict(row)) for row in rows]


def update_server_approval(
    db_path: str,
    server_id: int,
    approval_state: str,
    actor: str,
    blocked_reason: Optional[str] = None,
    allowlist_policy: Optional[Dict[str, Any]] = None,
) -> bool:
    server = get_mcp_server(db_path, server_id)
    if not server:
        return False

    now = datetime.now(timezone.utc).isoformat()
    metadata = dict(server.get("approval_metadata") or {})
    metadata.update({"actor": actor, "updated_at": now, "approval_state": approval_state})

    policy = allowlist_policy
    if approval_state == APPROVAL_APPROVED:
        if policy is None:
            policy = derive_server_allowlist_policy(server)
        if not server_matches_allowlist_policy(server, policy):
            return False

    updates: Dict[str, Any] = {
        "approval_state": approval_state,
        "approval_metadata": metadata,
        "blocked_reason": blocked_reason,
    }
    if policy is not None:
        updates["allowlist_policy"] = policy

    if approval_state == APPROVAL_APPROVED:
        updates["blocked_reason"] = None
    return update_mcp_server(db_path, server_id, **updates)


def list_pending_mcp_servers(db_path: str) -> List[Dict[str, Any]]:
    return [s for s in list_mcp_servers(db_path) if s.get("approval_state") == APPROVAL_PENDING]


def create_virtual_tool(
    db_path: str,
    mcp_server_id: int,
    name: str,
    description: Optional[str],
    execution_type: str,
    config: Optional[Dict[str, Any]],
    enabled: bool = True,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    tool_obj = {"name": name, "execution_type": execution_type, "config": config or {}}
    fingerprint = build_virtual_tool_fingerprint(tool_obj)
    risk_level = RISK_LOW
    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO virtual_tools (
                mcp_server_id, name, description, enabled, approval_state, risk_level,
                execution_type, config, config_fingerprint, approval_metadata, blocked_reason,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mcp_server_id,
                name,
                description,
                1 if enabled else 0,
                APPROVAL_PENDING,
                risk_level,
                execution_type,
                json.dumps(config or {}),
                fingerprint,
                json.dumps({}),
                "Virtual tool is pending whitelist approval",
                now,
                now,
            ),
        )
        tool_id = cursor.lastrowid
        conn.commit()
    return cast(int, tool_id)


def list_virtual_tools(
    db_path: str,
    mcp_server_id: Optional[int] = None,
    enabled_only: bool = False,
    approved_only: bool = False,
) -> List[Dict[str, Any]]:
    with _db_conn(db_path, row_factory=sqlite3.Row) as conn:
        cursor = conn.cursor()
        query = "SELECT vt.*, s.name AS source_server_name FROM virtual_tools vt JOIN mcp_servers s ON vt.mcp_server_id = s.id"
        clauses = []
        params: List[Any] = []
        if mcp_server_id is not None:
            clauses.append("vt.mcp_server_id = ?")
            params.append(mcp_server_id)
        if enabled_only:
            clauses.append("vt.enabled = 1")
        if approved_only:
            clauses.append("vt.approval_state = ?")
            params.append(APPROVAL_APPROVED)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY vt.name"
        cursor.execute(query, params)
        rows = cursor.fetchall()

    tools = []
    for row in rows:
        item = dict(row)
        if isinstance(item.get("config"), str):
            try:
                item["config"] = json.loads(item["config"])
            except json.JSONDecodeError:
                item["config"] = {}
        if isinstance(item.get("approval_metadata"), str):
            try:
                item["approval_metadata"] = json.loads(item["approval_metadata"])
            except json.JSONDecodeError:
                item["approval_metadata"] = {}
        tools.append(item)
    return tools


def get_virtual_tool(db_path: str, tool_id: int) -> Optional[Dict[str, Any]]:
    tools = list_virtual_tools(db_path)
    for item in tools:
        if item["id"] == tool_id:
            return item
    return None


def get_virtual_tool_by_name(
    db_path: str, name: str, mcp_server_id: Optional[int] = None
) -> Optional[Dict[str, Any]]:
    tools = list_virtual_tools(db_path, mcp_server_id=mcp_server_id)
    for item in tools:
        if item["name"] == name:
            return item
    return None


def update_virtual_tool(db_path: str, tool_id: int, **fields) -> bool:
    if not fields:
        return False
    allowed = {
        "name",
        "description",
        "enabled",
        "approval_state",
        "risk_level",
        "execution_type",
        "config",
        "config_fingerprint",
        "approval_metadata",
        "blocked_reason",
        "updated_at",
    }
    invalid = set(fields.keys()) - allowed
    if invalid:
        raise ValueError(f"Invalid column names: {invalid}")

    current = get_virtual_tool(db_path, tool_id)
    if not current:
        return False

    if "config" in fields and fields["config"] is not None:
        fields["config"] = json.dumps(fields["config"])
    if "approval_metadata" in fields and fields["approval_metadata"] is not None:
        fields["approval_metadata"] = json.dumps(fields["approval_metadata"])

    merged = {**current, **fields}
    if isinstance(merged.get("config"), str):
        merged["config"] = json.loads(merged["config"] or "{}")
    new_fp = build_virtual_tool_fingerprint(merged)
    fields["config_fingerprint"] = new_fp
    if (
        current.get("approval_state") == APPROVAL_APPROVED
        and current.get("config_fingerprint") != new_fp
    ):
        fields["approval_state"] = APPROVAL_PENDING
        fields["blocked_reason"] = "Configuration changed and requires whitelist re-approval"

    fields["updated_at"] = datetime.now(timezone.utc).isoformat()
    set_clause = ", ".join([f"{key} = ?" for key in fields.keys()])
    values = list(fields.values()) + [tool_id]
    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(f"UPDATE virtual_tools SET {set_clause} WHERE id = ?", values)
        conn.commit()
        return cursor.rowcount > 0


def update_virtual_tool_approval(
    db_path: str,
    tool_id: int,
    approval_state: str,
    actor: str,
    blocked_reason: Optional[str] = None,
) -> bool:
    tool = get_virtual_tool(db_path, tool_id)
    if not tool:
        return False
    metadata = dict(tool.get("approval_metadata") or {})
    metadata.update(
        {
            "actor": actor,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "approval_state": approval_state,
        }
    )
    updates: Dict[str, Any] = {
        "approval_state": approval_state,
        "approval_metadata": metadata,
        "blocked_reason": blocked_reason,
    }
    if approval_state == APPROVAL_APPROVED:
        updates["blocked_reason"] = None
    return update_virtual_tool(db_path, tool_id, **updates)


def list_pending_virtual_tools(db_path: str) -> List[Dict[str, Any]]:
    return [
        tool
        for tool in list_virtual_tools(db_path)
        if tool.get("approval_state") == APPROVAL_PENDING
    ]


def list_mcp_servers_by_state(
    db_path: str, approval_state: Optional[str] = None
) -> List[Dict[str, Any]]:
    """List MCP servers optionally filtered by approval state.

    Args:
        db_path: Path to SQLite database
        approval_state: One of 'pending', 'approved', 'rejected', 'revoked',
                        or None to return servers in every state.

    Returns:
        List of server dicts
    """
    servers = list_mcp_servers(db_path)
    if approval_state is None:
        return servers
    return [s for s in servers if s.get("approval_state") == approval_state]


def delete_virtual_tool(db_path: str, tool_id: int) -> bool:
    """Delete a virtual tool by ID.

    Args:
        db_path: Path to SQLite database
        tool_id: Virtual tool ID

    Returns:
        bool: True if deleted, False if not found
    """
    with _db_conn(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM virtual_tools WHERE id = ?", (tool_id,))
        rows_affected = cursor.rowcount
        conn.commit()

    if rows_affected > 0:
        logger.info(f"Deleted virtual tool {tool_id}")
        return True

    return False


def list_virtual_tools_by_state(
    db_path: str, approval_state: Optional[str] = None
) -> List[Dict[str, Any]]:
    """List virtual tools optionally filtered by approval state.

    Args:
        db_path: Path to SQLite database
        approval_state: One of 'pending', 'approved', 'rejected', 'revoked',
                        or None to return tools in every state.

    Returns:
        List of virtual tool dicts
    """
    tools = list_virtual_tools(db_path)
    if approval_state is None:
        return tools
    return [t for t in tools if t.get("approval_state") == approval_state]
