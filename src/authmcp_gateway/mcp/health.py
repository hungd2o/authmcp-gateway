"""Health check mechanism for backend MCP servers."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, cast

import httpx

from ._exceptions import (
    PROXY_DISCOVERY_DB_ERRORS,
    PROXY_DISCOVERY_ERRORS,
    PROXY_TOKEN_REFRESH_ERRORS,
)
from .process_manager import get_process_manager
from .proxy import get_auth_headers, parse_sse_response
from .store import list_mcp_servers, update_server_health
from .transports import PipeTransport

logger = logging.getLogger(__name__)


class HealthChecker:
    """Periodic health checker for backend MCP servers."""

    def __init__(
        self,
        db_path: str,
        interval: int = 60,
        timeout: int = 10,
        shared_session_ids: Dict[int, str] | None = None,
        shared_recovery_locks: Dict[int, asyncio.Lock] | None = None,
    ):
        """Initialize health checker.

        Args:
            db_path: Path to SQLite database
            interval: Check interval in seconds
            timeout: Request timeout in seconds
            shared_session_ids: Optional shared session dict (from McpProxy) to
                avoid creating competing sessions on single-session backends
            shared_recovery_locks: Optional per-server lock dict (from McpProxy)
                to serialize stale-session recovery across health checks and
                foreground MCP requests
        """
        self.db_path = db_path
        self.interval = interval
        self.timeout = timeout
        self._running = False
        self._task = None
        self._session_ids: Dict[int, str] = (
            shared_session_ids if shared_session_ids is not None else {}
        )
        self._recovery_locks: Dict[int, asyncio.Lock] = (
            shared_recovery_locks if shared_recovery_locks is not None else {}
        )

    def _get_recovery_lock(self, server_id: int) -> asyncio.Lock:
        lock = self._recovery_locks.get(server_id)
        if lock is None:
            lock = asyncio.Lock()
            self._recovery_locks[server_id] = lock
        return lock

    async def _check_non_http_server(self, server: Dict[str, Any]) -> Dict[str, Any]:
        """Health check for stdio/pipe transports."""
        server_id = server["id"]
        server_name = server["name"]
        transport_type = (server.get("transport_type") or "http").lower()
        start_time = datetime.now(timezone.utc)
        tools_count = 0
        request_timeout = float(server.get("timeout") or self.timeout)

        try:
            data: Dict[str, Any]
            if transport_type == "stdio":
                process_manager = get_process_manager()
                await process_manager.start_server(server_id, server)
                transport = process_manager.get_transport(server_id)
                if transport is None:
                    raise RuntimeError("STDIO transport unavailable")
                data = await transport.send_request(
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                    timeout=request_timeout,
                )
            elif transport_type == "pipe":
                pipe_path = server.get("pipe_path")
                if not pipe_path:
                    raise RuntimeError("pipe_path is required for pipe transport")
                transport = PipeTransport(pipe_path=pipe_path)
                try:
                    data = await transport.send_request(
                        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                        timeout=request_timeout,
                    )
                finally:
                    await transport.close()
            else:
                raise RuntimeError(f"Unsupported transport type: {transport_type}")

            if "result" in data and isinstance(data["result"], dict):
                tools_count = len(data["result"].get("tools", []) or [])

            response_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            update_server_health(self.db_path, server_id, status="online", tools_count=tools_count)
            return {
                "server_id": server_id,
                "server_name": server_name,
                "status": "online",
                "response_time_ms": response_time,
                "tools_count": tools_count,
                "error": None,
                "checked_at": datetime.now(timezone.utc),
            }
        except asyncio.TimeoutError:
            error_msg = f"Timeout after {request_timeout:g}s"
            update_server_health(self.db_path, server_id, status="offline", error=error_msg)
            return {
                "server_id": server_id,
                "server_name": server_name,
                "status": "offline",
                "response_time_ms": None,
                "tools_count": None,
                "error": error_msg,
                "checked_at": datetime.now(timezone.utc),
            }
        except Exception as e:
            error_msg = str(e).strip() or type(e).__name__
            update_server_health(self.db_path, server_id, status="error", error=error_msg)
            return {
                "server_id": server_id,
                "server_name": server_name,
                "status": "error",
                "response_time_ms": None,
                "tools_count": None,
                "error": error_msg,
                "checked_at": datetime.now(timezone.utc),
            }

    def start(self):
        """Start health checking background task."""
        if self._running:
            logger.warning("Health checker already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._health_check_loop())
        logger.info(f"Health checker started (interval={self.interval}s)")

    async def stop(self):
        """Stop health checking background task."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        logger.info("Health checker stopped")

    async def _health_check_loop(self):
        """Background loop that performs health checks."""
        # Initial delay to let the application finish startup
        await asyncio.sleep(5)

        while self._running:
            try:
                await self.check_all_servers()
            except Exception as e:  # noqa: BLE001 — loop guard, must never die
                # Long-running background loop. Any failure (transient
                # network glitch, DB lock, bug in a downstream call) must
                # be logged and absorbed so the health checker keeps
                # running for subsequent intervals.
                logger.error(f"Error in health check loop: {e}")

            # Wait for next check
            await asyncio.sleep(self.interval)

    async def check_all_servers(self) -> List[Dict[str, Any]]:
        """Check health of all enabled MCP servers.

        Returns:
            List of health check results
        """
        servers = list_mcp_servers(self.db_path, enabled_only=True)
        servers = [s for s in servers if s.get("approval_state") == "approved"]

        if not servers:
            logger.debug("No enabled servers to check")
            return []

        # Check all servers in parallel
        tasks = []
        for server in servers:
            tasks.append(self.check_server(server))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Log summary
        online_count = sum(
            1 for r in results if not isinstance(r, BaseException) and r["status"] == "online"
        )
        logger.info(f"Health check: {online_count}/{len(servers)} servers online")

        return [r for r in results if not isinstance(r, BaseException)]

    async def check_server(self, server: Dict[str, Any]) -> Dict[str, Any]:
        """Check health of a single MCP server.

        Args:
            server: Server dict from database

        Returns:
            Health check result dict
        """
        server_id = server["id"]
        server_name = server["name"]
        server_url = server["url"]
        transport_type = (server.get("transport_type") or "http").lower()
        if server.get("approval_state") != "approved":
            return {
                "server_id": server_id,
                "server_name": server_name,
                "status": "offline",
                "response_time_ms": None,
                "tools_count": None,
                "error": server.get("blocked_reason") or "Server is pending whitelist approval",
                "checked_at": datetime.now(timezone.utc),
            }

        if transport_type != "http":
            return await self._check_non_http_server(server)

        start_time = datetime.now(timezone.utc)

        try:
            # Prepare auth headers
            headers = self._get_auth_headers(server)

            # Per-server timeout override (DB field → global default)
            server_timeout = server.get("timeout") or self.timeout

            # Ping server with tools/list request
            async with httpx.AsyncClient(timeout=server_timeout) as client:
                # Include mcp-session-id if we have one
                session_id = self._session_ids.get(server_id)
                if session_id:
                    headers["mcp-session-id"] = session_id

                try:
                    response = await client.post(
                        server_url,
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                        headers=headers,
                    )
                except httpx.TimeoutException:
                    # Stale session can cause backends to hang instead of returning 400.
                    # If we had a session, clear it and retry with fresh initialize.
                    if session_id:
                        logger.info(
                            f"Health check: {server_name} timed out with session, "
                            "retrying with fresh initialize"
                        )
                        async with self._get_recovery_lock(server_id):
                            recovered_session = self._session_ids.get(server_id)
                            if not recovered_session or recovered_session == session_id:
                                self._session_ids.pop(server_id, None)
                                headers.pop("mcp-session-id", None)
                                recovered_session = await self._initialize_session(
                                    client, server_url, headers, server_id, server_name
                                )
                            headers.pop("mcp-session-id", None)
                            if recovered_session:
                                headers["mcp-session-id"] = recovered_session
                                response = await client.post(
                                    server_url,
                                    json={
                                        "jsonrpc": "2.0",
                                        "id": 1,
                                        "method": "tools/list",
                                        "params": {},
                                    },
                                    headers=headers,
                                )
                            else:
                                raise  # Re-raise timeout if init also failed
                    else:
                        raise  # No session to clear, genuine timeout

                # Handle 400 "no valid session" — initialize first
                if response.status_code == 400:
                    body_text = response.text[:200] if response.text else ""
                    if "session" in body_text.lower():
                        logger.info(f"Health check: {server_name} requires session, initializing")
                        async with self._get_recovery_lock(server_id):
                            current_session = self._session_ids.get(server_id)
                            if not current_session or current_session == session_id:
                                self._session_ids.pop(server_id, None)
                                headers.pop("mcp-session-id", None)
                                current_session = await self._initialize_session(
                                    client, server_url, headers, server_id, server_name
                                )
                            headers.pop("mcp-session-id", None)
                            if current_session:
                                headers["mcp-session-id"] = current_session
                                response = await client.post(
                                    server_url,
                                    json={
                                        "jsonrpc": "2.0",
                                        "id": 1,
                                        "method": "tools/list",
                                        "params": {},
                                    },
                                    headers=headers,
                                )

                # Handle 401 with token refresh
                if response.status_code == 401 and server.get("refresh_token_hash"):
                    logger.warning(
                        f"Got 401 during health check for {server_name}, attempting token refresh"
                    )

                    try:
                        from .store import get_mcp_server
                        from .token_manager import get_token_manager

                        token_mgr = get_token_manager()
                        success, error = await token_mgr.refresh_server_token(
                            server_id, triggered_by="reactive_401"
                        )

                        if success:
                            # Reload server with new token and retry
                            refreshed = get_mcp_server(self.db_path, server_id)
                            if refreshed is None:
                                logger.error(
                                    f"Server {server_name} disappeared during token refresh"
                                )
                                raise RuntimeError("server vanished mid-refresh")
                            server = refreshed
                            headers = self._get_auth_headers(server)
                            session_id = self._session_ids.get(server_id)
                            if session_id:
                                headers["mcp-session-id"] = session_id
                            response = await client.post(
                                server_url,
                                json={
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "method": "tools/list",
                                    "params": {},
                                },
                                headers=headers,
                            )
                            logger.info(
                                f"Health check retry after token refresh succeeded for {server_name}"
                            )
                        else:
                            logger.error(
                                f"Token refresh failed during health check for {server_name}: {error}"
                            )
                    except PROXY_TOKEN_REFRESH_ERRORS as refresh_error:
                        logger.error(
                            f"Exception during token refresh in health check: {refresh_error}"
                        )

                response.raise_for_status()
                data = parse_sse_response(response)

                # Calculate response time
                response_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

                # Extract tools count
                tools_count = 0
                if "result" in data and "tools" in data["result"]:
                    tools_count = len(data["result"]["tools"])

                # Update database
                update_server_health(
                    self.db_path, server_id, status="online", tools_count=tools_count
                )

                result = {
                    "server_id": server_id,
                    "server_name": server_name,
                    "status": "online",
                    "response_time_ms": response_time,
                    "tools_count": tools_count,
                    "error": None,
                    "checked_at": datetime.now(timezone.utc),
                }

                logger.debug(
                    f"Health check: {server_name} is online "
                    f"({response_time:.0f}ms, {tools_count} tools)"
                )

                return result

        except httpx.TimeoutException:
            error_msg = f"Timeout after {server_timeout}s"
            logger.warning(f"Health check: {server_name} - {error_msg}")

            update_server_health(self.db_path, server_id, status="offline", error=error_msg)

            return {
                "server_id": server_id,
                "server_name": server_name,
                "status": "offline",
                "response_time_ms": None,
                "tools_count": None,
                "error": error_msg,
                "checked_at": datetime.now(timezone.utc),
            }

        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP {e.response.status_code}: {e.response.text[:100]}"
            logger.warning(f"Health check: {server_name} - {error_msg}")

            update_server_health(self.db_path, server_id, status="error", error=error_msg)

            return {
                "server_id": server_id,
                "server_name": server_name,
                "status": "error",
                "response_time_ms": None,
                "tools_count": None,
                "error": error_msg,
                "checked_at": datetime.now(timezone.utc),
            }

        except PROXY_DISCOVERY_DB_ERRORS as e:
            # Catches everything the inner try block can realistically raise
            # that wasn't handled by the specific httpx.TimeoutException /
            # HTTPStatusError above. RuntimeError covers backends that turn
            # JSON-RPC errors into Python exceptions during initialize.
            error_msg = str(e)
            logger.error(f"Health check: {server_name} - Unexpected error: {error_msg}")

            update_server_health(self.db_path, server_id, status="error", error=error_msg)

            return {
                "server_id": server_id,
                "server_name": server_name,
                "status": "error",
                "response_time_ms": None,
                "tools_count": None,
                "error": error_msg,
                "checked_at": datetime.now(timezone.utc),
            }

    async def _initialize_session(
        self,
        client: httpx.AsyncClient,
        server_url: str,
        headers: Dict[str, str],
        server_id: int,
        server_name: str,
    ) -> str:
        """Send initialize to get mcp-session-id from a Streamable HTTP backend.

        Returns:
            Session ID string, or empty string if not available.
        """
        try:
            # Remove stale session ID for the init request
            init_headers = {k: v for k, v in headers.items() if k != "mcp-session-id"}
            resp = await client.post(
                server_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "authmcp-gateway", "version": "2.0.0"},
                    },
                },
                headers=init_headers,
            )
            session_id = resp.headers.get("mcp-session-id", "")
            if session_id:
                self._session_ids[server_id] = session_id
                logger.info(f"Health check: got session ID for {server_name}")

                # Send initialized notification (best-effort)
                try:
                    notify_headers = dict(init_headers)
                    notify_headers["mcp-session-id"] = session_id
                    await client.post(
                        server_url,
                        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                        headers=notify_headers,
                    )
                except httpx.HTTPError as notify_err:
                    # Best-effort post-init handshake; log so operators can
                    # correlate degraded backend behaviour. Same rationale as
                    # the parallel block in mcp/proxy.py.
                    logger.debug(
                        "Health-check notifications/initialized to %s failed " "(best-effort): %s",
                        server_name,
                        notify_err,
                    )

            return cast(str, session_id)
        except PROXY_DISCOVERY_ERRORS as e:
            logger.debug(f"Health check: initialize failed for {server_name}: {e}")
            return ""

    def _get_auth_headers(self, server: Dict[str, Any]) -> Dict[str, str]:
        """Get authentication headers for backend MCP server."""
        return get_auth_headers(server)


# Global health checker instance
_health_checker: Optional[HealthChecker] = None


def get_health_checker() -> HealthChecker:
    """Get global health checker instance.

    Returns:
        HealthChecker instance

    Raises:
        RuntimeError: If not initialized
    """
    if _health_checker is None:
        raise RuntimeError("Health checker not initialized")
    return _health_checker


def initialize_health_checker(
    db_path: str,
    interval: int = 60,
    timeout: int = 10,
    shared_session_ids: Dict[int, str] | None = None,
    shared_recovery_locks: Dict[int, asyncio.Lock] | None = None,
) -> HealthChecker:
    """Initialize global health checker.

    Args:
        db_path: Path to SQLite database
        interval: Check interval in seconds
        timeout: Request timeout in seconds
        shared_session_ids: Optional shared session dict from McpProxy
        shared_recovery_locks: Optional per-server recovery lock dict from McpProxy

    Returns:
        HealthChecker instance
    """
    global _health_checker
    _health_checker = HealthChecker(
        db_path,
        interval,
        timeout,
        shared_session_ids=shared_session_ids,
        shared_recovery_locks=shared_recovery_locks,
    )
    return _health_checker
