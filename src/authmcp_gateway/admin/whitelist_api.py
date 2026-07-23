"""Whitelist page APIs with a dedicated short-lived verification session."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from authmcp_gateway.admin.routes import (
    api_error_handler,
    get_config,
    get_mcp_runtime,
    render_template,
)
from authmcp_gateway.admin.whitelist_auth import (
    clear_session_cookies,
    create_session_for_request,
    get_session_for_request,
    revoke_session_for_request,
    set_session_cookie,
    verify_bootstrap_value,
)
from authmcp_gateway.security.logger import log_security_event

__all__ = [
    "admin_whitelist",
    "api_whitelist_session",
    "api_whitelist_unlock_legacy",
    "api_whitelist_lock",
    "api_whitelist_items",
    "api_whitelist_server_review",
    "api_whitelist_virtual_tool_review",
    "api_whitelist_servers_action",
    "api_whitelist_virtual_tools_action",
]


async def admin_whitelist(_: Request) -> HTMLResponse:
    return render_template("admin/whitelist_sessions.html", active_page="whitelist")


def _session_payload(session: dict | None) -> dict:
    if not session:
        return {"verified": False}
    return {
        "verified": True,
        "method": session.get("method"),
        "verified_at": session.get("verified_at"),
        "expires_at": session.get("expires_at"),
    }


def _verification_required() -> JSONResponse:
    return JSONResponse(
        {
            "error": "Whitelist verification required",
            "code": "whitelist_verification_required",
        },
        status_code=401,
    )


def _audit(
    request: Request,
    event_type: str,
    severity: str = "low",
    *,
    details: dict | None = None,
) -> None:
    log_security_event(
        db_path=get_config(request).auth.sqlite_path,
        event_type=event_type,
        severity=severity,
        details=details,
        user_id=getattr(request.state, "user_id", None),
        username=str(getattr(request.state, "username", "") or ""),
        ip_address=request.client.host if request.client else None,
        endpoint=request.url.path,
        method=request.method,
    )


def _validated_reason(
    payload: dict, *, required: bool = False
) -> tuple[str | None, JSONResponse | None]:
    reason = payload.get("reason")
    if reason is None:
        if required:
            return None, JSONResponse(
                {"error": "A reason of at least 5 characters is required"}, status_code=400
            )
        return None, None
    if not isinstance(reason, str):
        return None, JSONResponse({"error": "Reason must be text"}, status_code=400)
    reason = reason.strip()
    if len(reason) > 500:
        return None, JSONResponse(
            {"error": "Reason must be at most 500 characters"}, status_code=400
        )
    if required and len(reason) < 5:
        return None, JSONResponse(
            {"error": "A reason of at least 5 characters is required"}, status_code=400
        )
    return reason or None, None


def require_whitelist_session(request: Request) -> dict | JSONResponse:
    """Return the active Whitelist session dict, or a 401 JSONResponse if absent.

    Shared by items/servers-action/virtual-tools-action to avoid repeating the
    None-check in every handler.
    """
    session = get_session_for_request(request)
    if session is None:
        return _verification_required()
    return session


@api_error_handler
async def api_whitelist_session(request: Request) -> JSONResponse:
    """Return current Whitelist verification status (admin JWT alone is enough to check)."""
    return JSONResponse({"whitelist_session": _session_payload(get_session_for_request(request))})


@api_error_handler
async def api_whitelist_unlock_legacy(request: Request) -> JSONResponse:
    """Exchange the legacy Whitelist bootstrap token for a browser session."""
    payload = await request.json()
    supplied = str(payload.get("token") or "").strip()
    if not verify_bootstrap_value(request, supplied):
        _audit(request, "whitelist_legacy_verification_failed", "high")
        return JSONResponse({"error": "Invalid Whitelist verification value"}, status_code=401)

    from authmcp_gateway.auth import totp, webauthn_store

    db_path, user_id = get_config(request).auth.sqlite_path, int(request.state.user_id)
    if webauthn_store.list_passkeys(db_path, user_id) or totp.get_totp_credential(
        db_path, user_id, confirmed_only=True
    ):
        _audit(request, "whitelist_legacy_downgrade_denied", "high")
        return JSONResponse(
            {"error": "Legacy Whitelist verification is disabled after modern enrollment"}, status_code=403
        )

    handle, session = create_session_for_request(request, method="legacy")
    response = JSONResponse({"whitelist_session": _session_payload(session)})
    set_session_cookie(response, request, handle)
    _audit(request, "whitelist_legacy_verified", "medium")
    return response


@api_error_handler
async def api_whitelist_lock(request: Request) -> JSONResponse:
    """Revoke the current browser's Whitelist session and clear its cookies."""
    revoke_session_for_request(request)
    response = JSONResponse({"message": "Whitelist locked"})
    clear_session_cookies(response)
    _audit(request, "whitelist_session_locked")
    return response


@api_error_handler
async def api_whitelist_items(request: Request) -> JSONResponse:
    from authmcp_gateway.mcp.store import list_mcp_servers_by_state, list_virtual_tools_by_state
    from authmcp_gateway.mcp.trust import (
        APPROVAL_APPROVED,
        APPROVAL_PENDING,
        APPROVAL_REJECTED,
        APPROVAL_REVOKED,
    )

    session_or_error = require_whitelist_session(request)
    if isinstance(session_or_error, JSONResponse):
        return session_or_error

    state_param = (request.query_params.get("state") or "").strip().lower() or None
    valid_states = {APPROVAL_PENDING, APPROVAL_APPROVED, APPROVAL_REJECTED, APPROVAL_REVOKED}
    if state_param and state_param not in valid_states:
        return JSONResponse(
            {"error": f"Invalid state. Must be one of: {', '.join(sorted(valid_states))}"},
            status_code=400,
        )

    db_path = get_config(request).auth.sqlite_path
    from authmcp_gateway.mcp.whitelist_review import (
        build_server_whitelist_summary,
        build_virtual_tool_whitelist_summary,
    )

    servers = [
        build_server_whitelist_summary(s) for s in list_mcp_servers_by_state(db_path, state_param)
    ]
    virtual_tools = [
        build_virtual_tool_whitelist_summary(t)
        for t in list_virtual_tools_by_state(db_path, state_param)
    ]
    return JSONResponse(
        {
            "servers": servers,
            "virtual_tools": virtual_tools,
            "state_filter": state_param,
            "whitelist_session": _session_payload(session_or_error),
        }
    )


@api_error_handler
async def api_whitelist_server_review(request: Request) -> JSONResponse:
    from authmcp_gateway.mcp.store import get_mcp_server
    from authmcp_gateway.mcp.whitelist_review import build_server_whitelist_review

    session = require_whitelist_session(request)
    if isinstance(session, JSONResponse):
        return session
    server = get_mcp_server(
        get_config(request).auth.sqlite_path, int(request.path_params["server_id"])
    )
    if server is None:
        return JSONResponse({"error": "Server not found"}, status_code=404)
    return JSONResponse({"review": build_server_whitelist_review(server)})


@api_error_handler
async def api_whitelist_virtual_tool_review(request: Request) -> JSONResponse:
    from authmcp_gateway.mcp.store import get_virtual_tool
    from authmcp_gateway.mcp.whitelist_review import build_virtual_tool_whitelist_review

    session = require_whitelist_session(request)
    if isinstance(session, JSONResponse):
        return session
    tool = get_virtual_tool(
        get_config(request).auth.sqlite_path, int(request.path_params["tool_id"])
    )
    if tool is None:
        return JSONResponse({"error": "Virtual tool not found"}, status_code=404)
    return JSONResponse({"review": build_virtual_tool_whitelist_review(tool)})


@api_error_handler
async def api_whitelist_servers_action(request: Request) -> JSONResponse:
    from authmcp_gateway.mcp.store import get_mcp_server, update_server_approval

    session_or_error = require_whitelist_session(request)
    if isinstance(session_or_error, JSONResponse):
        return session_or_error

    payload = await request.json()
    action = (payload.get("action") or "").lower()
    server_id = int(request.path_params["server_id"])
    reason, reason_error = _validated_reason(payload, required=action in {"reject", "revoke"})
    if reason_error is not None:
        return reason_error
    approval_state = {"approve": "approved", "reject": "rejected", "revoke": "revoked"}.get(action)
    if not approval_state:
        _audit(
            request, "whitelist_server_action_rejected", "medium", details={"server_id": server_id}
        )
        return JSONResponse({"error": "Invalid action"}, status_code=400)

    expected_fingerprint = payload.get("config_fingerprint")
    authorization_fingerprint = None
    if not isinstance(expected_fingerprint, str) or not expected_fingerprint:
        return JSONResponse(
            {"error": "Reload this server before changing its decision"}, status_code=400
        )

    server = get_mcp_server(get_config(request).auth.sqlite_path, server_id)
    if server is None:
        return JSONResponse({"error": "Server not found"}, status_code=404)
    if approval_state == "approved" and server.get("transport_type") in {"stdio", "pipe"}:
        from authmcp_gateway.auth.whitelist_transaction import consume_authorization

        authorization_id = payload.get("authorization_id")
        if isinstance(authorization_id, bool) or not isinstance(authorization_id, int):
            _audit(
                request,
                "whitelist_server_fresh_authorization_required",
                "high",
                details={"server_id": server_id, "action": action},
            )
            return JSONResponse(
                {
                    "error": "A fresh passkey authorization is required for this high-risk server",
                    "code": "fresh_authorization_required",
                },
                status_code=403,
            )
        result, authorization_fingerprint = consume_authorization(
            get_config(request).auth.sqlite_path,
            authorization_id=authorization_id,
            user_id=int(request.state.user_id),
            admin_session_jti=str(getattr(request.state, "admin_session_jti", "")),
            action="approve",
            resource_type="server",
            resource_id=server_id,
            expected_fingerprint=expected_fingerprint,
        )
        if result == "stale":
            _audit(
                request,
                "whitelist_server_authorization_stale",
                "high",
                details={"server_id": server_id, "action": action},
            )
            return JSONResponse(
                {"error": "Server changed; reload and review it again"}, status_code=409
            )
        if result != "consumed" or not authorization_fingerprint:
            return JSONResponse(
                {
                    "error": "A fresh passkey authorization is required for this high-risk server",
                    "code": "fresh_authorization_required",
                },
                status_code=403,
            )
        expected_fingerprint = authorization_fingerprint

    runtime = get_mcp_runtime(request)
    success = update_server_approval(
        get_config(request).auth.sqlite_path,
        server_id=server_id,
        approval_state=approval_state,
        actor=str(request.state.username or request.state.user_id),
        blocked_reason=reason,
        allowlist_policy=None,
        expected_fingerprint=expected_fingerprint,
    )
    if not success:
        if approval_state == "approved" and authorization_fingerprint:
            from authmcp_gateway.auth.whitelist_transaction import unconsume_authorization

            unconsume_authorization(
                get_config(request).auth.sqlite_path,
                authorization_id=authorization_id,
                user_id=int(request.state.user_id),
                admin_session_jti=str(getattr(request.state, "admin_session_jti", "")),
                action="approve",
                resource_type="server",
                resource_id=server_id,
                config_fingerprint=authorization_fingerprint,
            )
        _audit(
            request,
            "whitelist_server_update_conflict",
            "high",
            details={"server_id": server_id, "action": action},
        )
        return JSONResponse(
            {
                "error": "Server changed or does not match the allowlist policy; reload and review it again"
            },
            status_code=409,
        )
    if approval_state != "approved":
        await runtime.block_and_stop_server(server_id)
    if approval_state == "approved":
        await runtime.allow_server(server_id)
    _audit(
        request,
        f"whitelist_server_{approval_state}",
        "high" if server.get("transport_type") in {"stdio", "pipe"} else "medium",
        details={"server_id": server_id, "action": action},
    )
    return JSONResponse({"message": f"Server {approval_state}"})


@api_error_handler
async def api_whitelist_virtual_tools_action(request: Request) -> JSONResponse:
    from authmcp_gateway.mcp.store import get_virtual_tool, update_virtual_tool_approval

    session_or_error = require_whitelist_session(request)
    if isinstance(session_or_error, JSONResponse):
        return session_or_error

    tool_id = int(request.path_params["tool_id"])
    payload = await request.json()
    action = (payload.get("action") or "").lower()
    reason, reason_error = _validated_reason(payload, required=action in {"reject", "revoke"})
    if reason_error is not None:
        return reason_error
    approval_state = {"approve": "approved", "reject": "rejected", "revoke": "revoked"}.get(action)
    if not approval_state:
        _audit(
            request,
            "whitelist_virtual_tool_action_rejected",
            "medium",
            details={"tool_id": tool_id},
        )
        return JSONResponse({"error": "Invalid action"}, status_code=400)

    expected_fingerprint = payload.get("config_fingerprint")
    authorization_fingerprint = None
    if not isinstance(expected_fingerprint, str) or not expected_fingerprint:
        return JSONResponse(
            {"error": "Reload this virtual tool before changing its decision"}, status_code=400
        )

    tool = get_virtual_tool(get_config(request).auth.sqlite_path, tool_id)
    if tool is None:
        return JSONResponse({"error": "Virtual tool not found"}, status_code=404)
    if approval_state == "approved" and tool.get("execution_type") in {
        "http_call",
        "stdio_call",
        "pipeline_call",
    }:
        from authmcp_gateway.auth.whitelist_transaction import consume_authorization

        authorization_id = payload.get("authorization_id")
        if isinstance(authorization_id, bool) or not isinstance(authorization_id, int):
            _audit(
                request,
                "whitelist_virtual_tool_fresh_authorization_required",
                "high",
                details={"tool_id": tool_id, "action": action},
            )
            return JSONResponse(
                {
                    "error": "A fresh passkey authorization is required for this high-risk virtual tool",
                    "code": "fresh_authorization_required",
                },
                status_code=403,
            )
        result, authorization_fingerprint = consume_authorization(
            get_config(request).auth.sqlite_path,
            authorization_id=authorization_id,
            user_id=int(request.state.user_id),
            admin_session_jti=str(getattr(request.state, "admin_session_jti", "")),
            action="approve",
            resource_type="virtual_tool",
            resource_id=tool_id,
            expected_fingerprint=expected_fingerprint,
        )
        if result == "stale":
            _audit(
                request,
                "whitelist_virtual_tool_authorization_stale",
                "high",
                details={"tool_id": tool_id, "action": action},
            )
            return JSONResponse(
                {"error": "Virtual tool changed; reload and review it again"}, status_code=409
            )
        if result != "consumed" or not authorization_fingerprint:
            return JSONResponse(
                {
                    "error": "A fresh passkey authorization is required for this high-risk virtual tool",
                    "code": "fresh_authorization_required",
                },
                status_code=403,
            )
        expected_fingerprint = authorization_fingerprint

    success = update_virtual_tool_approval(
        get_config(request).auth.sqlite_path,
        tool_id=tool_id,
        approval_state=approval_state,
        actor=str(request.state.username or request.state.user_id),
        blocked_reason=reason,
        expected_fingerprint=expected_fingerprint,
    )
    if not success:
        if approval_state == "approved" and authorization_fingerprint:
            from authmcp_gateway.auth.whitelist_transaction import unconsume_authorization

            unconsume_authorization(
                get_config(request).auth.sqlite_path,
                authorization_id=authorization_id,
                user_id=int(request.state.user_id),
                admin_session_jti=str(getattr(request.state, "admin_session_jti", "")),
                action="approve",
                resource_type="virtual_tool",
                resource_id=tool_id,
                config_fingerprint=authorization_fingerprint,
            )
        _audit(
            request,
            "whitelist_virtual_tool_update_conflict",
            "high",
            details={"tool_id": tool_id, "action": action},
        )
        return JSONResponse(
            {"error": "Virtual tool changed; reload and review it again"}, status_code=409
        )
    _audit(
        request,
        f"whitelist_virtual_tool_{approval_state}",
        "high" if tool.get("execution_type") in {"stdio_call", "pipeline_call"} else "medium",
        details={"tool_id": tool_id, "action": action},
    )
    return JSONResponse({"message": f"Virtual tool {approval_state}"})
