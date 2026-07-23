"""Passkey and TOTP endpoints for Whitelist-only verification sessions."""

from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
from datetime import datetime, timezone
from urllib.parse import quote

import qrcode
import qrcode.image.svg

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json, parse_authentication_credential_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from authmcp_gateway.admin.routes import api_error_handler, get_config
from authmcp_gateway.admin.whitelist_api import require_whitelist_session
from authmcp_gateway.admin.whitelist_auth import (
    clear_session_cookies,
    create_session_for_request,
    set_session_cookie,
)
from authmcp_gateway.auth import totp, webauthn_store, whitelist_recovery, whitelist_transaction
from authmcp_gateway.rate_limiter import get_rate_limiter
from authmcp_gateway.security.logger import log_security_event

__all__ = [
    "api_whitelist_passkeys",
    "api_whitelist_security_methods_status",
    "api_whitelist_passkey_registration_options",
    "api_whitelist_passkey_registration_verify",
    "api_whitelist_passkey_authentication_options",
    "api_whitelist_passkey_authentication_verify",
    "api_whitelist_passkey_rename",
    "api_whitelist_passkey_revoke",
    "api_whitelist_totp_status",
    "api_whitelist_totp_setup",
    "api_whitelist_totp_confirm",
    "api_whitelist_totp_verify",
    "api_whitelist_totp_remove",
    "api_whitelist_authorize_prepare",
    "api_whitelist_authorize_verify",
    "api_whitelist_recovery_status",
    "whitelist_recovery_page",
    "api_whitelist_recovery_claim",
    "api_whitelist_recovery_passkey_options",
    "api_whitelist_recovery_passkey_verify",
    "api_whitelist_recovery_totp_reset",
    "api_whitelist_recovery_rotate",
]

_RECOVERY_COOKIE = "authmcp_recovery_grant"


def _user_id(request: Request) -> int:
    return int(request.state.user_id)


def _binding(request: Request) -> str:
    value = getattr(request.state, "admin_session_jti", "")
    if not value:
        raise ValueError("Missing authenticated admin session binding")
    return str(value)


def _payload_error(message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code)


async def _json_payload(request: Request) -> dict | None:
    try:
        payload = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _challenge_from_credential(credential: dict) -> bytes:
    try:
        encoded = credential["response"]["clientDataJSON"]
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        challenge = json.loads(raw)["challenge"]
        result = base64.urlsafe_b64decode(challenge + "=" * (-len(challenge) % 4))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed WebAuthn credential response") from exc
    if len(result) != 32:
        raise ValueError("Invalid WebAuthn challenge")
    return result


def _options(value: object) -> dict:
    return json.loads(options_to_json(value))


def _audit(request: Request, event_type: str, severity: str = "low") -> None:
    log_security_event(
        db_path=get_config(request).auth.sqlite_path,
        event_type=event_type,
        severity=severity,
        user_id=_user_id(request),
        username=str(getattr(request.state, "username", "") or ""),
        ip_address=request.client.host if request.client else None,
        endpoint=request.url.path,
        method=request.method,
    )


def _audit_recovery(
    request: Request, event_type: str, *, user_id: int | None = None, severity: str = "high"
) -> None:
    """Audit recovery activity without recording codes, grants, or credential data."""
    log_security_event(
        db_path=get_config(request).auth.sqlite_path,
        event_type=event_type,
        severity=severity,
        user_id=user_id,
        ip_address=request.client.host if request.client else None,
        endpoint=request.url.path,
        method=request.method,
    )


def _is_loopback(value: str | None) -> bool:
    if not value:
        return False
    if value.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _require_local_recovery(request: Request) -> JSONResponse | None:
    """Fail closed unless both the network peer and requested host are loopback."""
    client_host = request.client.host if request.client else None
    forwarded = {"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"}
    if (
        not any(request.headers.get(header) for header in forwarded)
        and _is_loopback(client_host)
        and _is_loopback(request.url.hostname)
    ):
        return None
    _audit_recovery(request, "whitelist_recovery_remote_denied", severity="high")
    return _no_store(_payload_error("Whitelist recovery is available only from this machine", 403))


def _no_store(response: HTMLResponse | JSONResponse) -> HTMLResponse | JSONResponse:
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _require_session(request: Request) -> dict | JSONResponse:
    return require_whitelist_session(request)


def _recovery_context(request: Request) -> tuple[int, str] | JSONResponse:
    local_error = _require_local_recovery(request)
    if local_error is not None:
        return local_error
    handle = request.cookies.get(_RECOVERY_COOKIE)
    user_id = whitelist_recovery.get_recovery_grant(get_config(request).auth.sqlite_path, handle)
    if user_id is None:
        return _payload_error("Recovery grant is invalid or expired", 401)
    binding = hashlib.sha256(str(handle).encode("utf-8")).hexdigest()
    return user_id, f"recovery:{binding}"


def _set_recovery_cookie(response: JSONResponse, request: Request, handle: str) -> None:
    response.set_cookie(
        _RECOVERY_COOKIE,
        handle,
        path="/whitelist/recovery",
        max_age=600,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
    )


def _rp(request: Request) -> tuple[str, str]:
    config = get_config(request).whitelist_auth
    return webauthn_store.resolve_rp_id(request, config), webauthn_store.resolve_origin(
        request, config
    )


def _current_passkeys(request: Request, rp_id: str | None = None) -> tuple[str, list[dict]]:
    # Browsers do not reliably send Origin for same-origin GET requests.  Listing
    # credentials only needs the host-bound RP ID; origin verification remains
    # mandatory for every WebAuthn ceremony POST.
    current_rp = rp_id or webauthn_store.resolve_rp_id(request, get_config(request).whitelist_auth)
    keys = webauthn_store.list_passkeys(get_config(request).auth.sqlite_path, _user_id(request))
    return current_rp, [key for key in keys if key.get("rp_id") == current_rp]


def _fresh_passkey_session(request: Request, session: dict) -> bool:
    if (
        session.get("assurance_level") != "passkey"
        or session.get("credential_type") != "passkey"
        or not session.get("credential_id")
    ):
        return False
    try:
        verified_at = datetime.fromisoformat(str(session["verified_at"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return False
    if (datetime.now(timezone.utc) - verified_at).total_seconds() > get_config(
        request
    ).whitelist_auth.passkey_fresh_seconds:
        return False
    try:
        passkey = webauthn_store.get_passkey_by_credential_id(
            get_config(request).auth.sqlite_path, str(session["credential_id"])
        )
    except ValueError:
        return False
    return bool(
        passkey
        and int(passkey["user_id"]) == _user_id(request)
        and passkey["rp_id"] == session.get("credential_rp_id")
    )


def _require_passkey_enrollment_authority(request: Request, session: dict) -> JSONResponse | None:
    """Never let a fallback Whitelist session enroll a stronger credential."""
    if _fresh_passkey_session(request, session):
        return None
    return _payload_error(
        "Registering a passkey requires a fresh assertion from an existing passkey; "
        "use local recovery when no passkey is available",
        403,
    )


async def whitelist_recovery_page(request: Request) -> HTMLResponse:
    from authmcp_gateway.admin.routes import render_template

    local_error = _require_local_recovery(request)
    response = render_template("admin/whitelist_recovery.html", recovery_local=local_error is None)
    if local_error is not None:
        response.status_code = 403
    return _no_store(response)


@api_error_handler
async def api_whitelist_recovery_claim(request: Request) -> JSONResponse:
    local_error = _require_local_recovery(request)
    if local_error is not None:
        return local_error
    payload = await _json_payload(request)
    code = payload.get("code") if payload else None
    grant = whitelist_recovery.redeem_recovery_code(
        get_config(request).auth.sqlite_path, code if isinstance(code, str) else ""
    )
    if grant is None:
        _audit_recovery(request, "whitelist_recovery_claim_failed")
        return _payload_error("Recovery code is invalid or expired", 401)
    handle, user_id = grant
    response = JSONResponse({"message": "Recovery access granted", "expires_in": 600})
    _set_recovery_cookie(response, request, handle)
    _audit_recovery(request, "whitelist_recovery_claimed", user_id=user_id)
    return _no_store(response)


@api_error_handler
async def api_whitelist_recovery_passkey_options(request: Request) -> JSONResponse:
    context = _recovery_context(request)
    if isinstance(context, JSONResponse):
        return context
    user_id, binding = context
    try:
        rp_id, _ = _rp(request)
        db_path = get_config(request).auth.sqlite_path
        challenge_id, challenge = webauthn_store.create_challenge(
            db_path,
            user_id=user_id,
            admin_session_jti=binding,
            rp_id=rp_id,
            purpose="recovery_register",
        )
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name="AuthMCP Gateway",
            user_id=str(user_id).encode(),
            user_name=f"recovery-{user_id}",
            challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            ),
        )
    except ValueError as exc:
        return _payload_error(str(exc))
    return _no_store(JSONResponse({"challenge_id": challenge_id, "publicKey": _options(options)}))


@api_error_handler
async def api_whitelist_recovery_passkey_verify(request: Request) -> JSONResponse:
    context = _recovery_context(request)
    if isinstance(context, JSONResponse):
        return context
    user_id, binding = context
    payload = await _json_payload(request)
    credential = payload.get("credential") if payload else None
    if not isinstance(credential, dict):
        return _payload_error("A WebAuthn credential is required")
    try:
        rp_id, origin = _rp(request)
        challenge = _challenge_from_credential(credential)
        if (
            webauthn_store.get_and_consume_challenge(
                get_config(request).auth.sqlite_path,
                challenge=challenge,
                user_id=user_id,
                admin_session_jti=binding,
                rp_id=rp_id,
                purpose="recovery_register",
            )
            is None
        ):
            return _payload_error("WebAuthn challenge is expired or already used")
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
        label = payload.get("label")
        if label is not None and (not isinstance(label, str) or len(label.strip()) > 80):
            return _payload_error("Passkey label must be at most 80 characters")
        webauthn_store.create_passkey(
            get_config(request).auth.sqlite_path,
            user_id=user_id,
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            rp_id=rp_id,
            label=label.strip() if isinstance(label, str) and label.strip() else None,
        )
    except ValueError as exc:
        return _payload_error(str(exc))
    except Exception:
        return _payload_error("Passkey registration could not be verified")
    whitelist_recovery.revoke_recovery_grant(
        get_config(request).auth.sqlite_path, request.cookies.get(_RECOVERY_COOKIE)
    )
    response = JSONResponse({"message": "Passkey registered"}, status_code=201)
    response.delete_cookie(_RECOVERY_COOKIE, path="/whitelist/recovery")
    _audit_recovery(request, "whitelist_recovery_passkey_registered", user_id=user_id)
    return _no_store(response)


@api_error_handler
async def api_whitelist_recovery_totp_reset(request: Request) -> JSONResponse:
    context = _recovery_context(request)
    if isinstance(context, JSONResponse):
        return context
    user_id, _ = context
    removed = totp.remove_totp(get_config(request).auth.sqlite_path, user_id)
    _audit_recovery(request, "whitelist_recovery_totp_reset", user_id=user_id)
    return _no_store(JSONResponse({"message": "Authenticator reset", "removed": removed}))


@api_error_handler
async def api_whitelist_recovery_rotate(request: Request) -> JSONResponse:
    context = _recovery_context(request)
    if isinstance(context, JSONResponse):
        return context
    user_id, _ = context
    code = whitelist_recovery.create_recovery_code(get_config(request).auth.sqlite_path, user_id)
    whitelist_recovery.revoke_recovery_grant(
        get_config(request).auth.sqlite_path, request.cookies.get(_RECOVERY_COOKIE)
    )
    _audit_recovery(request, "whitelist_recovery_credential_rotated", user_id=user_id)
    response = JSONResponse({"recovery_url": f"/whitelist/recover#code={quote(code)}"})
    response.delete_cookie(_RECOVERY_COOKIE, path="/whitelist/recovery")
    return _no_store(response)


@api_error_handler
async def api_whitelist_security_methods_status(request: Request) -> JSONResponse:
    """Safe setup status; deliberately available before Whitelist unlock."""
    try:
        rp_id = webauthn_store.resolve_rp_id(request, get_config(request).whitelist_auth)
        passkey_supported = True
    except ValueError:
        rp_id, passkey_supported = "", False
    keys = webauthn_store.list_passkeys(get_config(request).auth.sqlite_path, _user_id(request))
    credential = totp.get_totp_credential(get_config(request).auth.sqlite_path, _user_id(request))
    return JSONResponse(
        {
            "passkey_supported": passkey_supported,
            "has_passkey_for_current_rp": bool(
                rp_id and any(key.get("rp_id") == rp_id for key in keys)
            ),
            "has_any_passkey": bool(keys),
            "totp_configured": bool(credential and credential.get("confirmed_at")),
            "legacy_bootstrap_available": bool(get_config(request).whitelist_token),
            "current_rp_id": rp_id,
            # Origin is deliberately not resolved here: browsers commonly omit it
            # for this same-origin GET. POST ceremony endpoints validate it.
            "current_origin": "",
        }
    )


@api_error_handler
async def api_whitelist_passkeys(request: Request) -> JSONResponse:
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    rp_id, current = _current_passkeys(request)
    all_keys = webauthn_store.list_passkeys(get_config(request).auth.sqlite_path, _user_id(request))
    other = [key for key in all_keys if key.get("rp_id") != rp_id]
    return JSONResponse({"current_rp_id": rp_id, "passkeys": current, "other_rp_passkeys": other})


@api_error_handler
async def api_whitelist_passkey_registration_options(request: Request) -> JSONResponse:
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    authority_error = _require_passkey_enrollment_authority(request, session)
    if authority_error is not None:
        return authority_error
    try:
        rp_id, _ = _rp(request)
        db_path, user_id = get_config(request).auth.sqlite_path, _user_id(request)
        challenge_id, challenge = webauthn_store.create_challenge(
            db_path,
            user_id=user_id,
            admin_session_jti=_binding(request),
            rp_id=rp_id,
            purpose="register",
        )
        excluded = [
            PublicKeyCredentialDescriptor(
                id=webauthn_store.credential_id_to_bytes(key["credential_id"])
            )
            for key in webauthn_store.list_passkeys(db_path, user_id)
            if key.get("rp_id") == rp_id
        ]
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name="AuthMCP Gateway",
            user_id=str(user_id).encode(),
            user_name=str(getattr(request.state, "username", user_id)),
            challenge=challenge,
            exclude_credentials=excluded or None,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            ),
        )
    except ValueError as exc:
        return _payload_error(str(exc))
    return JSONResponse({"challenge_id": challenge_id, "publicKey": _options(options)})


@api_error_handler
async def api_whitelist_passkey_registration_verify(request: Request) -> JSONResponse:
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    authority_error = _require_passkey_enrollment_authority(request, session)
    if authority_error is not None:
        return authority_error
    payload = await _json_payload(request)
    if payload is None or not isinstance(payload.get("credential"), dict):
        return _payload_error("A WebAuthn credential is required")
    try:
        rp_id, origin = _rp(request)
        challenge = _challenge_from_credential(payload["credential"])
        row = webauthn_store.get_and_consume_challenge(
            get_config(request).auth.sqlite_path,
            challenge=challenge,
            user_id=_user_id(request),
            admin_session_jti=_binding(request),
            rp_id=rp_id,
            purpose="register",
        )
        if row is None:
            return _payload_error("WebAuthn challenge is expired or already used", 400)
        verified = verify_registration_response(
            credential=payload["credential"],
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
        label = payload.get("label")
        if label is not None and (not isinstance(label, str) or len(label.strip()) > 80):
            return _payload_error("Passkey label must be at most 80 characters")
        webauthn_store.create_passkey(
            get_config(request).auth.sqlite_path,
            user_id=_user_id(request),
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            rp_id=rp_id,
            label=label.strip() if isinstance(label, str) and label.strip() else None,
        )
    except ValueError as exc:
        return _payload_error(str(exc))
    except Exception:
        return _payload_error("Passkey registration could not be verified")
    _audit(request, "whitelist_passkey_registered")
    response = JSONResponse({"message": "Passkey registered"}, status_code=201)
    clear_session_cookies(response)
    return response


@api_error_handler
async def api_whitelist_passkey_authentication_options(request: Request) -> JSONResponse:
    try:
        rp_id, _ = _rp(request)
        db_path, user_id = get_config(request).auth.sqlite_path, _user_id(request)
        keys = [
            key
            for key in webauthn_store.list_passkeys(db_path, user_id)
            if key.get("rp_id") == rp_id
        ]
        if not keys:
            return _payload_error("No passkey is registered", 404)
        _, challenge = webauthn_store.create_challenge(
            db_path,
            user_id=user_id,
            admin_session_jti=_binding(request),
            rp_id=rp_id,
            purpose="authenticate",
        )
        options = generate_authentication_options(
            rp_id=rp_id,
            challenge=challenge,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=webauthn_store.credential_id_to_bytes(key["credential_id"])
                )
                for key in keys
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
    except ValueError as exc:
        return _payload_error(str(exc))
    return JSONResponse({"publicKey": _options(options)})


@api_error_handler
async def api_whitelist_passkey_authentication_verify(request: Request) -> JSONResponse:
    payload = await _json_payload(request)
    if payload is None or not isinstance(payload.get("credential"), dict):
        return _payload_error("A WebAuthn credential is required")
    try:
        rp_id, origin = _rp(request)
        credential = parse_authentication_credential_json(payload["credential"])
        challenge = _challenge_from_credential(payload["credential"])
        db_path, user_id = get_config(request).auth.sqlite_path, _user_id(request)
        passkey = webauthn_store.get_passkey_by_credential_id(db_path, credential.id)
        if passkey is None or int(passkey["user_id"]) != user_id or passkey["rp_id"] != rp_id:
            return _payload_error("Unknown passkey", 401)
        if (
            webauthn_store.get_and_consume_challenge(
                db_path,
                challenge=challenge,
                user_id=user_id,
                admin_session_jti=_binding(request),
                rp_id=rp_id,
                purpose="authenticate",
            )
            is None
        ):
            return _payload_error("WebAuthn challenge is expired or already used")
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=passkey["public_key_bytes"],
            credential_current_sign_count=int(passkey["sign_count"]),
            require_user_verification=True,
        )
        if not webauthn_store.update_sign_count(
            db_path, credential_id=credential.id, sign_count=verified.new_sign_count
        ):
            return _payload_error("Passkey sign count was rejected", 401)
        handle, session = create_session_for_request(
            request,
            method="passkey",
            credential_type="passkey",
            credential_id=credential.id,
            credential_rp_id=rp_id,
        )
    except ValueError as exc:
        return _payload_error(str(exc))
    except Exception:
        return _payload_error("Passkey authentication could not be verified", 401)
    response = JSONResponse(
        {
            "whitelist_session": {
                "verified": True,
                "method": session["method"],
                "expires_at": session["expires_at"],
            }
        }
    )
    set_session_cookie(response, request, handle)
    _audit(request, "whitelist_passkey_verified")
    return response


@api_error_handler
async def api_whitelist_passkey_rename(request: Request) -> JSONResponse:
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    payload = await _json_payload(request)
    label = payload.get("label") if payload else None
    if not isinstance(label, str):
        return _payload_error("Passkey label is required")
    try:
        changed = webauthn_store.rename_passkey(
            get_config(request).auth.sqlite_path,
            user_id=_user_id(request),
            credential_id=str(request.path_params["credential_id"]),
            label=label.strip(),
        )
    except ValueError as exc:
        return _payload_error(str(exc))
    if changed:
        _audit(request, "whitelist_passkey_renamed")
    return JSONResponse(
        {"message": "Passkey renamed"} if changed else {"error": "Passkey not found"},
        status_code=200 if changed else 404,
    )


@api_error_handler
async def api_whitelist_passkey_revoke(request: Request) -> JSONResponse:
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    if not _fresh_passkey_session(request, session):
        return _payload_error(
            "Removing a passkey requires a fresh passkey verification on this site", 403
        )
    db_path, user_id = get_config(request).auth.sqlite_path, _user_id(request)
    credential_id = str(request.path_params["credential_id"])
    passkey = webauthn_store.get_passkey_by_credential_id(db_path, credential_id)
    rp_id, _ = _rp(request)
    if passkey is None or int(passkey["user_id"]) != user_id or passkey["rp_id"] != rp_id:
        return _payload_error("Passkey not found for this site", 404)
    result = webauthn_store.revoke_passkey(db_path, user_id=user_id, credential_id=credential_id)
    if result == "recovery_required":
        return _payload_error(
            "Cannot remove the final passkey without an active recovery credential", 409
        )
    if result == "not_found":
        return _payload_error("Passkey not found", 404)
    _audit(request, "whitelist_passkey_revoked", "medium")
    response = JSONResponse({"message": "Passkey revoked"})
    clear_session_cookies(response)
    return response


@api_error_handler
async def api_whitelist_totp_status(request: Request) -> JSONResponse:
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    credential = totp.get_totp_credential(get_config(request).auth.sqlite_path, _user_id(request))
    return JSONResponse({"configured": bool(credential and credential.get("confirmed_at"))})


@api_error_handler
async def api_whitelist_totp_setup(request: Request) -> JSONResponse:
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    existing = totp.get_totp_credential(
        get_config(request).auth.sqlite_path, _user_id(request), confirmed_only=True
    )
    if existing is not None:
        return _payload_error(
            "An authenticator is already configured; remove it with passkey verification first",
            409,
        )
    secret = totp.generate_secret()
    totp.create_totp_pending(get_config(request).auth.sqlite_path, _user_id(request), secret)
    username = quote(str(getattr(request.state, "username", _user_id(request))), safe="")
    uri = f"otpauth://totp/AuthMCP%20Gateway:{username}?secret={secret}&issuer=AuthMCP%20Gateway&algorithm=SHA1&digits=6&period=30"
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, border=3)
    buffer = io.BytesIO()
    image.save(buffer)
    qr_data_uri = "data:image/svg+xml;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")
    _audit(request, "whitelist_totp_setup_started")
    return _no_store(
        JSONResponse({"secret": secret, "otpauth_url": uri, "qr_data_uri": qr_data_uri})
    )


def _verify_totp_request(
    request: Request, code: object, *, pending: bool
) -> tuple[int | None, JSONResponse | None]:
    if not isinstance(code, str):
        return None, _payload_error("A six-digit authenticator code is required")
    config, user_id = get_config(request), _user_id(request)
    allowed, retry_after = get_rate_limiter().check_limit(
        f"whitelist_totp:{user_id}:{'setup' if pending else 'verify'}", limit=5, window=60
    )
    if not allowed:
        return None, JSONResponse(
            {"error": "Too many verification attempts", "retry_after": retry_after},
            status_code=429,
        )
    credential = totp.get_totp_credential(
        config.auth.sqlite_path, user_id, confirmed_only=not pending
    )
    if credential is None or (pending and credential.get("confirmed_at") is not None):
        return None, _payload_error("Authenticator is not ready", 404)
    try:
        step = totp.verify_totp(
            totp.decrypt_totp_secret(str(credential["secret_encrypted"])),
            code,
            last_used_time_step=credential.get("last_used_time_step"),
        )
    except ValueError:
        step = None
    return step, (
        None
        if step is not None
        else _payload_error("Invalid or previously used authenticator code", 401)
    )


@api_error_handler
async def api_whitelist_totp_confirm(request: Request) -> JSONResponse:
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    payload = await _json_payload(request)
    step, error = _verify_totp_request(
        request, payload.get("code") if payload else None, pending=True
    )
    if error:
        return error
    if not totp.confirm_totp(get_config(request).auth.sqlite_path, _user_id(request), int(step)):
        return _payload_error("Authenticator setup is no longer pending", 409)
    _audit(request, "whitelist_totp_confirmed")
    response = JSONResponse({"message": "Authenticator configured"})
    clear_session_cookies(response)
    return response


@api_error_handler
async def api_whitelist_totp_verify(request: Request) -> JSONResponse:
    payload = await _json_payload(request)
    step, error = _verify_totp_request(
        request, payload.get("code") if payload else None, pending=False
    )
    if error:
        return error
    if not totp.mark_totp_used(get_config(request).auth.sqlite_path, _user_id(request), int(step)):
        return _payload_error("Authenticator code was already used", 401)
    handle, session = create_session_for_request(request, method="totp", credential_type="totp")
    response = JSONResponse(
        {
            "whitelist_session": {
                "verified": True,
                "method": session["method"],
                "expires_at": session["expires_at"],
            }
        }
    )
    set_session_cookie(response, request, handle)
    _audit(request, "whitelist_totp_verified")
    return response


@api_error_handler
async def api_whitelist_totp_remove(request: Request) -> JSONResponse:
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    if not _fresh_passkey_session(request, session):
        return _payload_error(
            "Removing TOTP requires a fresh passkey verification on this site", 403
        )
    if not totp.remove_totp(get_config(request).auth.sqlite_path, _user_id(request)):
        return _payload_error("Authenticator is not configured", 404)
    _audit(request, "whitelist_totp_removed", "medium")
    response = JSONResponse({"message": "Authenticator removed"})
    clear_session_cookies(response)
    return response


@api_error_handler
async def api_whitelist_authorize_prepare(request: Request) -> JSONResponse:
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    payload = await _json_payload(request)
    action = payload.get("action") if payload else None
    resource_type = payload.get("resource_type") if payload else None
    resource_id = payload.get("resource_id") if payload else None
    if (
        not isinstance(action, str)
        or not isinstance(resource_type, str)
        or isinstance(resource_id, bool)
    ):
        return _payload_error("Action, resource type, and resource ID are required")
    try:
        resource_id = int(resource_id)
        db_path, user_id = get_config(request).auth.sqlite_path, _user_id(request)
        rp_id, _ = _rp(request)
        passkeys = [
            key
            for key in webauthn_store.list_passkeys(db_path, user_id)
            if key.get("rp_id") == rp_id
        ]
        if not passkeys:
            return _payload_error("No passkey is registered for this site", 404)
        challenge_id, challenge = whitelist_transaction.prepare_authorization(
            db_path,
            user_id=user_id,
            admin_session_jti=_binding(request),
            action=action.lower(),
            resource_type=resource_type,
            resource_id=resource_id,
            rp_id=rp_id,
            ttl_seconds=get_config(request).whitelist_auth.passkey_fresh_seconds,
        )
        options = generate_authentication_options(
            rp_id=rp_id,
            challenge=challenge,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=webauthn_store.credential_id_to_bytes(passkey["credential_id"])
                )
                for passkey in passkeys
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
    except (TypeError, ValueError) as exc:
        return _payload_error(str(exc))
    _audit(request, "whitelist_transaction_authorization_prepared")
    return JSONResponse({"challenge_id": challenge_id, "webauthn_options": _options(options)})


@api_error_handler
async def api_whitelist_authorize_verify(request: Request) -> JSONResponse:
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    payload = await _json_payload(request)
    challenge_id = payload.get("challenge_id") if payload else None
    response = payload.get("webauthn_response") if payload else None
    if (
        isinstance(challenge_id, bool)
        or not isinstance(challenge_id, int)
        or not isinstance(response, dict)
    ):
        return _payload_error("Challenge ID and WebAuthn response are required")
    try:
        rp_id, origin = _rp(request)
        authorization = whitelist_transaction.verify_and_create_authorization(
            get_config(request).auth.sqlite_path,
            challenge_id=challenge_id,
            webauthn_response=response,
            user_id=_user_id(request),
            admin_session_jti=_binding(request),
            rp_id=rp_id,
            origin=origin,
            fresh_seconds=get_config(request).whitelist_auth.passkey_fresh_seconds,
        )
    except ValueError as exc:
        return _payload_error(str(exc), 401)
    except Exception:
        return _payload_error("Passkey authorization could not be verified", 401)
    _audit(request, "whitelist_transaction_authorization_verified", "medium")
    return JSONResponse(authorization, status_code=201)


@api_error_handler
async def api_whitelist_recovery_status(request: Request) -> JSONResponse:
    """Expose only recovery availability to an already verified Whitelist session."""
    session = _require_session(request)
    if isinstance(session, JSONResponse):
        return session
    db_path = get_config(request).auth.sqlite_path
    return JSONResponse(
        {"recovery_available": whitelist_recovery.recovery_status(db_path, _user_id(request))}
    )
