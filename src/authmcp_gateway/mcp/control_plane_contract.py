"""Shared constants and helpers for the admin-only control-plane contract."""

from __future__ import annotations

import hashlib
import html
import json
import re
import threading
from typing import Any
from uuid import UUID

from pydantic import ValidationError

CONTROL_PLANE_EXTENSION = "com.authmcp/control-plane-v1"
CONTROL_PLANE_PROTOCOL_VERSION = "2025-11-25"
CONTROL_PLANE_METHOD_PREFIX = f"{CONTROL_PLANE_EXTENSION}/"
CONTROL_PLANE_METHODS = {
    "descriptor": f"{CONTROL_PLANE_METHOD_PREFIX}descriptor",
    "entities_list": f"{CONTROL_PLANE_METHOD_PREFIX}entities/list",
    "entities_get": f"{CONTROL_PLANE_METHOD_PREFIX}entities/get",
    "entities_create": f"{CONTROL_PLANE_METHOD_PREFIX}entities/create",
    "entities_update": f"{CONTROL_PLANE_METHOD_PREFIX}entities/update",
    "entities_delete": f"{CONTROL_PLANE_METHOD_PREFIX}entities/delete",
    "actions_run": f"{CONTROL_PLANE_METHOD_PREFIX}actions/run",
    "jobs_get": f"{CONTROL_PLANE_METHOD_PREFIX}jobs/get",
    "jobs_list": f"{CONTROL_PLANE_METHOD_PREFIX}jobs/list",
    "jobs_cancel": f"{CONTROL_PLANE_METHOD_PREFIX}jobs/cancel",
    "status_get": f"{CONTROL_PLANE_METHOD_PREFIX}status/get",
}
CONTROL_PLANE_OPERATIONS = frozenset((*CONTROL_PLANE_METHODS, "reconcile"))
CONTROL_PLANE_MUTATING_OPERATIONS = frozenset(
    {"entities_create", "entities_update", "entities_delete", "actions_run", "jobs_cancel", "reconcile"}
)
CONTROL_PLANE_RISKS = frozenset({"safe", "mutating", "destructive"})
CONTROL_PLANE_CONFIRMATIONS = {
    "safe": "immediate",
    "mutating": "confirm",
    "destructive": "typed_confirm",
}
CONTROL_PLANE_CONFIRMATION_ORDER = {"immediate": 0, "confirm": 1, "typed_confirm": 2}
CONTROL_PLANE_COLUMN_KINDS = frozenset(
    {"text", "code", "path", "badge", "number", "datetime", "bool"}
)
CONTROL_PLANE_ACTION_ICONS = frozenset({"scan-search", "rotate-cw", "trash-2"})
CONTROL_PLANE_ENTITY_OPS = frozenset({"list", "create", "update", "delete"})
CONTROL_PLANE_ERROR_CODES = frozenset(
    {"CONFLICT", "VALIDATION_FAILED", "UNSUPPORTED", "UNAVAILABLE", "INTERNAL"}
)
CONTROL_PLANE_DEFAULT_PAGE_SIZE = 50
CONTROL_PLANE_MAX_PAGE_SIZE = 200
CONTROL_PLANE_MAX_ENTITY_TYPES = 32
CONTROL_PLANE_MAX_COLUMNS_PER_ENTITY = 24
CONTROL_PLANE_MAX_SCHEMA_PROPERTIES = 64
CONTROL_PLANE_MAX_ACTIONS = 32
CONTROL_PLANE_MAX_STATUS_FIELDS = 64
CONTROL_PLANE_MAX_LABEL_CHARS = 120
CONTROL_PLANE_MAX_ERROR_TEXT_CHARS = 2048
CONTROL_PLANE_MAX_VALUE_CHARS = 8192
CONTROL_PLANE_TRUNCATION_SUFFIX = "...[truncated]"
CONTROL_PLANE_SENSITIVE_KEY_FRAGMENTS = frozenset(
    {
        "token",
        "secret",
        "password",
        "authorization",
        "api_key",
        "apikey",
        "credential",
        "cookie",
        "path",
        "working_dir",
        "env",
    }
)

# Compatibility aliases used by current store/tests.
ERROR_CODES = CONTROL_PLANE_ERROR_CODES
MAX_ERROR_LENGTH = CONTROL_PLANE_MAX_ERROR_TEXT_CHARS


class DescriptorValidationError(ValueError):
    """Raised when a descriptor violates the control-plane contract."""


# A schema-declared `pattern` is a native regex descriptor supplied by a
# management provider profile, not fully trusted input. `maxLength` on the
# pattern field bounds its size, but a short pattern can still exhibit
# catastrophic backtracking (nested quantifiers) against an attacker-chosen
# value and hang the thread doing synchronous validation. CPython cannot
# preempt a running `re` match, so this runs the match on a daemon thread
# and only waits a bounded amount of time for it; a pattern that doesn't
# finish in time is treated as a non-match (the orphaned thread is later
# abandoned/GC'd once it does finish).
_REGEX_MATCH_TIMEOUT_SECONDS = 0.1


def _bounded_fullmatch(pattern: str, value: str) -> bool:
    outcome: list[bool] = []

    def _run() -> None:
        try:
            outcome.append(re.fullmatch(pattern, value) is not None)
        except re.error:
            outcome.append(False)

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(_REGEX_MATCH_TIMEOUT_SECONDS)
    if worker.is_alive() or not outcome:
        return False
    return outcome[0]


_SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?ix)"
    r"(?P<key>access[_-]?token|refresh[_-]?token|id[_-]?token|token|secret|"
    r"password|authorization|api[_-]?key|apikey|credential(?:s)?|cookie|"
    r"path|working[_-]?dir|env)"
    r"(?P<separator>\s*(?:=|:)\s*)"
    r"(?P<value>(?!(?:\[REDACTED\]))(?:\"[^\"]*\"|'[^']*'|[^\s,&;}\]]+))"
)
_AUTHORIZATION_HEADER_PATTERN = re.compile(
    r"(?ix)\bauthorization\s*[:=]\s*(?:bearer\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,&;}\]]+)"
)
_BEARER_TOKEN_PATTERN = re.compile(r"(?i)\bbearer\s+[^\s,&;}\]]+")
_FILESYSTEM_PATH_PATTERN = re.compile(
    r"(?<![:\w/])(?:[a-z]:[\\/]|/)(?:[^\s,;\]\[{}'\"`]+)", re.IGNORECASE
)


def is_control_plane_method(method: object) -> bool:
    return isinstance(method, str) and method.startswith(CONTROL_PLANE_METHOD_PREFIX)


def validate_idempotency_key(value: str) -> str:
    UUID(str(value))
    return str(value)


def normalize_page_size(value: int | None) -> int:
    if value is None:
        return CONTROL_PLANE_DEFAULT_PAGE_SIZE
    if value < 1 or value > CONTROL_PLANE_MAX_PAGE_SIZE:
        raise ValueError(
            f"page_size must be between 1 and {CONTROL_PLANE_MAX_PAGE_SIZE}"
        )
    return value


def ensure_revision_match(current_revision: str, provided_revision: str | None) -> None:
    if not provided_revision:
        raise ValueError("revision is required for mutating requests")
    if provided_revision != current_revision:
        raise ValueError("revision mismatch")


def validate_operation_params(operation: str, params: Any) -> dict[str, Any]:
    """Validate the bounded, gateway-owned operation envelope before dispatch."""
    from .control_plane_models import ControlPlaneListRequest, ControlPlaneMutationContext

    if operation not in CONTROL_PLANE_OPERATIONS:
        raise ValueError("unsupported management operation")
    if not isinstance(params, dict):
        raise ValueError("management params must be an object")
    if operation in {"entities_list", "jobs_list"}:
        envelope = dict(params)
        entity_type = envelope.pop("entity_type", None)
        if entity_type is not None:
            _validate_identifier({"entity_type": entity_type}, key="entity_type")
        page = ControlPlaneListRequest.model_validate(envelope)
        return {**page.model_dump(exclude_none=True), **({"entity_type": entity_type} if entity_type else {})}
    if operation in CONTROL_PLANE_MUTATING_OPERATIONS:
        context = ControlPlaneMutationContext.model_validate(
            {key: params.get(key) for key in ("request_id", "idempotency_key", "revision")}
        )
        if operation.startswith("entities_"):
            _validate_entity_operation(operation, params)
        elif operation == "actions_run":
            _validate_identifier(params, key="action_id")
        elif operation == "jobs_cancel":
            _validate_identifier(params)
        if len(params) > CONTROL_PLANE_MAX_SCHEMA_PROPERTIES:
            raise ValueError("management param field limit exceeded")
        return {**params, **context.model_dump(exclude_none=True)}
    if operation == "entities_get":
        _validate_identifier(params, key="entity_type")
        _validate_identifier(params)
    if operation == "jobs_get":
        _validate_identifier(params)
    if operation == "actions_run":
        _validate_identifier(params, key="action_id")
    if len(params) > CONTROL_PLANE_MAX_SCHEMA_PROPERTIES:
        raise ValueError("management param field limit exceeded")
    return dict(params)


def _validate_entity_operation(operation: str, params: dict[str, Any]) -> None:
    _validate_identifier(params, key="entity_type")
    if operation in {"entities_update", "entities_delete"}:
        _validate_identifier(params)
    entity = params.get("entity")
    if operation != "entities_delete":
        if not isinstance(entity, dict) or not entity:
            raise ValueError("entity must be a non-empty object")
        if len(entity) > CONTROL_PLANE_MAX_SCHEMA_PROPERTIES:
            raise ValueError("entity field limit exceeded")
        for key, value in entity.items():
            if not isinstance(key, str) or len(key) > 64:
                raise ValueError("entity field name is invalid")
            if isinstance(value, (dict, list)) or len(str(value)) > CONTROL_PLANE_MAX_VALUE_CHARS:
                raise ValueError("entity field value is invalid")
    if operation == "entities_delete" and params.get("typed_confirmation") != params.get("id"):
        raise ValueError("typed confirmation must match the entity id")


def _validate_identifier(params: dict[str, Any], *, key: str = "id") -> None:
    value = params.get(key)
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError(f"{key} must be a bounded non-empty string")


def validate_operation_response(operation: str, response: Any) -> dict[str, Any]:
    """Reject malformed provider results before they reach the admin UI."""
    if not isinstance(response, dict) or not isinstance(response.get("result"), dict):
        raise ValueError("management provider returned an invalid response")
    result = response["result"]
    if operation == "descriptor":
        response = dict(response)
        response["result"] = validate_descriptor(result)
    elif operation in {"entities_list", "jobs_list"}:
        items = result.get("items")
        if not isinstance(items, list) or len(items) > CONTROL_PLANE_MAX_PAGE_SIZE:
            raise ValueError("management list result is invalid")
        if any(not isinstance(item, dict) for item in items):
            raise ValueError("management list item is invalid")
    if "revision" in response and (not isinstance(response["revision"], str) or len(response["revision"]) > 512):
        raise ValueError("management revision is invalid")
    if operation != "descriptor":
        _validate_result_value(response["result"])
    return response


def validate_writable_entity(descriptor: Any, operation: str, params: dict[str, Any]) -> None:
    """Keep a provider from accepting fields outside its validated flat schema."""
    validated = validate_descriptor(descriptor)
    entity_type = params.get("entity_type")
    entity = next((item for item in validated["entities"] if item["type"] == entity_type), None)
    if entity is None or operation.removeprefix("entities_") not in entity["ops"]:
        raise ValueError("entity operation is not declared by the descriptor")
    supplied = params.get("entity") or {}
    properties = entity["schema"]["properties"]
    if set(supplied) - set(properties):
        raise ValueError("entity contains undeclared fields")
    _validate_schema_values(supplied, entity["schema"])


def validate_declared_action(
    descriptor: Any, params: dict[str, Any], confirmation_overrides: Any = None
) -> None:
    """Allow only a descriptor-declared action at its gateway-owned risk level."""
    validated = validate_descriptor(descriptor)
    action = next((item for item in validated["actions"] if item["id"] == params.get("action_id")), None)
    if action is None:
        raise ValueError("action is not declared by the descriptor")
    overrides = confirmation_overrides if isinstance(confirmation_overrides, dict) else {}
    mode = resolve_confirmation_mode(action["risk"], overrides.get(action["id"]))
    if mode == "confirm" and params.get("confirmed") is not True:
        raise ValueError("action confirmation is required")
    if mode == "typed_confirm" and params.get("typed_confirmation") != action["id"]:
        raise ValueError("typed confirmation must match the action id")
    supplied = params.get("action_params", {})
    if not isinstance(supplied, dict):
        raise ValueError("action_params must be an object")
    schema = action.get("params_schema") or {"properties": {}}
    _validate_schema_values(supplied, schema)


def project_management_response(
    descriptor: Any | None, operation: str, response: dict[str, Any], *, entity_type: str | None = None
) -> dict[str, Any]:
    """Project provider data to fields the fixed UI contract explicitly permits."""
    if operation == "descriptor" or descriptor is None:
        return response
    result = response["result"]
    allowed_by_operation = {
        "actions_run": {"job_id", "status", "pending_restart", "previous_revision"},
        "entities_create": {"id", "status", "pending_restart", "previous_revision", "revision"},
        "entities_update": {"id", "status", "pending_restart", "previous_revision", "revision"},
        "entities_delete": {"id", "status", "pending_restart", "previous_revision", "revision"},
        "jobs_get": {"id", "status", "phase", "percent", "error_code", "revision"},
        "jobs_cancel": {"id", "status", "pending_restart"},
        "jobs_list": {"items", "next_cursor"},
        "status_get": {field["field"] for field in descriptor.get("status_fields", [])},
    }
    if operation in {"entities_list", "entities_get"}:
        entities = descriptor.get("entities", [])
        if entity_type is None and len(entities) == 1:
            entity_type = entities[0]["type"]
        entity = next((item for item in entities if item["type"] == entity_type), entities[0] if len(entities) == 1 else None)
        if entity is None:
            raise ValueError("entity result cannot be projected")
        allowed = set(entity["schema"]["properties"]) | {item["field"] for item in entity["columns"]} | {"status", "revision"}
        if operation == "entities_list":
            return {**response, "result": {"items": [{key: value for key, value in row.items() if key in allowed} for row in result["items"]], "next_cursor": result.get("next_cursor")}}
        return {**response, "result": {key: value for key, value in result.items() if key in allowed}}
    if operation == "jobs_list":
        fields = {"id", "status", "phase", "percent", "error_code", "revision"}
        return {**response, "result": {"items": [{key: value for key, value in row.items() if key in fields} for row in result["items"]], "next_cursor": result.get("next_cursor")}}
    allowed = allowed_by_operation.get(operation)
    if allowed is None:
        return response
    return {**response, "result": {key: value for key, value in result.items() if key in allowed}}


def _validate_schema_values(values: dict[str, Any], schema: dict[str, Any]) -> None:
    """Validate every allowed flat-schema facet before provider dispatch."""
    properties = schema["properties"]
    if set(values) - set(properties):
        raise ValueError("entity contains undeclared fields")
    missing = set(schema.get("required", [])) - set(values)
    if missing:
        raise ValueError(f"required fields are missing: {', '.join(sorted(missing))}")
    for field, value in values.items():
        definition = properties[field]
        expected = definition["type"]
        if expected == "boolean":
            valid = isinstance(value, bool)
        elif expected == "string":
            valid = isinstance(value, str) and len(value) <= definition.get(
                "maxLength", CONTROL_PLANE_MAX_VALUE_CHARS
            )
            pattern = definition.get("pattern")
            if valid and pattern:
                # `value` is already bounded to maxLength above, so only the
                # pattern itself (bounded separately, see _bounded_fullmatch)
                # can still cause pathological backtracking here.
                valid = _bounded_fullmatch(pattern, value)
            if valid and definition.get("enum") is not None:
                valid = value in definition["enum"]
        elif expected == "integer":
            valid = isinstance(value, int) and not isinstance(value, bool)
        else:
            valid = isinstance(value, (int, float)) and not isinstance(value, bool)
        if expected in {"integer", "number"} and valid:
            minimum, maximum = definition.get("minimum"), definition.get("maximum")
            valid = (minimum is None or value >= minimum) and (maximum is None or value <= maximum)
        if not valid:
            raise ValueError(f"{field} is invalid")


def _validate_result_value(value: Any, depth: int = 0) -> None:
    if depth > 4:
        raise ValueError("management result nesting limit exceeded")
    if isinstance(value, str):
        if len(value) > CONTROL_PLANE_MAX_VALUE_CHARS:
            raise ValueError("management result string limit exceeded")
        return
    if isinstance(value, (bool, int, float)) or value is None:
        return
    if isinstance(value, list):
        if len(value) > CONTROL_PLANE_MAX_PAGE_SIZE:
            raise ValueError("management result list limit exceeded")
        for item in value:
            _validate_result_value(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > CONTROL_PLANE_MAX_SCHEMA_PROPERTIES:
            raise ValueError("management result field limit exceeded")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 64:
                raise ValueError("management result key is invalid")
            _validate_result_value(item, depth + 1)
        return
    raise ValueError("management result contains an unsupported value")


def truncate_untrusted_text(value: Any, *, limit: int = CONTROL_PLANE_MAX_VALUE_CHARS) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    budget = max(0, limit - len(CONTROL_PLANE_TRUNCATION_SUFFIX))
    return f"{text[:budget]}{CONTROL_PLANE_TRUNCATION_SUFFIX}"


def escape_control_plane_text(value: Any, *, limit: int = CONTROL_PLANE_MAX_VALUE_CHARS) -> str:
    return html.escape(truncate_untrusted_text(value, limit=limit), quote=True)


def escape_display_text(value: Any, *, limit: int = CONTROL_PLANE_MAX_VALUE_CHARS) -> str:
    return escape_control_plane_text(value, limit=limit)


def resolve_confirmation_mode(declared_risk: str, override: str | None = None) -> str:
    if declared_risk not in CONTROL_PLANE_RISKS:
        raise ValueError(f"Unsupported risk: {declared_risk}")
    base_mode = CONTROL_PLANE_CONFIRMATIONS[declared_risk]
    if override not in CONTROL_PLANE_CONFIRMATION_ORDER:
        return base_mode
    if CONTROL_PLANE_CONFIRMATION_ORDER[override] < CONTROL_PLANE_CONFIRMATION_ORDER[base_mode]:
        return base_mode
    return override


def hash_control_plane_target(payload: Any) -> str:
    try:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except TypeError:
        raw = truncate_untrusted_text(payload)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _redact_string(value: str) -> str:
    redacted = _AUTHORIZATION_HEADER_PATTERN.sub("authorization=[REDACTED]", value)
    redacted = _SENSITIVE_VALUE_PATTERN.sub(
        lambda match: f"{match.group('key')}={ '[REDACTED]' }", redacted
    )
    redacted = _BEARER_TOKEN_PATTERN.sub("Bearer [REDACTED]", redacted)
    redacted = _FILESYSTEM_PATH_PATTERN.sub("[REDACTED_PATH]", redacted)
    return truncate_untrusted_text(redacted)


def redact_audit_details(payload: Any) -> Any:
    if isinstance(payload, dict):
        sanitized: dict[str, Any] = {}
        for raw_key, value in payload.items():
            key = truncate_untrusted_text(raw_key, limit=64)
            if any(fragment in key.lower() for fragment in CONTROL_PLANE_SENSITIVE_KEY_FRAGMENTS):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = redact_audit_details(value)
        return sanitized
    if isinstance(payload, list):
        return [redact_audit_details(item) for item in payload[:64]]
    if isinstance(payload, str):
        return _redact_string(payload)
    return payload


def sanitize_management_payload(payload: Any) -> Any:
    return redact_audit_details(payload)


def validate_descriptor(descriptor: Any) -> dict[str, Any]:
    from .control_plane_models import ControlPlaneDescriptor

    try:
        validated = ControlPlaneDescriptor.model_validate(descriptor)
    except ValidationError as exc:  # pragma: no cover - exercised via tests
        raise DescriptorValidationError(str(exc)) from exc
    return validated.model_dump(by_alias=True, exclude_none=True)
