"""Helpers for validating and resolving virtual tool templates."""

from __future__ import annotations

import json
import re
from typing import Any, Dict
from urllib.parse import quote

_SEGMENT_RE = r"[A-Za-z_][A-Za-z0-9_]*"
_PATH_RE = re.compile(rf"arguments(?:\.{_SEGMENT_RE})*")
_TEMPLATE_RE = re.compile(rf"{{{{\s*({_PATH_RE.pattern})\s*}}}}")
_EXACT_TEMPLATE_RE = re.compile(rf"^\s*{{{{\s*({_PATH_RE.pattern})\s*}}}}\s*$")


def validate_template_string(value: str) -> None:
    """Reject malformed or unsupported template expressions."""
    cursor = 0
    while cursor < len(value):
        start = value.find("{{", cursor)
        end = value.find("}}", cursor)
        if start == -1 and end == -1:
            return
        if end != -1 and (start == -1 or end < start):
            raise ValueError(f"Invalid template syntax: {value}")
        if start == -1:
            raise ValueError(f"Invalid template syntax: {value}")
        close = value.find("}}", start + 2)
        if close == -1:
            raise ValueError(f"Invalid template syntax: {value}")
        token = value[start : close + 2]
        if not _TEMPLATE_RE.fullmatch(token):
            raise ValueError(f"Invalid template syntax: {value}")
        cursor = close + 2


def validate_templates_in_value(value: Any, field_name: str) -> None:
    """Recursively validate template syntax in nested values."""
    if isinstance(value, str):
        validate_template_string(value)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_templates_in_value(item, f"{field_name}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            validate_templates_in_value(item, f"{field_name}.{key}")


def resolve_template_string(template: str, context: Dict[str, Any], *, mode: str = "text") -> Any:
    """Resolve placeholders inside a string."""
    validate_template_string(template)
    exact_match = _EXACT_TEMPLATE_RE.fullmatch(template)
    if exact_match:
        value = _lookup_template_path(context, exact_match.group(1))
        if mode == "raw":
            return value
        return _stringify_template_value(value, mode=mode)

    def _replace(match: re.Match[str]) -> str:
        value = _lookup_template_path(context, match.group(1))
        return _stringify_template_value(value, mode=mode)

    return _TEMPLATE_RE.sub(_replace, template)


def resolve_templated_value(value: Any, context: Dict[str, Any], *, mode: str = "raw") -> Any:
    """Resolve a nested templated structure."""
    if isinstance(value, str):
        return resolve_template_string(value, context, mode=mode)
    if isinstance(value, list):
        return [resolve_templated_value(item, context, mode=mode) for item in value]
    if isinstance(value, dict):
        return {
            str(key): resolve_templated_value(item, context, mode=mode)
            for key, item in value.items()
        }
    return value


def _lookup_template_path(context: Dict[str, Any], path: str) -> Any:
    current: Any = context
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            raise ValueError(f"Template references missing value: {path}")
        current = current[segment]
    return current


def _stringify_template_value(value: Any, *, mode: str) -> str:
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)

    if mode == "url":
        return quote(text, safe="")
    return text
