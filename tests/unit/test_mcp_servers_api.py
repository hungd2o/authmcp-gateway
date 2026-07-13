"""Tests for MCP server API payload normalization."""

import pytest

from authmcp_gateway.admin.mcp_servers_api import _normalize_transport_payload


def _base_payload(command_args):
    return {
        "name": "demo",
        "transport_type": "stdio",
        "command": "npx",
        "command_args": command_args,
    }


def test_normalize_command_args_accepts_list_input():
    payload = _normalize_transport_payload(_base_payload(["--flag", 123]))
    assert payload["command_args"] == ["--flag", "123"]


def test_normalize_command_args_accepts_json_array_string():
    payload = _normalize_transport_payload(_base_payload('["--name","my value"]'))
    assert payload["command_args"] == ["--name", "my value"]


def test_normalize_command_args_fallback_parses_shell_like_string():
    payload = _normalize_transport_payload(_base_payload('--name "my value" /tmp'))
    assert payload["command_args"] == ["--name", "my value", "/tmp"]


def test_normalize_command_args_parses_multiline_input():
    payload = _normalize_transport_payload(_base_payload("--name\nmy-value\n/tmp"))
    assert payload["command_args"] == ["--name", "my-value", "/tmp"]


def test_normalize_command_args_rejects_invalid_unclosed_quote():
    with pytest.raises(ValueError, match="Invalid command_args"):
        _normalize_transport_payload(_base_payload('--name "unterminated'))
