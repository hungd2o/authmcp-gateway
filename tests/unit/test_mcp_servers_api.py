"""Tests for MCP server API payload normalization."""

import pytest

from authmcp_gateway.admin.mcp_servers_api import _normalize_transport_payload


def _base_payload(command_args=None, **overrides):
    payload = {
        "name": "demo",
        "transport_type": "stdio",
        "command": "npx",
        "command_args": command_args,
    }
    payload.update(overrides)
    return payload


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


def test_normalize_command_args_ignores_commented_lines_and_segments():
    payload = _normalize_transport_payload(
        _base_payload('--name "my value" # comment\n# ignore\n/tmp')
    )
    assert payload["command_args"] == ["--name", "my value", "/tmp"]


def test_normalize_command_args_accepts_json_array_with_hash_comments():
    payload = _normalize_transport_payload(
        _base_payload(
            '[\n  "--name",\n  "my value", # trailing comment\n  # "/ignored",\n  "/tmp"\n]'
        )
    )
    assert payload["command_args"] == ["--name", "my value", "/tmp"]


def test_normalize_command_args_rejects_invalid_unclosed_quote():
    with pytest.raises(ValueError, match="Invalid command_args"):
        _normalize_transport_payload(_base_payload('--name "unterminated'))


def test_normalize_env_vars_accepts_key_value_lines_and_ignores_comments():
    payload = _normalize_transport_payload(
        _base_payload(
            env_vars="NODE_ENV=production\n# comment only\nAPI_URL=https://example.com # trailing"
        )
    )
    assert payload["env_vars"] == {
        "NODE_ENV": "production",
        "API_URL": "https://example.com",
    }


def test_normalize_env_vars_preserves_hash_inside_quoted_value():
    payload = _normalize_transport_payload(
        _base_payload(env_vars='SECRET="abc # keep"\nTOKEN=value#keep')
    )
    assert payload["env_vars"] == {
        "SECRET": "abc # keep",
        "TOKEN": "value#keep",
    }


def test_normalize_env_vars_rejects_invalid_non_assignment_lines():
    with pytest.raises(ValueError, match="Invalid env_vars line"):
        _normalize_transport_payload(_base_payload(env_vars="NOT_AN_ASSIGNMENT"))
