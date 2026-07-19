"""Tests for the validated, fixed control-plane descriptor contract."""

import pytest
from pydantic import ValidationError

from authmcp_gateway.mcp.control_plane_contract import (
    CONTROL_PLANE_EXTENSION,
    escape_control_plane_text,
    is_control_plane_method,
    project_management_response,
    sanitize_management_payload,
    validate_declared_action,
    validate_writable_entity,
)
from authmcp_gateway.mcp.control_plane_models import ControlPlaneDescriptor


def _descriptor() -> dict:
    return {
        "extension": CONTROL_PLANE_EXTENSION,
        "revision": "r1",
        "entities": [
            {
                "type": "repository",
                "label": "Repositories",
                "id_field": "alias",
                "columns": [{"field": "alias", "kind": "code"}],
                "schema": {
                    "type": "object",
                    "properties": {
                        "alias": {"type": "string", "maxLength": 64},
                        "enabled": {"type": "boolean", "default": True},
                    },
                    "required": ["alias"],
                },
                "ops": ["list", "create", "update", "delete"],
            }
        ],
        "actions": [
            {
                "id": "index.rebuild",
                "label": "Rebuild",
                "target": "index",
                "risk": "destructive",
                "async": True,
                "params_schema": {"type": "object", "properties": {}},
            }
        ],
        "status_fields": [{"field": "engine_version", "kind": "text"}],
    }


def test_valid_descriptor_is_accepted_without_mutating_input():
    descriptor = _descriptor()

    validated = ControlPlaneDescriptor.model_validate(descriptor)

    assert validated.extension == CONTROL_PLANE_EXTENSION
    assert validated.entities[0].schema_definition.properties["alias"].max_length == 64
    assert validated.actions[0].async_operation is True


@pytest.mark.parametrize(
    "mutator",
    [
        lambda descriptor: descriptor["entities"][0]["schema"]["properties"].update(
            {"nested": {"type": "object", "properties": {}}}
        ),
        lambda descriptor: descriptor["entities"][0]["schema"]["properties"].update(
            {"alias": {"type": "string", "maxLength": 9000}}
        ),
        lambda descriptor: descriptor["actions"][0].update(
            {"method": "tools/call"}
        ),
    ],
)
def test_unsafe_descriptor_features_are_rejected(mutator):
    descriptor = _descriptor()
    mutator(descriptor)

    with pytest.raises(ValidationError):
        ControlPlaneDescriptor.model_validate(descriptor)


def test_entity_limit_and_untrusted_display_text_are_bounded():
    descriptor = _descriptor()
    descriptor["entities"] = descriptor["entities"] * 33

    with pytest.raises(ValidationError):
        ControlPlaneDescriptor.model_validate(descriptor)

    assert escape_control_plane_text('<img src=x onerror="alert(1)">') == "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"
    assert len(escape_control_plane_text("x" * 9000)) == 8192


def test_control_plane_methods_are_distinct_from_model_tool_names():
    assert is_control_plane_method("com.authmcp/control-plane-v1/entities/list")
    assert not is_control_plane_method("repo_list_roots")


def test_audit_metadata_redacts_credentials():
    details = sanitize_management_payload(
        {"access_token": "should-not-persist", "message": "token=abc"}
    )

    assert details == {"access_token": "[REDACTED]", "message": "token=[REDACTED]"}


def test_audit_redaction_covers_paths_json_and_query_strings():
    details = sanitize_management_payload(
        {
            "message": 'api_key: "abc" path=/private/repository',
            "url": "https://example.test/mcp?access_token=abc&cookie=session",
            "authorization": "Bearer super-secret-token",
            "bare_bearer": "Bearer another-secret-token",
            "nested": {"credentials": "must-not-persist"},
        }
    )

    rendered = str(details)
    assert "abc" not in rendered
    assert "session" not in rendered
    assert "super-secret-token" not in rendered
    assert "another-secret-token" not in rendered
    assert "/private/repository" not in rendered
    assert "must-not-persist" not in rendered


def test_declared_actions_and_entity_schema_are_enforced_before_dispatch():
    descriptor = _descriptor()
    descriptor["actions"][0]["risk"] = "mutating"
    with pytest.raises(ValueError, match="action confirmation"):
        validate_declared_action(descriptor, {"action_id": "index.rebuild"})
    descriptor["actions"][0]["risk"] = "destructive"
    with pytest.raises(ValueError, match="typed confirmation"):
        validate_declared_action(
            descriptor, {"action_id": "index.rebuild", "confirmed": True}
        )
    validate_declared_action(
        descriptor, {"action_id": "index.rebuild", "typed_confirmation": "index.rebuild"}
    )
    with pytest.raises(ValueError, match="required fields"):
        validate_writable_entity(descriptor, "entities_create", {"entity_type": "repository", "entity": {}})


def test_provider_response_is_projected_to_descriptor_fields_only():
    response = project_management_response(
        _descriptor(), "entities_list",
        {"result": {"items": [{"alias": "repo", "enabled": True, "token": "secret"}]}},
        entity_type="repository",
    )

    assert response["result"]["items"] == [{"alias": "repo", "enabled": True}]
