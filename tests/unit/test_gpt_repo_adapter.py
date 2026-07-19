import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from authmcp_gateway.mcp.control_plane_adapters import GptRepoAdapter
from authmcp_gateway.mcp.control_plane_document_lock import document_lock


def _server(config_path):
    return {"env_vars": {"GPT_REPO_CONFIG": str(config_path)}}


def test_gpt_repo_adapter_lists_and_creates_pending_restart(tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"repos": [], "limits": {}}), encoding="utf-8")
    root = tmp_path / "repository"
    root.mkdir()
    adapter = GptRepoAdapter()
    descriptor = adapter.call(_server(registry), "descriptor", {})["result"]

    created = adapter.call(
        _server(registry), "entities_create",
        {"revision": descriptor["revision"], "entity": {"alias": "repo-a", "path": str(root)}},
    )
    listed = adapter.call(_server(registry), "entities_list", {})

    assert created["result"]["pending_restart"] is True
    assert listed["result"]["items"][0]["alias"] == "repo-a"


def test_gpt_repo_adapter_rejects_stale_revision_and_missing_path(tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"repos": [], "limits": {}}), encoding="utf-8")
    adapter = GptRepoAdapter()

    with pytest.raises(ValueError, match="revision"):
        adapter.call(_server(registry), "entities_create", {"revision": "stale", "entity": {}})


def test_gpt_repo_adapter_serializes_concurrent_cas_writers(tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"repos": [], "limits": {}}), encoding="utf-8")
    first, second = tmp_path / "one", tmp_path / "two"
    first.mkdir()
    second.mkdir()
    adapter = GptRepoAdapter()
    revision = adapter.call(_server(registry), "descriptor", {})["revision"]

    def create(alias, root):
        return adapter.call(_server(registry), "entities_create", {
            "revision": revision, "entity": {"alias": alias, "path": str(root)},
        })

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.exception() for future in (
            pool.submit(create, "one", first), pool.submit(create, "two", second)
        )]

    assert sum(error is None for error in results) == 1
    assert any(isinstance(error, ValueError) for error in results)
    assert len(json.loads(registry.read_text(encoding="utf-8"))["repos"]) == 1


def test_document_lock_uses_the_shared_management_lock_directory(tmp_path):
    registry = tmp_path / "config.local.json"
    lock_path = tmp_path / ".config.local.json.management-lock"

    with document_lock(registry):
        assert lock_path.is_dir()

    assert not lock_path.exists()


def test_gpt_repo_adapter_never_rewrites_a_malformed_registry(tmp_path):
    registry = tmp_path / "registry.json"
    original = '{"repos":["not-an-object"]}'
    registry.write_text(original, encoding="utf-8")

    with pytest.raises(RuntimeError):
        GptRepoAdapter().call(_server(registry), "entities_list", {})

    assert registry.read_text(encoding="utf-8") == original


def test_gpt_repo_adapter_probe_accepts_gateway_owned_adapter_paths(tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"repos": []}), encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "gpt-repo-mcp", "version": "0.1.0"}), encoding="utf-8"
    )

    probe = GptRepoAdapter().probe({"management": {
        "mode": "adapter", "adapter": "gpt-repo", "package_root": str(tmp_path),
        "registry_path": str(registry),
    }})

    assert probe.compatible


def test_gpt_repo_adapter_matches_gpt_repo_config_precedence_and_relative_paths(tmp_path):
    first_registry = tmp_path / "first.json"
    env_registry = tmp_path / "env.json"
    cli_registry = tmp_path / "cli.json"
    for registry, alias in ((first_registry, "first"), (env_registry, "env"), (cli_registry, "cli")):
        registry.write_text(
            json.dumps({"repos": [{"repo_id": alias, "root": str(tmp_path)}], "limits": {}}),
            encoding="utf-8",
        )
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "gpt-repo-mcp", "version": "0.1.0"}), encoding="utf-8"
    )
    server = {
        "working_dir": str(tmp_path),
        "command_args": ["/c", "gpt-repo", "stdio", "--config", "first.json", "--config=cli.json"],
        "env_vars": {"GPT_REPO_CONFIG": "env.json"},
        "management": {"mode": "adapter", "adapter": "gpt-repo"},
    }

    adapter = GptRepoAdapter()

    assert adapter.probe(server).compatible
    assert adapter.call(server, "entities_list", {})["result"]["items"][0]["alias"] == "cli"


def test_gpt_repo_adapter_edits_the_backend_access_mode(tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps({"repos": [{
            "repo_id": "repo-a", "display_name": "repo-a", "root": str(tmp_path),
            "writes": {"enabled": False}, "operations": {"enabled": False},
        }], "limits": {}}),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "gpt-repo-mcp", "version": "0.1.0"}), encoding="utf-8"
    )
    server = {"management": {"package_root": str(tmp_path), "registry_path": str(registry)}}
    adapter = GptRepoAdapter()
    listed = adapter.call(server, "entities_list", {})

    assert listed["result"]["items"][0]["mode"] == "read"
    updated = adapter.call(server, "entities_update", {
        "id": "repo-a", "revision": listed["revision"],
        "entity": {"alias": "repo-a", "path": str(tmp_path), "mode": "ship"},
    })
    document = json.loads(registry.read_text(encoding="utf-8"))

    assert updated["result"]["pending_restart"] is True
    assert document["repos"][0]["writes"]["enabled"] is True
    assert document["repos"][0]["writes"]["allowed_globs"] == ["**"]
    assert document["repos"][0]["operations"] == {
        "enabled": True, "git_stage_enabled": True, "git_commit_enabled": True, "cleanup_enabled": True,
    }
    assert adapter.call(server, "entities_list", {})["result"]["items"][0]["mode"] == "ship"
