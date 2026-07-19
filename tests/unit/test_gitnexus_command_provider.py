from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from authmcp_gateway.mcp.control_plane_adapters import adapter_for


GITNEXUS_LIST = """  Indexed Repositories (1)

  repo-a
    Path:    {path}
    Indexed: today
    Commit:  1234567
    Stats:   1 files, 2 symbols, 3 edges
    Clusters:   4
    Processes:  5
"""


def _completed(args, stdout=""):
    return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")


def test_gitnexus_uses_direct_argv_and_parses_index_list(monkeypatch, tmp_path):
    repository = tmp_path / "repo-a"
    repository.mkdir()
    calls = []
    monkeypatch.setattr("shutil.which", lambda _name: "C:/tools/gitnexus.cmd")
    monkeypatch.setattr(
        "authmcp_gateway.mcp.control_plane_command.run_command",
        lambda executable, argv, **kwargs: calls.append(([executable, *argv], kwargs)) or _completed([executable, *argv], GITNEXUS_LIST.format(path=repository)),
    )
    provider = adapter_for("gitnexus")

    listed = provider.call({}, "entities_list", {})

    assert listed["result"]["items"][0]["path"] == str(repository)
    assert len(calls) == 1
    assert calls[0][0] == ["C:/tools/gitnexus.cmd", "list"]
    assert calls[0][1]["cwd"] is None
    assert isinstance(calls[0][1]["env"], dict)


def test_gitnexus_clean_requires_a_currently_indexed_repository(monkeypatch, tmp_path):
    indexed = tmp_path / "indexed"
    other = tmp_path / "other"
    indexed.mkdir()
    other.mkdir()
    calls = []
    monkeypatch.setattr("shutil.which", lambda _name: "C:/tools/gitnexus.cmd")
    monkeypatch.setattr(
        "authmcp_gateway.mcp.control_plane_command.run_command",
        lambda executable, argv, **kwargs: calls.append(([executable, *argv], kwargs)) or _completed([executable, *argv], GITNEXUS_LIST.format(path=indexed)),
    )
    provider = adapter_for("gitnexus")

    with pytest.raises(ValueError, match="indexed GitNexus"):
        provider.call({}, "actions_run", {"action_id": "index.remove", "action_params": {"path": str(other)}})

    provider.call({}, "actions_run", {"action_id": "index.remove", "action_params": {"path": str(indexed)}})
    assert calls[-1][0] == ["C:/tools/gitnexus.cmd", "clean", "--force"]
    assert calls[-1][1]["cwd"] == str(indexed)


def test_gitnexus_rejects_a_bound_executable_when_it_changes(monkeypatch, tmp_path):
    executable = tmp_path / "gitnexus.cmd"
    executable.write_text("reviewed", encoding="utf-8")
    monkeypatch.setattr(
        "authmcp_gateway.mcp.control_plane_command.run_command",
        lambda executable, argv, **_kwargs: _completed([executable, *argv], "1.6.3"),
    )
    provider = adapter_for("gitnexus")
    server = {"management": {
        "executable_path": str(executable),
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "observed_version": "1.6.3",
    }}

    assert provider.probe(server).compatible
    executable.write_text("replaced", encoding="utf-8")

    assert provider.probe(server).compatible is False
