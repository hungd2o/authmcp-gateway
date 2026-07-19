"""Direct-argv command provider for built-in, reviewed CLI profiles."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from .control_plane_contract import CONTROL_PLANE_MAX_PAGE_SIZE
from .control_plane_command_runner import run_command
from .control_plane_native_client import ManagementUnavailableError
from .control_plane_parsers import parse_output
from .transports.stdio_transport import _minimal_subprocess_env


class CommandProvider:
    def __init__(self, manifest: dict[str, Any]):
        self._manifest, self.name, self.version = manifest, manifest["id"], manifest["version"]
        self.manifest_hash = manifest["manifest_hash"]

    def probe(self, server: dict[str, Any]):
        from .control_plane_adapters import AdapterProbe

        executable = self._executable(server)
        if executable is None:
            return AdapterProbe(False, reason="management executable is unavailable")
        try:
            result = self._run(server, ["--version"])
        except ManagementUnavailableError as exc:
            return AdapterProbe(False, reason=str(exc))
        version = result.stdout.strip()
        if not version.startswith(self._manifest["probe"]["version_prefix"]):
            return AdapterProbe(False, executable, version or None, "unsupported executable version")
        expected_version = self._binding(server, "observed_version")
        if expected_version and version != expected_version:
            return AdapterProbe(False, executable, version, "management executable version changed")
        return AdapterProbe(True, executable, version)

    def descriptor(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._manifest["descriptor"]))

    def call(self, server: dict[str, Any], operation: str, params: dict[str, Any]) -> dict[str, Any]:
        if isinstance(server.get("management"), dict) and not self.probe(server).compatible:
            raise ManagementUnavailableError("management executable is unavailable")
        revision = self._revision()
        if operation == "descriptor":
            descriptor = self.descriptor()
            descriptor["revision"] = revision
            return {"result": descriptor, "revision": revision}
        if operation == "status_get":
            return {"result": {"state": "ready"}, "revision": revision}
        if operation == "entities_list":
            rows = self._list_rows(server)
            offset, page_size = int(params.get("cursor") or 0), min(int(params.get("page_size", 50)), CONTROL_PLANE_MAX_PAGE_SIZE)
            if offset < 0:
                raise ValueError("cursor is invalid")
            items = [self._row(row, revision) for row in rows]
            return {"result": {"items": items[offset:offset + page_size], "next_cursor": str(offset + page_size) if offset + page_size < len(items) else None}, "revision": revision}
        if operation == "actions_run":
            action = self._manifest["commands"]["actions"].get(params.get("action_id"))
            if not isinstance(action, dict):
                raise ManagementUnavailableError("management action is unsupported")
            values = params.get("action_params") if isinstance(params.get("action_params"), dict) else {}
            if params.get("action_id") in {"index.rebuild", "index.remove"}:
                # Substitute the resolved, validated path (not the raw
                # user-supplied value) into argv so a symlink/rename race
                # between validation and execution (TOCTOU) can't smuggle
                # an unindexed path past `_require_indexed_path`.
                values = {**values, "path": self._require_indexed_path(server, values.get("path"))}
            argv = self._expand_argv(action["argv"], values)
            cwd = self._cwd(action, values)
            self._run(server, argv, cwd=cwd)
            return {"result": {"status": "completed"}, "revision": revision}
        raise ManagementUnavailableError("management operation is unsupported")

    def _list_rows(self, server: dict[str, Any]) -> list[dict[str, str]]:
        command = self._manifest["commands"]["entities_list"]
        return parse_output(self._run(server, command["argv"]).stdout, command["parser"])

    def _require_indexed_path(self, server: dict[str, Any], value: Any) -> str:
        """Validate ``value`` and return the resolved path callers must use.

        Returning the resolved path (instead of the caller trusting the raw
        input after this check passes) closes a TOCTOU window: only the
        path that was actually verified against the indexed set is ever
        substituted into argv.
        """
        if not isinstance(value, str) or not value:
            raise ValueError("path is required")
        try:
            requested = Path(value).resolve(strict=True)
        except OSError as exc:
            raise ValueError("path must be an existing indexed repository") from exc
        indexed = {Path(row["path"]).resolve() for row in self._list_rows(server) if row.get("path")}
        if requested not in indexed:
            raise ValueError("path must be an indexed GitNexus repository")
        return str(requested)

    def _run(self, server: dict[str, Any], argv: list[str], *, cwd: str | None = None):
        executable = self._executable(server)
        if executable is None:
            raise ManagementUnavailableError("management executable is unavailable")
        return run_command(executable, argv, cwd=cwd, env=self._env(server))

    @staticmethod
    def _env(server: dict[str, Any]) -> dict[str, str]:
        """Scrubbed env for a spawned management CLI.

        The gateway process holds JWT secrets, DB credentials and other API
        keys; those must never be handed to a reviewed-but-external CLI.
        Only OS/runtime essentials plus the server's own configured
        env_vars pass through (mirrors stdio_transport's
        ``_minimal_subprocess_env``).
        """
        env_vars = server.get("env_vars")
        extra = (
            {key: value for key, value in env_vars.items() if isinstance(key, str) and isinstance(value, str)}
            if isinstance(env_vars, dict)
            else {}
        )
        return _minimal_subprocess_env(extra)

    def _executable(self, server: dict[str, Any]) -> str | None:
        configured_path = self._binding(server, "executable_path")
        configured_hash = self._binding(server, "executable_sha256")
        if configured_path or configured_hash:
            if not configured_path or not configured_hash:
                return None
            try:
                path = Path(configured_path).resolve(strict=True)
                if _file_sha256(path) != configured_hash:
                    return None
            except OSError:
                return None
            return str(path)
        return shutil.which(self._manifest["probe"]["executable"])

    @staticmethod
    def _binding(server: dict[str, Any], key: str) -> str | None:
        management = server.get("management")
        value = management.get(key) if isinstance(management, dict) else None
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _expand_argv(template: list[Any], values: dict[str, Any]) -> list[str]:
        argv: list[str] = []
        separator_inserted = False
        for item in template:
            if isinstance(item, str):
                argv.append(item)
            elif isinstance(item, dict) and isinstance(item.get("input"), str):
                value = values.get(item["input"])
                if not isinstance(value, str) or not value:
                    raise ValueError(f"{item['input']} is required")
                if value.startswith("-"):
                    raise ValueError(f"{item['input']} must not look like a command-line option")
                if not separator_inserted:
                    # Static/known subcommand tokens (already appended above)
                    # stay ahead of "--"; every templated positional after
                    # this point is user-controlled, so "--" stops the
                    # child CLI's own argument parser from ever treating one
                    # as a flag.
                    argv.append("--")
                    separator_inserted = True
                argv.append(value)
            else:
                raise ManagementUnavailableError("management command profile is invalid")
        return argv

    @staticmethod
    def _cwd(action: dict[str, Any], values: dict[str, Any]) -> str | None:
        key = action.get("cwd_input")
        if key is None:
            return None
        value = values.get(key)
        try:
            directory = Path(value).resolve(strict=True) if isinstance(value, str) else None
        except OSError:
            directory = None
        if directory is None or not directory.is_dir():
            raise ValueError("command working directory is invalid")
        return str(directory)

    def _row(self, row: dict[str, str], revision: str) -> dict[str, Any]:
        converted: dict[str, Any] = {"status": "indexed", "revision": revision}
        for key, value in row.items():
            converted[key] = int(value) if key in {"files", "symbols", "edges", "clusters", "processes"} else value
        return converted

    def _revision(self) -> str:
        return hashlib.sha256(self._manifest["manifest_hash"].encode()).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
