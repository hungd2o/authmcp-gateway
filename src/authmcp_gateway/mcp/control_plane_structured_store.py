"""Generic, atomic CRUD over a reviewed JSON document collection."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

from .control_plane_contract import CONTROL_PLANE_MAX_PAGE_SIZE, ensure_revision_match
from .control_plane_document_lock import document_lock
from .control_plane_native_client import ManagementUnavailableError


class StructuredStoreProvider:
    def __init__(self, manifest: dict[str, Any]):
        self._manifest, self.name, self.version = manifest, manifest["id"], manifest["version"]
        self.manifest_hash = manifest["manifest_hash"]

    def probe(self, server: dict[str, Any]):
        from .control_plane_adapters import AdapterProbe

        package_root = self._binding(server, "package_root") or server.get("working_dir")
        if not isinstance(package_root, str) or not package_root:
            return AdapterProbe(False, reason="management package metadata is unavailable")
        package_path = self._resolve_path(server, package_root) / "package.json"
        try:
            package = json.loads(package_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return AdapterProbe(False, reason="management package metadata is unavailable")
        probe = self._manifest["probe"]
        name, version = package.get("name"), package.get("version")
        if name != probe["package_name"] or version != probe["package_version"]:
            return AdapterProbe(False, str(name or "") or None, str(version or "") or None, "unsupported package version")
        try:
            self._path(server)
        except ManagementUnavailableError as exc:
            return AdapterProbe(False, name, version, str(exc))
        return AdapterProbe(True, name, version)

    def descriptor(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._manifest["descriptor"]))

    def call(self, server: dict[str, Any], operation: str, params: dict[str, Any]) -> dict[str, Any]:
        path = self._path(server)
        if operation in {"entities_create", "entities_update", "entities_delete"}:
            return self._mutate(path, operation, params)
        document = self._read(path)
        revision, collection = self._revision(document), self._collection(document)
        if operation == "descriptor":
            descriptor = self.descriptor()
            descriptor["revision"] = revision
            return {"result": descriptor, "revision": revision}
        if operation == "status_get":
            return {"result": {"state": "pending_restart"}, "revision": revision}
        if operation == "entities_get":
            item = self._find(collection, str(params["id"]))
            if item is None:
                raise ValueError("managed entity does not exist")
            return {"result": self._row(item, revision), "revision": revision}
        offset = int(params.get("cursor") or 0)
        if offset < 0:
            raise ValueError("cursor is invalid")
        page_size = min(int(params.get("page_size", 50)), CONTROL_PLANE_MAX_PAGE_SIZE)
        rows = [self._row(item, revision) for item in collection]
        return {"result": {"items": rows[offset:offset + page_size], "next_cursor": str(offset + page_size) if offset + page_size < len(rows) else None}, "revision": revision}

    def _mutate(self, path: Path, operation: str, params: dict[str, Any]) -> dict[str, Any]:
        with document_lock(path):
            document = self._read(path)
            previous = self._revision(document)
            ensure_revision_match(previous, params.get("revision"))
            collection = self._collection(document)
            entity = params.get("entity") if isinstance(params.get("entity"), dict) else {}
            identity = str(params.get("id") or entity.get("alias") or "")
            existing = self._find(collection, identity)
            if operation == "entities_delete":
                if existing is None:
                    raise ValueError("managed entity does not exist")
                collection.remove(existing)
            else:
                replacement = self._replacement(entity, existing)
                if existing is None:
                    if operation == "entities_update":
                        raise ValueError("managed entity does not exist")
                    self._ensure_unique(collection, replacement)
                    collection.append(replacement)
                else:
                    self._ensure_unique(collection, replacement, existing)
                    collection[collection.index(existing)] = replacement
            self._validate(document)
            self._write(path, document)
            revision = self._revision(document)
        return {"result": {"pending_restart": True, "previous_revision": previous}, "revision": revision}

    def _replacement(self, entity: dict[str, Any], existing: dict[str, Any] | None) -> dict[str, Any]:
        config, replacement = self._manifest["document"], deepcopy(existing or {})
        for field, storage in config["fields"].items():
            value = entity.get(field)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field} is required")
            if field == config.get("directory_field"):
                try:
                    root = Path(value).resolve(strict=True)
                except OSError as exc:
                    raise ValueError(f"{field} must be an existing directory") from exc
                if not root.is_dir():
                    raise ValueError(f"{field} must be a directory")
                value = str(root)
            replacement[storage] = value
        for storage, source in config.get("derived", {}).items():
            replacement[storage] = entity[source]
        for field, definition in config.get("virtual_fields", {}).items():
            value = entity.get(field, definition.get("default") if isinstance(definition, dict) else None)
            updates = definition.get("apply", {}).get(value) if isinstance(definition, dict) else None
            if not isinstance(updates, dict):
                raise ValueError(f"{field} is invalid")
            self._merge_document_values(replacement, updates)
        return replacement

    def _ensure_unique(self, collection, replacement, existing=None) -> None:
        for item in collection:
            if item is existing:
                continue
            if any(item.get(field) == replacement.get(field) for field in self._manifest["document"]["unique_fields"]):
                raise ValueError("managed entity already exists")

    def _path(self, server: dict[str, Any]) -> Path:
        config, env = self._manifest["document"], server.get("env_vars") or {}
        raw = self._binding(server, config["binding"]) or next((env.get(key) for key in config["environment"] if env.get(key)), None)
        if not isinstance(raw, str) or not raw:
            raise ManagementUnavailableError("managed document path is not configured")
        try:
            path = self._resolve_path(server, raw).resolve(strict=True)
        except OSError as exc:
            raise ManagementUnavailableError("managed document is unavailable") from exc
        if not path.is_file() or path.suffix.lower() != ".json":
            raise ManagementUnavailableError("managed document is unavailable")
        return path

    def _binding(
        self, server: dict[str, Any], key: str, seen: frozenset[str] = frozenset()
    ) -> str | None:
        binding = server.get("management")
        value = binding.get(key) if isinstance(binding, dict) else None
        if isinstance(value, str) and value:
            return value

        # The reviewed manifest may derive non-secret local bindings from the
        # already-approved server launch configuration. This keeps a profile
        # declarative while avoiding backend-specific Python adapters.
        if key in seen:
            return None
        sources = self._manifest.get("bindings", {}).get(key, [])
        if not isinstance(sources, list):
            return None
        for source in sources:
            resolved = self._binding_source(server, source, seen | {key})
            if resolved:
                return resolved
        return None

    def _binding_source(
        self, server: dict[str, Any], source: Any, seen: frozenset[str]
    ) -> str | None:
        if not isinstance(source, dict):
            return None
        source_kind = source.get("from")
        if source_kind == "working_dir":
            value = server.get("working_dir")
            return value if isinstance(value, str) and value else None
        if source_kind == "environment":
            env = server.get("env_vars")
            keys = source.get("keys")
            if not isinstance(env, dict) or not isinstance(keys, list):
                return None
            for key in keys:
                value = env.get(key) if isinstance(key, str) else None
                if isinstance(value, str) and value:
                    return value
            return None
        if source_kind == "argument":
            flag = source.get("flag")
            args = server.get("command_args")
            if not isinstance(flag, str) or not isinstance(args, list):
                return None
            values = []
            index = 0
            while index < len(args):
                value = args[index]
                if value == flag and index + 1 < len(args) and isinstance(args[index + 1], str) and args[index + 1]:
                    values.append(args[index + 1])
                    index += 2
                    continue
                elif source.get("allow_equals") and isinstance(value, str) and value.startswith(f"{flag}="):
                    candidate = value[len(flag) + 1:]
                    if candidate:
                        values.append(candidate)
                index += 1
            return values[-1] if source.get("occurrence") == "last" and values else (values[0] if values else None)
        if source_kind == "literal":
            value = source.get("value")
            return value if isinstance(value, str) and value else None
        if source_kind == "parent":
            binding = source.get("binding")
            if not isinstance(binding, str):
                return None
            value = self._binding(server, binding, seen)
            return str(self._resolve_path(server, value).parent) if value else None
        return None

    @staticmethod
    def _resolve_path(server: dict[str, Any], raw: str) -> Path:
        path = Path(raw)
        if path.is_absolute():
            return path
        working_dir = server.get("working_dir")
        base = Path(working_dir).resolve() if isinstance(working_dir, str) and working_dir else Path.cwd()
        return base / path

    def _collection(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        collection = document.get(self._manifest["document"]["collection"])
        if not isinstance(collection, list) or any(not isinstance(item, dict) for item in collection):
            raise ManagementUnavailableError("managed document schema is invalid")
        return collection

    def _validate(self, document: Any) -> None:
        if not isinstance(document, dict):
            raise ManagementUnavailableError("managed document schema is invalid")
        fields = set(self._manifest["document"]["fields"].values()) | {self._manifest["document"]["id_field"]}
        collection = self._collection(document)
        for item in collection:
            if any(not isinstance(item.get(field), str) or not item[field] for field in fields):
                raise ManagementUnavailableError("managed document contains an invalid entity")
        for field in self._manifest["document"]["unique_fields"]:
            values = [item[field] for item in collection]
            if len(values) != len(set(values)):
                raise ManagementUnavailableError("managed document contains duplicate entities")

    def _read(self, path: Path) -> dict[str, Any]:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ManagementUnavailableError("managed document is malformed") from exc
        self._validate(document)
        return document

    @staticmethod
    def _write(path: Path, document: dict[str, Any]) -> None:
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(document, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def _find(self, collection, identity):
        return next((item for item in collection if item.get(self._manifest["document"]["id_field"]) == identity), None)

    def _row(self, item, revision):
        fields = self._manifest["document"]["fields"]
        virtual = self._manifest["document"].get("virtual_fields", {})
        return (
            {field: item[storage] for field, storage in fields.items()}
            | {field: self._virtual_value(item, definition) for field, definition in virtual.items()}
            | {"status": "pending_restart", "revision": revision}
        )

    @staticmethod
    def _merge_document_values(target: dict[str, Any], updates: dict[str, Any]) -> None:
        for key, value in updates.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                StructuredStoreProvider._merge_document_values(target[key], value)
            else:
                target[key] = deepcopy(value)

    @staticmethod
    def _virtual_value(item: dict[str, Any], definition: Any) -> str:
        if not isinstance(definition, dict):
            return ""
        for rule in definition.get("rules", []):
            if not isinstance(rule, dict):
                continue
            conditions = rule.get("all", [])
            if all(
                isinstance(condition, dict)
                and StructuredStoreProvider._document_value(item, condition.get("path")) == condition.get("equals")
                for condition in conditions
            ):
                return str(rule.get("value", ""))
        return str(definition.get("default", ""))

    @staticmethod
    def _document_value(item: dict[str, Any], path: Any) -> Any:
        current: Any = item
        if not isinstance(path, str):
            return None
        for part in path.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current

    @staticmethod
    def _revision(document: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
