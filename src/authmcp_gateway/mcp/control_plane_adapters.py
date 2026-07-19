"""Manifest-driven, allowlisted management providers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .control_plane_command import CommandProvider
from .control_plane_manifests import ManifestError, load_manifest
from .control_plane_structured_store import StructuredStoreProvider


@dataclass(frozen=True)
class AdapterProbe:
    compatible: bool
    package: str | None = None
    version: str | None = None
    reason: str | None = None


class ManagementProvider(Protocol):
    name: str
    version: str

    def probe(self, server: dict[str, Any]) -> AdapterProbe: ...
    def descriptor(self) -> dict[str, Any]: ...
    def call(self, server: dict[str, Any], operation: str, params: dict[str, Any]) -> dict[str, Any]: ...


def adapter_for(name: str) -> ManagementProvider | None:
    try:
        manifest = load_manifest(name)
    except ManifestError:
        return None
    if manifest["driver"] == "structured-store-v1":
        return StructuredStoreProvider(manifest)
    if manifest["driver"] == "command-v1":
        return CommandProvider(manifest)
    return None


class GptRepoAdapter(StructuredStoreProvider):
    """Compatibility import; behavior is fully defined by gpt-repo.json."""

    def __init__(self) -> None:
        super().__init__(load_manifest("gpt-repo"))
