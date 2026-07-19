"""Load immutable, package-owned management provider manifests."""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from typing import Any


class ManifestError(ValueError):
    """A built-in management profile is malformed or unavailable."""


def load_manifest(provider_id: str) -> dict[str, Any]:
    if not provider_id or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in provider_id):
        raise ManifestError("management provider is invalid")
    package = resources.files("authmcp_gateway.mcp.management_profiles")
    try:
        raw = (package / f"{provider_id}.json").read_text(encoding="utf-8")
        manifest = json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise ManifestError("management provider is unavailable") from exc
    if manifest.get("id") != provider_id or manifest.get("driver") not in {"structured-store-v1", "command-v1"}:
        raise ManifestError("management provider is invalid")
    manifest["manifest_hash"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return manifest
