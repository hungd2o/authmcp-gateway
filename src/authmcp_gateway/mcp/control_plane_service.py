"""Fixed provider boundary for the admin-only management control plane."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Awaitable, Callable

from .control_plane_adapters import AdapterProbe, adapter_for
from .control_plane_contract import (
    CONTROL_PLANE_METHODS,
    CONTROL_PLANE_MUTATING_OPERATIONS,
    hash_control_plane_target,
    redact_audit_details,
    project_management_response,
    validate_declared_action,
    validate_operation_params,
    validate_operation_response,
    validate_writable_entity,
)
from .control_plane_native_client import ManagementUnavailableError, NativeManagementClient
from .store import (
    complete_management_idempotency,
    clear_management_runtime_state,
    create_management_idempotency,
    get_management_idempotency,
    get_management_runtime_state,
    get_mcp_server,
    log_management_audit,
    save_management_probe,
    set_management_runtime_state,
)


class ManagementUnsupportedError(ManagementUnavailableError):
    code = "UNSUPPORTED"


class ManagementConflictError(ManagementUnavailableError):
    code = "CONFLICT"


class ManagementValidationError(ManagementUnavailableError):
    code = "VALIDATION_FAILED"


ReconcileCallback = Callable[[dict[str, Any]], Awaitable[None]]


class ControlPlaneService:
    """Dispatch only reviewed operations without touching model-plane state."""

    def __init__(self, db_path: str, process_manager: Any, native_client: NativeManagementClient):
        self._db_path, self._process_manager, self._native = db_path, process_manager, native_client
        self._reconcile: ReconcileCallback | None = None
        self._native_descriptors: dict[str, dict[str, Any]] = {}
        self._server_locks: dict[int, asyncio.Lock] = {}
        self._fenced_servers: set[int] = set()
        self._runtime_revisions_verified_this_boot: set[int] = set()

    def set_reconcile_callback(self, callback: ReconcileCallback) -> None:
        self._reconcile = callback

    async def availability(self, server_id: int) -> dict[str, Any]:
        server = self._eligible_server(server_id)
        binding = server.get("management") or {"mode": "none"}
        if binding.get("mode") == "adapter":
            adapter, probe = self._adapter_probe(server, binding)
            if adapter is None or not probe.compatible:
                return {"available": False, "mode": "adapter", "reason": probe.reason}
            try:
                validate_operation_response(
                    "descriptor", await asyncio.to_thread(adapter.call, server, "descriptor", {})
                )
            except (RuntimeError, ValueError):
                return {
                    "available": False,
                    "mode": "adapter",
                    "reason": "adapter descriptor is unavailable",
                }
            return {
                "available": True,
                "mode": "adapter",
                "adapter": adapter.name,
                "version": probe.version,
            }
        if (
            binding.get("mode") == "native"
            and (server.get("transport_type") or "http").lower() == "stdio"
        ):
            try:
                lifecycle = self._lifecycle_identity(server)
                await self._native_descriptor(server, lifecycle)
            except (RuntimeError, ValueError):
                return {
                    "available": False,
                    "mode": "native",
                    "reason": "native extension is unavailable",
                }
            return {"available": True, "mode": "native"}
        return {"available": False, "mode": "none", "reason": "management is not configured"}

    async def call(
        self,
        server_id: int,
        operation: str,
        params: dict[str, Any],
        *,
        actor_user_id: int | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        if server_id in self._fenced_servers:
            raise ManagementUnavailableError("Management server is unavailable")
        async with self._lock(server_id):
            if server_id in self._fenced_servers:
                raise ManagementUnavailableError("Management server is unavailable")
            return await self._call(
                server_id,
                operation,
                params,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            )

    async def _call(
        self,
        server_id: int,
        operation: str,
        params: dict[str, Any],
        *,
        actor_user_id: int | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            params = validate_operation_params(operation, params)
        except ValueError as exc:
            raise ManagementValidationError(str(exc)) from exc
        server = self._eligible_server(server_id)
        binding = server.get("management") or {"mode": "none"}
        if operation == "reconcile":
            return await self._reconcile_server(server, params, actor_user_id, correlation_id)
        if binding.get("mode") == "adapter":
            adapter, probe = self._adapter_probe(server, binding)
            if adapter is None or not probe.compatible:
                raise ManagementUnsupportedError("Management adapter compatibility probe failed")
            descriptor = adapter.descriptor()
            if (
                operation.startswith("entities_")
                and operation != "entities_list"
                and operation != "entities_get"
            ):
                try:
                    validate_writable_entity(descriptor, operation, params)
                except ValueError as exc:
                    raise ManagementValidationError(str(exc)) from exc
            if operation == "actions_run":
                try:
                    validate_declared_action(
                        descriptor, params, binding.get("confirmation_overrides")
                    )
                except ValueError as exc:
                    raise ManagementValidationError(str(exc)) from exc
            response = await self._call_with_receipt(
                server,
                operation,
                params,
                lambda: asyncio.to_thread(adapter.call, server, operation, params),
                adapter.name,
                adapter.version,
                probe,
                actor_user_id,
                correlation_id,
                descriptor=descriptor,
            )
            return self._project_adapter_state(server, operation, response)
        if binding.get("mode") != "native":
            raise ManagementUnsupportedError("Management provider is unsupported")
        if (server.get("transport_type") or "http").lower() != "stdio":
            raise ManagementUnsupportedError("Management transport is unsupported")
        method = CONTROL_PLANE_METHODS.get(operation)
        if not method:
            raise ManagementUnsupportedError("Management operation is unsupported")
        lifecycle = self._lifecycle_identity(server)
        descriptor = (
            None if operation == "descriptor" else await self._native_descriptor(server, lifecycle)
        )
        if operation.startswith("entities_") and operation not in {"entities_list", "entities_get"}:
            try:
                validate_writable_entity(descriptor, operation, params)
            except ValueError as exc:
                raise ManagementValidationError(str(exc)) from exc
        if operation == "actions_run":
            try:
                validate_declared_action(descriptor, params, binding.get("confirmation_overrides"))
            except ValueError as exc:
                raise ManagementValidationError(str(exc)) from exc
        response = await self._call_native(
            server, lifecycle, operation, method, params, actor_user_id, correlation_id, descriptor
        )
        if operation == "descriptor":
            self._native_descriptors[f"{server_id}:{lifecycle}"] = response["result"]
        return response

    async def _native_descriptor(self, server: dict[str, Any], lifecycle: str) -> dict[str, Any]:
        key = f"{server['id']}:{lifecycle}"
        if descriptor := self._native_descriptors.get(key):
            return descriptor
        response = await self._native.request(
            server,
            lifecycle,
            CONTROL_PLANE_METHODS["descriptor"],
            {},
            eligible=lambda: self._still_eligible(server, lifecycle),
        )
        descriptor = validate_operation_response("descriptor", response)["result"]
        self._native_descriptors[key] = descriptor
        return descriptor

    async def _call_native(
        self, server, lifecycle, operation, method, params, actor, correlation, descriptor
    ):
        return await self._call_with_receipt(
            server,
            operation,
            params,
            lambda: self._native.request(
                server,
                lifecycle,
                method,
                params,
                eligible=lambda: self._still_eligible(server, lifecycle),
            ),
            "native",
            "v1",
            AdapterProbe(True),
            actor,
            correlation,
            descriptor=descriptor,
        )

    async def _reconcile_server(self, server, params, actor, correlation) -> dict[str, Any]:
        if self._reconcile is None:
            raise ManagementUnavailableError("Management lifecycle is not initialized")
        binding = server.get("management") or {"mode": "none"}
        if (server.get("transport_type") or "http").lower() != "stdio" or binding.get(
            "mode"
        ) == "none":
            raise ManagementUnsupportedError("Management reconciliation is unsupported")
        if binding.get("mode") == "adapter":
            _adapter, probe = self._adapter_probe(server, binding)
            if not probe.compatible:
                raise ManagementUnsupportedError("Management adapter compatibility probe failed")
            clear_management_runtime_state(self._db_path, int(server["id"]))
            self._runtime_revisions_verified_this_boot.discard(int(server["id"]))
        elif binding.get("mode") == "native":
            await self._native_descriptor(server, self._lifecycle_identity(server))
        else:
            raise ManagementUnsupportedError("Management provider is unsupported")

        async def reconcile() -> None:
            await self._reconcile(server)
            await self._invalidate_locked(int(server["id"]))

        response = await self._call_with_receipt(
            server,
            "reconcile",
            params,
            reconcile,
            "gateway",
            "v1",
            AdapterProbe(True),
            actor,
            correlation,
            reconcile=True,
        )
        if binding.get("mode") == "adapter":
            adapter, _probe = self._adapter_probe(server, binding)
            if (
                adapter is not None
                and params.get("revision") is not None
                and await self._adapter_revision(server, adapter) == params.get("revision")
            ):
                self._mark_adapter_revision_active(server, str(params.get("revision")))
        return response

    async def _call_with_receipt(
        self,
        server,
        operation,
        params,
        invoke,
        adapter,
        version,
        probe,
        actor,
        correlation,
        *,
        reconcile=False,
        descriptor=None,
    ):
        mutation = operation in CONTROL_PLANE_MUTATING_OPERATIONS
        fingerprint = hash_control_plane_target(
            {
                "server": server["id"],
                "operation": operation,
                "params": {key: value for key, value in params.items() if key != "idempotency_key"},
            }
        )
        key = params.get("idempotency_key") if mutation else None
        if key:
            replay = self._reserve_or_replay(server["id"], operation, fingerprint, key)
            if replay is not None:
                return replay
        try:
            invocation = invoke()
            response = await invocation if hasattr(invocation, "__await__") else invocation
            if reconcile:
                response = {
                    "result": {"reconciled": True, "pending_restart": False},
                    "revision": params.get("revision", "gateway"),
                }
            response = validate_operation_response(
                operation if not reconcile else "status_get", response
            )
            response = project_management_response(
                descriptor, operation, response, entity_type=params.get("entity_type")
            )
        except asyncio.CancelledError:
            error = ManagementUnavailableError("Management operation was cancelled")
            self._audit(
                server,
                operation,
                params,
                adapter,
                version,
                probe,
                actor,
                correlation,
                False,
                "UNAVAILABLE",
            )
            self._complete_failure(key, server["id"], operation, fingerprint, error)
            raise
        except ManagementUnavailableError as exc:
            self._audit(
                server,
                operation,
                params,
                adapter,
                version,
                probe,
                actor,
                correlation,
                False,
                getattr(exc, "code", "UNAVAILABLE"),
            )
            self._complete_failure(key, server["id"], operation, fingerprint, exc)
            raise
        except ValueError as exc:
            error = ManagementValidationError(str(exc))
            self._audit(
                server,
                operation,
                params,
                adapter,
                version,
                probe,
                actor,
                correlation,
                False,
                error.code,
            )
            self._complete_failure(key, server["id"], operation, fingerprint, error)
            raise error from exc
        except Exception as exc:
            error = ManagementUnavailableError("Management operation failed")
            self._audit(
                server,
                operation,
                params,
                adapter,
                version,
                probe,
                actor,
                correlation,
                False,
                "INTERNAL",
            )
            self._complete_failure(key, server["id"], operation, fingerprint, error)
            raise error from exc
        if mutation and adapter != "gateway":
            clear_management_runtime_state(self._db_path, int(server["id"]))
            self._runtime_revisions_verified_this_boot.discard(int(server["id"]))
        self._complete_success(key, server["id"], operation, fingerprint, response)
        self._audit(
            server,
            operation,
            params,
            adapter,
            version,
            probe,
            actor,
            correlation,
            True,
            None,
            response,
        )
        return response

    def _adapter_probe(self, server: dict[str, Any], binding: dict[str, Any]):
        adapter = adapter_for(str(binding.get("adapter") or ""))
        expected_hash = binding.get("manifest_hash")
        if adapter and expected_hash != getattr(adapter, "manifest_hash", None):
            probe = AdapterProbe(False, reason="management profile requires whitelist re-approval")
        else:
            probe = (
                adapter.probe(server)
                if adapter
                else AdapterProbe(False, reason="adapter is not allowlisted")
            )
        save_management_probe(
            self._db_path,
            int(server["id"]),
            adapter=str(binding.get("adapter") or ""),
            compatible=probe.compatible,
            observed_package=probe.package,
            observed_version=probe.version,
            failure_reason=probe.reason,
        )
        return adapter, probe

    def _eligible_server(self, server_id: int) -> dict[str, Any]:
        server = get_mcp_server(self._db_path, server_id)
        if not server or not server.get("enabled") or server.get("approval_state") != "approved":
            raise ManagementUnavailableError("Management server is unavailable")
        return server

    def _lifecycle_identity(self, server: dict[str, Any]) -> str:
        detail = self._process_manager.status_detail(int(server["id"]))
        generation = detail.get("generation")
        if not isinstance(generation, int) or generation < 0:
            raise ManagementUnavailableError("Management lifecycle generation is unavailable")
        fingerprint = server.get("config_fingerprint") or hash_control_plane_target(
            {key: server.get(key) for key in ("command", "command_args", "working_dir", "env_vars")}
        )
        return f"{fingerprint}:{generation}"

    def _still_eligible(self, server: dict[str, Any], lifecycle: str) -> None:
        current = self._eligible_server(int(server["id"]))
        if self._lifecycle_identity(current) != lifecycle:
            raise ManagementUnavailableError("Management lifecycle changed")

    def _reserve_or_replay(self, server_id, operation, fingerprint, key):
        for _attempt in range(3):
            receipt = get_management_idempotency(self._db_path, key)
            if receipt:
                if (
                    receipt["mcp_server_id"] != server_id
                    or receipt["operation"] != operation
                    or receipt["request_fingerprint"] != fingerprint
                ):
                    raise ManagementConflictError("Idempotency key belongs to another request")
                if receipt["status"] == "pending":
                    raise ManagementUnavailableError(
                        "An identical management request is still running"
                    )
                return self._decode_receipt(receipt)
            if create_management_idempotency(
                self._db_path,
                idempotency_key=key,
                mcp_server_id=server_id,
                operation=operation,
                request_fingerprint=fingerprint,
            ):
                return None
        raise ManagementUnavailableError("Management idempotency reservation is unavailable")

    @staticmethod
    def _decode_receipt(receipt):
        try:
            stored = json.loads(receipt["result_json"] or "{}")
        except json.JSONDecodeError as exc:
            raise ManagementUnavailableError("Management retry receipt is invalid") from exc
        if "error" in stored:
            raise ManagementUnavailableError(stored["error"])
        return stored

    def _complete_success(self, key, server_id, operation, fingerprint, response):
        if key:
            complete_management_idempotency(
                self._db_path,
                idempotency_key=key,
                mcp_server_id=server_id,
                operation=operation,
                request_fingerprint=fingerprint,
                status="completed",
                result=response,
            )

    def _complete_failure(self, key, server_id, operation, fingerprint, error):
        if key:
            complete_management_idempotency(
                self._db_path,
                idempotency_key=key,
                mcp_server_id=server_id,
                operation=operation,
                request_fingerprint=fingerprint,
                status="failed",
                result={"error": str(error)},
            )

    def _project_adapter_state(
        self, server: dict[str, Any], operation: str, response: dict[str, Any]
    ) -> dict[str, Any]:
        """Expose active state only after this gateway successfully reconciled that revision."""
        state = get_management_runtime_state(self._db_path, int(server["id"]))
        if (
            not state
            or response.get("revision") != state["active_revision"]
            or state["config_fingerprint"] != self._server_fingerprint(server)
        ):
            return response
        result = response.get("result", {})
        if operation == "status_get":
            return {**response, "result": {**result, "state": "active"}}
        if operation == "entities_list":
            rows = [{**row, "status": "active"} for row in result.get("items", [])]
            return {**response, "result": {**result, "items": rows}}
        return response

    async def capture_runtime_revision(self, server_id: int) -> str | None:
        """Snapshot an adapter document revision before a process is restarted."""
        async with self._lock(server_id):
            try:
                server = self._eligible_server(server_id)
                binding = server.get("management") or {"mode": "none"}
                adapter, probe = self._adapter_probe(server, binding)
                if binding.get("mode") != "adapter" or adapter is None or not probe.compatible:
                    return None
                clear_management_runtime_state(self._db_path, server_id)
                self._runtime_revisions_verified_this_boot.discard(server_id)
                return await self._adapter_revision(server, adapter)
            except (ManagementUnavailableError, RuntimeError, ValueError):
                return None

    async def record_runtime_applied(self, server_id: int, expected_revision: str | None) -> bool:
        """Persist an adapter revision only when it did not change during process startup."""
        if not expected_revision:
            return False
        async with self._lock(server_id):
            try:
                server = self._eligible_server(server_id)
                binding = server.get("management") or {"mode": "none"}
                adapter, probe = self._adapter_probe(server, binding)
                if binding.get("mode") != "adapter" or adapter is None or not probe.compatible:
                    return False
                if await self._adapter_revision(server, adapter) != expected_revision:
                    return False
            except (ManagementUnavailableError, RuntimeError, ValueError):
                return False
            self._mark_adapter_revision_active(server, expected_revision)
            return True

    async def _adapter_revision(self, server: dict[str, Any], adapter: Any) -> str:
        response = validate_operation_response(
            "status_get", await asyncio.to_thread(adapter.call, server, "status_get", {})
        )
        revision = response.get("revision")
        if not isinstance(revision, str) or not revision:
            raise ManagementUnavailableError("Management adapter revision is unavailable")
        return revision

    def _mark_adapter_revision_active(self, server: dict[str, Any], revision: str) -> None:
        set_management_runtime_state(
            self._db_path, int(server["id"]), revision, self._server_fingerprint(server)
        )
        self._runtime_revisions_verified_this_boot.add(int(server["id"]))

    def is_runtime_revision_verified(self, server_id: int) -> bool:
        """Whether this gateway boot verified the persisted adapter revision."""
        return server_id in self._runtime_revisions_verified_this_boot

    @staticmethod
    def _server_fingerprint(server: dict[str, Any]) -> str:
        return str(
            server.get("config_fingerprint")
            or hash_control_plane_target(
                {
                    key: server.get(key)
                    for key in ("command", "command_args", "working_dir", "env_vars", "management")
                }
            )
        )

    def _audit(
        self,
        server,
        operation,
        params,
        adapter,
        version,
        probe,
        actor,
        correlation,
        success,
        error_code,
        response=None,
    ):
        log_management_audit(
            self._db_path,
            int(server["id"]),
            operation,
            actor_user_id=actor,
            target_id_hash=hash_control_plane_target(
                params.get("id") or params.get("entity") or {}
            ),
            previous_revision=params.get("revision"),
            revision=(response or {}).get("revision"),
            idempotency_key=params.get("idempotency_key"),
            correlation_id=correlation,
            success=success,
            error_code=error_code,
            details=redact_audit_details(
                {"adapter": adapter, "adapter_version": version, "result": response or {}}
            ),
            probe_evidence=f"{probe.package or adapter} {probe.version or version}: {probe.reason or 'compatible'}",
        )

    async def invalidate(self, server_id: int) -> None:
        async with self._lock(server_id):
            await self._invalidate_locked(server_id)

    async def fence(self, server_id: int) -> None:
        """Prevent new calls, drain current work, then evict its session."""
        self._fenced_servers.add(server_id)
        await self.invalidate(server_id)

    def unfence(self, server_id: int) -> None:
        self._fenced_servers.discard(server_id)

    def _lock(self, server_id: int) -> asyncio.Lock:
        return self._server_locks.setdefault(server_id, asyncio.Lock())

    async def _invalidate_locked(self, server_id: int) -> None:
        await self._native.invalidate(server_id)
        self._native_descriptors = {
            key: descriptor
            for key, descriptor in self._native_descriptors.items()
            if not key.startswith(f"{server_id}:")
        }

    async def close(self) -> None:
        await self._native.close()
