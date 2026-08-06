"""WriteApiClient — the second, and only other, module permitted to
call a Transport's request() method directly (see
scripts/get_only_check.py, whose allow-list names this file explicitly
alongside rest_api_client.py).

dry_run() never issues a non-GET network call: it only validates a
MutationPlan against the (empty, in this build) WriteEndpoints allow-list
and, if a current_state snapshot is supplied by the caller, computes a
predicted diff in-process. execute() additionally requires a valid, open
Recovery Contract and is the only method in this class that reaches
_request() with a non-GET method — and since WriteEndpoints ships empty,
every execute() call in this build refuses before any network call too.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from .api_version import ApiVersion, version_at_least
from .errors import WriteNotAllowedError
from .recovery import RecoveryContract
from .transport.base import Transport, TransportResponse
from .write_endpoints import WriteEndpointInfo, WriteEndpoints
from .write_types import ContractStatus, DryRunResult, ExecutionResult, MutationPlan

logger = logging.getLogger("pfsense_mcp.write_api_client")


def _resolve_endpoint(endpoint_symbol: str) -> WriteEndpointInfo | None:
    candidate = getattr(WriteEndpoints, endpoint_symbol, None)
    return candidate if isinstance(candidate, WriteEndpointInfo) else None


def _compute_diff(current_state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    diff: dict[str, Any] = {}
    for key, new_value in payload.items():
        old_value = current_state.get(key)
        if old_value != new_value:
            diff[key] = {"from": old_value, "to": new_value}
    return diff


class WriteApiClient:
    def __init__(self, transport: Transport, *, identity: str, api_version: ApiVersion) -> None:
        self._transport = transport
        self._identity = identity
        self._api_version = api_version

    def dry_run(self, plan: MutationPlan, *, current_state: dict[str, Any] | None = None) -> DryRunResult:
        reasons: list[str] = []
        endpoint = _resolve_endpoint(plan.endpoint_symbol)

        if endpoint is None:
            reasons.append(f"{plan.endpoint_symbol!r} is not in the write allow-list (WriteEndpoints).")
        else:
            if not endpoint.verified:
                reasons.append(f"WriteEndpoints.{plan.endpoint_symbol} is not verified=True.")
            if endpoint.http_method != plan.http_method:
                reasons.append(
                    f"plan.http_method {plan.http_method!r} does not match the allow-listed "
                    f"method {endpoint.http_method!r}."
                )
            if not endpoint.dry_run_supported:
                reasons.append(f"WriteEndpoints.{plan.endpoint_symbol} does not support dry-run.")

        allowed = not reasons
        predicted_diff = _compute_diff(current_state, plan.payload) if (allowed and current_state is not None) else None
        return DryRunResult(allowed=allowed, reasons=tuple(reasons), predicted_diff=predicted_diff)

    def execute(self, plan: MutationPlan, contract: RecoveryContract | None) -> ExecutionResult:
        endpoint = _resolve_endpoint(plan.endpoint_symbol)
        if endpoint is None:
            raise WriteNotAllowedError(f"{plan.endpoint_symbol!r} is not in the write allow-list.")
        if endpoint.http_method != plan.http_method:
            raise WriteNotAllowedError(
                f"plan.http_method does not match the allow-listed method for {plan.endpoint_symbol!r}."
            )
        if contract is None:
            raise WriteNotAllowedError("No Recovery Contract supplied; a mutation requires one.")
        if contract.status != ContractStatus.OPEN or contract.is_expired():
            raise WriteNotAllowedError("Recovery Contract is not open (missing, committed, rolled back, or expired).")
        if not version_at_least(self._api_version, endpoint.min_api_version):
            raise WriteNotAllowedError(
                f"Endpoint requires API version >= {endpoint.min_api_version.value}, "
                f"client is configured for {self._api_version.value}."
            )

        path = f"/api/{self._api_version.value}{endpoint.path_suffix}"
        response = self._request(plan.http_method, path)
        return ExecutionResult(
            contract_id=contract.contract_id,
            status_code=response.status_code,
            committed_at_utc=datetime.now(timezone.utc).isoformat(),
        )

    def _request(self, method: str, path: str) -> TransportResponse:
        # Unreachable in this build: execute() above always raises
        # WriteNotAllowedError first, since WriteEndpoints is empty.
        # This is the sole call site scripts/get_only_check.py permits
        # for a non-GET request, mirroring RestApiClient._request's role
        # for GET.
        logger.warning("mutating_request identity=%s method=%s path=%s", self._identity, method, path)
        return self._transport.request(method, path)
