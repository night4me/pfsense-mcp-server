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
from typing import Any, Protocol

from .api_version import ApiVersion, version_at_least
from .errors import WriteNotAllowedError
from .recovery import RecoveryContract
from .transport.base import Transport, TransportConnectionError, TransportResponse, TransportTimeoutError
from .write_endpoints import WriteEndpointInfo, WriteEndpoints
from .write_types import ContractStatus, DryRunResult, ExecutionResult, MutationPlan


class _AcceptanceExecutionProof(Protocol):
    """ADR-029: a structural type only -- deliberately not an import of
    `tier1.acceptance.AcceptanceExecutionContext` (this module must never
    import anything from `tier1`, per
    `tests/tier1/test_isolation.py::test_tier1_is_not_imported_outside_its_inert_package`,
    and importing it even under `TYPE_CHECKING` would still trip that AST
    -level check, which does not evaluate the guard). `AcceptanceExecutionContext`
    satisfies this shape; nothing else meaningfully can, since its
    `__post_init__` already enforces `target_identity` is the pinned LAB
    identity before an instance can exist at all.

    Read-only `@property` members, not plain attribute annotations: a
    frozen dataclass's fields are read-only, and a Protocol's plain
    attribute annotation requires a settable member (mypy checks both
    getter and setter compatibility) -- this must match structurally
    against an immutable implementation."""

    @property
    def endpoint_symbol(self) -> str: ...

    @property
    def http_method(self) -> str: ...

    @property
    def target_identity(self) -> str: ...


# Re-exported so tier1/executor.py -- forbidden from importing
# pfsense_mcp.transport directly (tests/tier1/test_isolation.py) -- can
# classify send_for_tier1() failures without ever holding a Transport
# reference itself.
__all__ = ["TransportConnectionError", "TransportTimeoutError", "WriteApiClient"]

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

    def send_for_tier1(self, *, endpoint_symbol: str, http_method: str, body: bytes) -> TransportResponse:
        """The sealed Tier 1 executor's only entry point into this
        chokepoint (see docs/tier1/specs/sealed_executor.md). Unlike
        execute() above, this takes no Tier 0 RecoveryContract: Tier 1's
        caller has already performed its own, more rigorous contract
        validation (PREPARED/confirmed/unexpired, atomic
        PREPARED -> EXECUTING acquisition, target re-verification) before
        ever reaching this call, so re-imposing Tier 0's simpler
        status == OPEN check here would be redundant and would incorrectly
        couple this chokepoint to a contract model Tier 1 does not use.

        Performs the identical allow-list/verified/method/api-version
        checks as execute() and is exactly as inert while WriteEndpoints
        is empty -- every call refuses before any network call in this
        build. Returns the raw TransportResponse; classifying it into
        VERIFIED/FAILED/RECONCILIATION is the executor's responsibility,
        not this chokepoint's -- this method's only job is to prove
        exactly one bounded request reached exactly one allow-listed
        endpoint."""

        endpoint = _resolve_endpoint(endpoint_symbol)
        if endpoint is None:
            raise WriteNotAllowedError(f"{endpoint_symbol!r} is not in the write allow-list.")
        if not endpoint.verified:
            raise WriteNotAllowedError(f"WriteEndpoints.{endpoint_symbol} is not verified=True.")
        if endpoint.http_method != http_method:
            raise WriteNotAllowedError(
                f"http_method {http_method!r} does not match the allow-listed method for {endpoint_symbol!r}."
            )
        if not version_at_least(self._api_version, endpoint.min_api_version):
            raise WriteNotAllowedError(
                f"Endpoint requires API version >= {endpoint.min_api_version.value}, "
                f"client is configured for {self._api_version.value}."
            )
        path = f"/api/{self._api_version.value}{endpoint.path_suffix}"
        return self._request(http_method, path, body=body)

    def send_for_tier1_acceptance(
        self, *, acceptance_context: _AcceptanceExecutionProof, endpoint_symbol: str, http_method: str, body: bytes
    ) -> TransportResponse:
        """ADR-029's separate, structurally-isolated first-live-acceptance
        chokepoint. Reachable only via `tier1.acceptance.issue_acceptance_context()`
        producing the mandatory `acceptance_context` -- there is no default,
        no way to omit it, and no way to construct one from JSON/MCP-style
        input (see that module's own docstring for the isolation proof).

        Deliberately does NOT reuse send_for_tier1()'s `verified` check --
        it requires the opposite (`endpoint.verified is False`), and an
        independent `endpoint.acceptance_eligible is True` check plus three
        cross-checks against the caller-supplied context and this client's
        own bound identity, none of which send_for_tier1() performs. This
        method's existence never changes send_for_tier1()'s, execute()'s,
        or dry_run()'s behavior -- all three remain byte-for-byte
        unmodified and still refuse unconditionally while verified is
        False, exactly as before this ADR."""

        endpoint = _resolve_endpoint(endpoint_symbol)
        if endpoint is None:
            raise WriteNotAllowedError(f"{endpoint_symbol!r} is not in the write allow-list.")
        if not endpoint.acceptance_eligible:
            raise WriteNotAllowedError(f"WriteEndpoints.{endpoint_symbol} is not acceptance_eligible=True.")
        if endpoint.verified:
            raise WriteNotAllowedError(
                f"WriteEndpoints.{endpoint_symbol} is already verified=True; "
                "the first-live-acceptance path permanently refuses further use."
            )
        if endpoint.http_method != http_method:
            raise WriteNotAllowedError(
                f"http_method {http_method!r} does not match the allow-listed method for {endpoint_symbol!r}."
            )
        if acceptance_context.endpoint_symbol != endpoint_symbol:
            raise WriteNotAllowedError("Acceptance context endpoint_symbol does not match this call.")
        if acceptance_context.http_method != http_method:
            raise WriteNotAllowedError("Acceptance context http_method does not match this call.")
        if acceptance_context.target_identity != self._identity:
            raise WriteNotAllowedError("Acceptance context target identity does not match this client.")
        if not version_at_least(self._api_version, endpoint.min_api_version):
            raise WriteNotAllowedError(
                f"Endpoint requires API version >= {endpoint.min_api_version.value}, "
                f"client is configured for {self._api_version.value}."
            )
        path = f"/api/{self._api_version.value}{endpoint.path_suffix}"
        return self._request(http_method, path, body=body)

    def _request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        # Unreachable in this build via execute(): it always raises
        # WriteNotAllowedError first, since WriteEndpoints is empty.
        # Also unreachable via send_for_tier1() for the same reason. This
        # is the sole call site scripts/get_only_check.py permits for a
        # non-GET request, mirroring RestApiClient._request's role for GET.
        logger.warning("mutating_request identity=%s method=%s path=%s", self._identity, method, path)
        return self._transport.request(method, path, body=body)
