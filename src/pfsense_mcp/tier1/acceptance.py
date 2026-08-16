"""ADR-029: the first-live-acceptance execution boundary.

Not imported by `production_runtime.py`'s own MCP-reachable construction
path, `application.py`, `server.py`, `factory.py`, or any tool-registration
module -- enforced by `tests/tier1/test_acceptance_isolation.py`'s AST-based
import-graph check, the same technique `tests/test_signing_tool_isolation.py`
already uses to prove no production module imports `signing.*`. This module
exists solely to gather the live evidence ADR-026's acceptance matrix (rows
6/17/18) still requires before `WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.
verified` may be promoted from `False` to `True` -- see ADR-029 for the full
circularity this resolves and why a raw PATCH or a provisional
`verified=True` were both explicitly rejected.

`AcceptanceExecutionContext` carries no authority of its own: it changes
nothing about authorization, confirmation, RecoveryContract, or
MutationExecutor semantics, all of which remain completely unmodified and
mandatory. Its only effect is selecting, at the very last step inside
`MutationExecutor._send()`, which one of two independently-gated
`WriteApiClient` methods is called -- `send_for_tier1()` (unchanged, requires
`verified=True`) or `send_for_tier1_acceptance()` (new, requires
`acceptance_eligible=True` and `verified=False`, plus this context).

One-time semantics are provided by facts that already exist rather than any
new persisted flag (see ADR-029 "Lifecycle / one-time semantics"): `verified`
is source code, not runtime state, so once a build ships with it `True`,
`issue_acceptance_context()` below and `send_for_tier1_acceptance()`'s own
independent re-check both refuse permanently; replay/repetition within one
unverified run is already prevented by the unmodified authorization-
consumption and contract state-machine layers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from pfsense_mcp.config import PfSenseConfig
from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints

from .errors import AcceptanceError

#: Hardcoded, not read from environment configuration -- an operator
#: mistake in PFSENSE_API_URL/PFSENSE_IDENTITY cannot cause this path to
#: target anything else, because the comparison value itself is not
#: derived from that same environment (ADR-029 "Target/endpoint
#: restriction").
_ACCEPTANCE_TARGET_BASE_URL = "https://pfsense-test.lab.invalid"
_ACCEPTANCE_TARGET_IDENTITY = "pfsense_lab1"

#: How long an issued context remains usable. Short enough that a stale
#: context found lying around cannot be reused far from when it was
#: issued; long enough for one real, human-paced authorization +
#: confirmation ceremony.
_CONTEXT_MAX_AGE = timedelta(minutes=30)


def _resolve_endpoint(endpoint_symbol: str) -> WriteEndpointInfo | None:
    candidate = getattr(WriteEndpoints, endpoint_symbol, None)
    return candidate if isinstance(candidate, WriteEndpointInfo) else None


@dataclass(frozen=True, slots=True)
class AcceptanceExecutionContext:
    """Proof that `issue_acceptance_context()` validated the LAB target,
    the endpoint's acceptance eligibility, and that `verified` is still
    `False`, at `issued_at`. Never constructed directly by calling code --
    always via `issue_acceptance_context()`, which is the only place these
    invariants are actually checked against live state. Re-checked again,
    independently, by `WriteApiClient.send_for_tier1_acceptance()` at the
    point of use -- this object is never trusted on its own say-so."""

    endpoint_symbol: str
    http_method: str
    target_identity: str
    issued_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint_symbol, str) or not self.endpoint_symbol:
            raise AcceptanceError("Acceptance context endpoint_symbol is invalid.")
        if not isinstance(self.http_method, str) or not self.http_method:
            raise AcceptanceError("Acceptance context http_method is invalid.")
        if self.target_identity != _ACCEPTANCE_TARGET_IDENTITY:
            raise AcceptanceError("Acceptance context target identity is not the pinned LAB identity.")
        if (
            not isinstance(self.issued_at, datetime)
            or self.issued_at.tzinfo is None
            or self.issued_at.utcoffset() != timezone.utc.utcoffset(self.issued_at)
        ):
            raise AcceptanceError("Acceptance context issued_at must be UTC.")

    def is_fresh(self, *, now: datetime) -> bool:
        if now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
            raise AcceptanceError("Freshness check requires a UTC 'now'.")
        return self.issued_at <= now < self.issued_at + _CONTEXT_MAX_AGE


def issue_acceptance_context(
    pf_config: PfSenseConfig, *, endpoint_symbol: str = "FIREWALL_ALIAS_DESCRIPTION"
) -> AcceptanceExecutionContext:
    """The only way to obtain an `AcceptanceExecutionContext`. Refuses
    (raises `AcceptanceError`) unless every one of the following holds:

    - `pf_config` names exactly the pinned LAB appliance and identity
      (never production/home pfSense, never any other LAB-shaped value).
    - `endpoint_symbol` names a real `WriteEndpoints` entry.
    - That entry has `acceptance_eligible=True`.
    - That entry still has `verified=False` -- the one-time gate: once a
      build ships with `verified=True`, this call refuses permanently.
    """

    if pf_config.base_url != _ACCEPTANCE_TARGET_BASE_URL:
        raise AcceptanceError(f"Acceptance is LAB-only; refusing target {pf_config.base_url!r}.")
    if pf_config.identity != _ACCEPTANCE_TARGET_IDENTITY:
        raise AcceptanceError(f"Acceptance is pfsense_lab1-only; refusing identity {pf_config.identity!r}.")

    endpoint = _resolve_endpoint(endpoint_symbol)
    if endpoint is None:
        raise AcceptanceError(f"{endpoint_symbol!r} is not in the write allow-list.")
    if not endpoint.acceptance_eligible:
        raise AcceptanceError(f"WriteEndpoints.{endpoint_symbol} is not acceptance_eligible=True.")
    if endpoint.verified:
        raise AcceptanceError(
            f"WriteEndpoints.{endpoint_symbol} is already verified=True; "
            "the first-live-acceptance path permanently refuses further use."
        )

    return AcceptanceExecutionContext(
        endpoint_symbol=endpoint_symbol,
        http_method=endpoint.http_method,
        target_identity=pf_config.identity,
        issued_at=datetime.now(timezone.utc),
    )
