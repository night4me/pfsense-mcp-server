"""Fault injection for disposable-lab scenarios.

See docs/TIER1_LAB_PLAN.md's "Fault scenarios" list — every entry has a
FaultScenario member below. Network-level scenarios are mechanically
injected by FaultProxy, wrapping a Transport (I3: reusing the existing
Transport shape rather than inventing a second mechanism, matching how
store.py's own FaultHook already covers store-level faults). Store/
process-level scenarios are exercised via store.py's existing
`fault_hook` parameter, not this proxy. Target/state-level scenarios have
no fault to "inject" — the scenario is constructed as a starting state
(e.g. a target mutated between prepare and execute) and driven through
the ordinary executor path, which is expected to detect and refuse it,
exactly as tests/tier1/test_executor.py's fingerprint-drift tests already
prove offline.
"""

from __future__ import annotations

from enum import Enum

from pfsense_mcp.transport.base import Transport, TransportConnectionError, TransportResponse, TransportTimeoutError


class FaultScenario(str, Enum):
    """One member per docs/TIER1_LAB_PLAN.md "Fault scenarios" entry."""

    CLEAN_PASSTHROUGH = "clean_passthrough"
    CRASH_BEFORE_DURABLE_ACQUISITION = "crash_before_durable_acquisition"
    CRASH_AFTER_EXECUTING_BEFORE_SEND = "crash_after_executing_before_send"
    CONNECTION_RESET_DURING_UPLOAD = "connection_reset_during_upload"
    RESPONSE_DROPPED_AFTER_COMMIT = "response_dropped_after_commit"
    TIMEOUT_DURING_RESPONSE = "timeout_during_response"
    TIMEOUT_DURING_READBACK = "timeout_during_readback"
    PROCESS_RESTART_DURING_EXECUTING = "process_restart_during_executing"
    PROCESS_RESTART_DURING_ROLLING_BACK = "process_restart_during_rolling_back"
    TARGET_CHANGED_BETWEEN_PREPARE_AND_EXECUTE = "target_changed_between_prepare_and_execute"
    CONFLICTING_EDIT_AFTER_VERIFICATION = "conflicting_edit_after_verification"
    ROLLBACK_RESPONSE_LOST = "rollback_response_lost"
    CORRUPT_OR_REPLAYED_LOCAL_STORE = "corrupt_or_replayed_local_store"


# The subset FaultProxy can mechanically inject at the transport
# boundary. Every other member is exercised by other means (store
# fault_hook, or constructed starting state) — installing one of those on
# a FaultProxy is a no-op passthrough, not an error, since a harness run
# may legitimately combine a store-level fault with a clean transport.
NETWORK_INJECTABLE_SCENARIOS = frozenset(
    {
        FaultScenario.CONNECTION_RESET_DURING_UPLOAD,
        FaultScenario.RESPONSE_DROPPED_AFTER_COMMIT,
        FaultScenario.TIMEOUT_DURING_RESPONSE,
        FaultScenario.TIMEOUT_DURING_READBACK,
    }
)


class FaultProxy:
    """Wraps a Transport (real `HttpTransport` against the lab VM, or a
    `MockTransport` in offline tests) and deterministically injects at
    most one network-level fault, once, per `install()` call — scripted
    and repeatable (G2), never a random/organic fault."""

    def __init__(self, inner: Transport) -> None:
        self._inner = inner
        self._scenario = FaultScenario.CLEAN_PASSTHROUGH
        self._triggered = False

    def install(self, scenario: FaultScenario) -> None:
        self._scenario = scenario
        self._triggered = False

    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        if not self._triggered and self._scenario in NETWORK_INJECTABLE_SCENARIOS:
            self._triggered = True
            if self._scenario is FaultScenario.CONNECTION_RESET_DURING_UPLOAD:
                raise TransportConnectionError("synthetic connection reset (lab fault injection)")
            if self._scenario is FaultScenario.TIMEOUT_DURING_RESPONSE:
                raise TransportTimeoutError("synthetic timeout during response (lab fault injection)")
            if self._scenario is FaultScenario.TIMEOUT_DURING_READBACK:
                raise TransportTimeoutError("synthetic timeout during read-back (lab fault injection)")
            if self._scenario is FaultScenario.RESPONSE_DROPPED_AFTER_COMMIT:
                # The upstream request may have committed, but the
                # response itself never arrived — indistinguishable from
                # a timeout at the transport boundary. That is exactly
                # the point: it must classify as AMBIGUOUS, never as a
                # confident success or failure.
                raise TransportTimeoutError("synthetic response drop after commit (lab fault injection)")
        return self._inner.request(method, path, body=body)
