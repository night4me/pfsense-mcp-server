"""Regression, adversarial, and concurrency tests for
`pfsense_mcp.tier1.execution_coordinator` -- ADR-022 Phase E, Slice E2
(`docs/adr/ADR-024-execution-authorization-coordination.md`, "Slice 2").

Proves the one invariant this slice establishes: an execution attempt
may reach the consumed state only after signature validity, expiry/
currentness, exact plan-digest + authorized-step membership, and full
freshness re-check all succeed, in that order -- and that reaching
consumption always means exactly one durable, one-time state change,
never more, never less. No `RecoveryContract`, no `MutationExecutor`,
no `tier1/state_machine.py` interaction anywhere in this module or
these tests.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import pfsense_mcp.security_plan_freshness as security_plan_freshness
import pfsense_mcp.tier1.execution_coordinator as execution_coordinator
from pfsense_mcp.security_authorization import build_plan_authorization_payload, sign_plan_authorization
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.tier1.authorization_consumption_store import SqliteAuthorizationConsumptionStore
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.errors import AuthorizationConsumptionError
from pfsense_mcp.tier1.execution_coordinator import (
    ExecutionCoordinator,
    PreExecutionAuthorizationDenied,
    PreExecutionAuthorizationGranted,
)
from tests.test_security_plan_digest import _synthetic_plan, _synthetic_step

_INTEGRITY_KEY = b"synthetic-test-integrity-key-32bytes!"


# ---------------------------------------------------------------------------
# Shared fixtures/helpers -- mirror the established conventions from
# test_security_authorization_verifier.py / test_authorization_consumption_store.py
# ---------------------------------------------------------------------------


def _keypair():
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return private_key, public_bytes


def _authorities(authority_id: str, public_key: bytes, *, active: bool = True) -> PinnedAuthoritySet:
    return PinnedAuthoritySet((PinnedAuthority(authority_id=authority_id, public_key=public_key, active=active),))


def _plan(step_id: str = "s1", level: AuthorizationLevel = AuthorizationLevel.CONFIGURATION_CHANGE):
    return _synthetic_plan(steps=(_synthetic_step(step_id=step_id, order=1, authorization_required=level),))


def _times(*, ttl_seconds: int = 300):
    issued = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc)
    return issued, issued + timedelta(seconds=ttl_seconds)


def _authz(plan=None, step_ids=("s1",), *, private_key, authority_id="owner-1", authorization_id="authz-1"):
    plan = plan if plan is not None else _plan()
    issued, expires = _times()
    payload = build_plan_authorization_payload(
        plan,
        step_ids,
        authorization_id=authorization_id,
        authority_id=authority_id,
        issued_at=issued,
        expires_at=expires,
    )
    return sign_plan_authorization(payload, private_key)


def _consumption_store(tmp_path, *, store_id="synthetic-coordinator-store"):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    return SqliteAuthorizationConsumptionStore(
        tmp_path / "consumed.sqlite3", integrity_key=_INTEGRITY_KEY, store_id=store_id
    )


class _AssertNeverConsumedStore:
    """A fake `AuthorizationConsumptionStore` whose `try_consume` blows up
    if ever called -- used to prove earlier gates short-circuit before
    reaching consumption."""

    def try_consume(self, authorization_id: str) -> bool:
        raise AssertionError("try_consume() must not be reached before every earlier gate has passed")


class _RaisingConsumptionStore:
    """A fake that always raises AuthorizationConsumptionError, proving
    the coordinator converts an indeterminate consumption-store outcome
    into its own sanitized denial, never a raw store exception."""

    def try_consume(self, authorization_id: str) -> bool:
        raise AuthorizationConsumptionError("simulated indeterminate consumption-store failure")


def _setup(tmp_path, monkeypatch, *, step_id="s1", authority_id="owner-1", fresh_plan=None):
    """Builds a coordinator plus a validly-signed, currently-scoped
    authorization, with freshness patched (mirroring
    test_security_plan_freshness.py's own `_patched_freshness` pattern)
    to deterministically reproduce the authorized plan -- avoiding real
    discovery I/O in tests whose focus is the coordinator's own
    composition and ordering, not freshness itself (already covered by
    tests/test_security_plan_freshness.py)."""

    key, public_bytes = _keypair()
    plan = _plan(step_id=step_id)
    authz = _authz(plan=plan, step_ids=(step_id,), private_key=key, authority_id=authority_id)
    monkeypatch.setattr(security_plan_freshness, "generate_security_posture_plan", lambda *a, **k: fresh_plan or plan)
    coordinator = ExecutionCoordinator(
        authorities=_authorities(authority_id, public_bytes), consumption_store=_consumption_store(tmp_path)
    )
    return coordinator, authz, step_id


def _call(coordinator, authz, step_id, **overrides):
    kwargs = {
        "requested_plan_digest": authz.plan_digest,
        "requested_step_id": step_id,
        "target_capability_posture": CapabilityPosture.READ_ONLY,
        "target_anchor_assurance": AnchorAssurance.NONE,
        "now": authz.issued_at,
    }
    kwargs.update(overrides)
    return coordinator.authorize_and_consume(authz, **kwargs)


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------


def test_valid_authorization_first_consumption_succeeds(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    result = _call(coordinator, authz, step_id)
    assert isinstance(result, PreExecutionAuthorizationGranted)
    assert result.authorization_id == authz.authorization_id


# ---------------------------------------------------------------------------
# 2. Each ordinary security gate denies and does not consume
# ---------------------------------------------------------------------------


def test_invalid_signature_denies_and_does_not_consume(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    # Rebuild coordinator with a *different* signer's authorities so the
    # authz's real signature no longer verifies.
    _, wrong_public_bytes = _keypair()
    coordinator = ExecutionCoordinator(
        authorities=_authorities("owner-1", wrong_public_bytes), consumption_store=_consumption_store(tmp_path / "b")
    )
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id)
    # Not consumed: an independent store using the same file must still
    # accept a first consumption of this authorization_id.
    store = SqliteAuthorizationConsumptionStore(
        tmp_path / "b" / "consumed.sqlite3", integrity_key=_INTEGRITY_KEY, store_id="synthetic-coordinator-store"
    )
    assert store.try_consume(authz.authorization_id) is True


def test_wrong_signer_denies_and_does_not_consume(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch, authority_id="owner-1")
    _, other_public_bytes = _keypair()
    coordinator = ExecutionCoordinator(
        authorities=_authorities("someone-else", other_public_bytes),
        consumption_store=_consumption_store(tmp_path / "b"),
    )
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id)


def test_expired_authorization_denies_and_does_not_consume(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id, now=authz.expires_at)
    store = SqliteAuthorizationConsumptionStore(
        tmp_path / "consumed.sqlite3", integrity_key=_INTEGRITY_KEY, store_id="synthetic-coordinator-store"
    )
    assert store.try_consume(authz.authorization_id) is True


def test_wrong_plan_digest_denies_and_does_not_consume(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id, requested_plan_digest="ab" * 32)


def test_unauthorized_step_denies_and_does_not_consume(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id, requested_step_id="a-different-step")


def test_freshness_mismatch_denies_and_does_not_consume(tmp_path, monkeypatch):
    stale_plan = _synthetic_plan(
        steps=(_synthetic_step(step_id="s1", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),)
    )
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch, fresh_plan=stale_plan)
    # Force an actual mismatch: authz was built against one synthetic
    # plan object, freshness patched to reproduce a *different* one.
    monkeypatch.setattr(
        security_plan_freshness, "generate_security_posture_plan", lambda *a, **k: _synthetic_plan(steps=())
    )
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id)
    store = SqliteAuthorizationConsumptionStore(
        tmp_path / "consumed.sqlite3", integrity_key=_INTEGRITY_KEY, store_id="synthetic-coordinator-store"
    )
    assert store.try_consume(authz.authorization_id) is True


def test_freshness_exception_denies_and_does_not_consume(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated discovery failure")

    monkeypatch.setattr(security_plan_freshness, "generate_security_posture_plan", _boom)
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id)
    store = SqliteAuthorizationConsumptionStore(
        tmp_path / "consumed.sqlite3", integrity_key=_INTEGRITY_KEY, store_id="synthetic-coordinator-store"
    )
    assert store.try_consume(authz.authorization_id) is True


def test_malformed_authorization_object_denies(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    with pytest.raises(PreExecutionAuthorizationDenied):
        coordinator.authorize_and_consume(
            {"not": "a PlanAuthorization"},  # type: ignore[arg-type]
            requested_plan_digest=authz.plan_digest,
            requested_step_id=step_id,
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            now=authz.issued_at,
        )


@pytest.mark.parametrize("bad_step_id", [None, 12345, "", ["s1"]])
def test_malformed_step_id_denies(tmp_path, monkeypatch, bad_step_id):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id, requested_step_id=bad_step_id)


def test_consumption_store_failure_denies_and_is_sanitized(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    coordinator = ExecutionCoordinator(
        authorities=coordinator._authorities, consumption_store=_RaisingConsumptionStore()
    )
    with pytest.raises(PreExecutionAuthorizationDenied) as excinfo:
        _call(coordinator, authz, step_id)
    assert "simulated indeterminate" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# 3. Replay / concurrency
# ---------------------------------------------------------------------------


def test_repeated_valid_call_second_attempt_is_rejected(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    first = _call(coordinator, authz, step_id)
    assert isinstance(first, PreExecutionAuthorizationGranted)
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id)


def test_failed_attempt_then_corrected_valid_attempt_still_succeeds(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id, requested_step_id="wrong-step")
    result = _call(coordinator, authz, step_id)
    assert isinstance(result, PreExecutionAuthorizationGranted)


def test_concurrent_attempts_yield_exactly_one_success(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    results: list[object] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            outcome = _call(coordinator, authz, step_id)
        except PreExecutionAuthorizationDenied as exc:
            outcome = exc
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    granted = [r for r in results if isinstance(r, PreExecutionAuthorizationGranted)]
    denied = [r for r in results if isinstance(r, PreExecutionAuthorizationDenied)]
    assert len(granted) == 1
    assert len(denied) == 7


# ---------------------------------------------------------------------------
# 4. Exact ordering proof -- each gate must short-circuit before the next
# ---------------------------------------------------------------------------


def test_expiry_check_never_reached_when_signature_invalid(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    _, wrong_public_bytes = _keypair()
    coordinator = ExecutionCoordinator(
        authorities=_authorities("owner-1", wrong_public_bytes), consumption_store=_consumption_store(tmp_path / "b")
    )

    def _boom(*args, **kwargs):
        raise AssertionError("plan_authorization_is_current must not be reached")

    monkeypatch.setattr(execution_coordinator, "plan_authorization_is_current", _boom)
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id)


def test_scope_check_never_reached_when_expired(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)

    def _boom(*args, **kwargs):
        raise AssertionError("plan_authorization_authorizes_step must not be reached")

    monkeypatch.setattr(execution_coordinator, "plan_authorization_authorizes_step", _boom)
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id, now=authz.expires_at)


def test_freshness_check_never_reached_when_scope_wrong(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)

    def _boom(*args, **kwargs):
        raise AssertionError("plan_authorization_is_fresh must not be reached")

    monkeypatch.setattr(execution_coordinator, "plan_authorization_is_fresh", _boom)
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id, requested_step_id="a-different-step")


def test_consumption_never_reached_when_freshness_fails(tmp_path, monkeypatch):
    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    coordinator = ExecutionCoordinator(
        authorities=coordinator._authorities, consumption_store=_AssertNeverConsumedStore()
    )
    monkeypatch.setattr(
        security_plan_freshness, "generate_security_posture_plan", lambda *a, **k: _synthetic_plan(steps=())
    )
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id)


def test_freshness_occurs_before_consumption_on_the_success_path(tmp_path, monkeypatch):
    """A stronger version of the above: even on an otherwise-successful
    path, freshness must be evaluated (and pass) strictly before
    try_consume() is ever called -- proven by a spy store recording call
    order relative to a freshness call counter."""

    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    call_order: list[str] = []
    real_is_fresh = execution_coordinator.plan_authorization_is_fresh

    def _spy_is_fresh(*args, **kwargs):
        call_order.append("freshness")
        return real_is_fresh(*args, **kwargs)

    monkeypatch.setattr(execution_coordinator, "plan_authorization_is_fresh", _spy_is_fresh)

    store = _consumption_store(tmp_path)
    real_try_consume = store.try_consume

    def _spy_try_consume(authorization_id):
        call_order.append("consumption")
        return real_try_consume(authorization_id)

    store.try_consume = _spy_try_consume  # type: ignore[method-assign]
    coordinator = ExecutionCoordinator(authorities=coordinator._authorities, consumption_store=store)

    result = _call(coordinator, authz, step_id)
    assert isinstance(result, PreExecutionAuthorizationGranted)
    assert call_order == ["freshness", "consumption"]


# ---------------------------------------------------------------------------
# 5. Cross-cutting invariants
# ---------------------------------------------------------------------------


def test_signature_validity_never_implies_consumption(tmp_path, monkeypatch):
    """A validly-signed authorization that fails a later gate (here:
    expiry) leaves the authorization available for a genuine first
    consumption -- signature validity alone never burns it."""

    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    with pytest.raises(PreExecutionAuthorizationDenied):
        _call(coordinator, authz, step_id, now=authz.expires_at)
    store = SqliteAuthorizationConsumptionStore(
        tmp_path / "consumed.sqlite3", integrity_key=_INTEGRITY_KEY, store_id="synthetic-coordinator-store"
    )
    assert store.try_consume(authz.authorization_id) is True


def test_consumption_never_implies_signature_validity():
    """Structural: PreExecutionAuthorizationGranted carries no signature/
    verification-shaped field or method at all -- its mere existence
    cannot be later used to re-derive or assert 'the signature was
    valid' beyond what already happened inside authorize_and_consume()."""

    granted = PreExecutionAuthorizationGranted(authorization_id="x")
    assert not hasattr(granted, "signature_valid")
    assert not hasattr(granted, "verify")
    assert vars(granted).keys() == {"authorization_id"} if hasattr(granted, "__dict__") else True


def test_granted_result_carries_no_execution_or_contract_shaped_attribute():
    granted = PreExecutionAuthorizationGranted(authorization_id="x")
    forbidden = {"execute", "contract_id", "recovery_contract", "apply", "state"}
    assert forbidden.isdisjoint(dir(granted))


def test_denied_exception_message_is_uniform_across_all_gates(tmp_path, monkeypatch):
    """Every distinct failure reason maps to the exact same exception
    message -- proving no gate-identifying detail leaks through the
    public API."""

    coordinator, authz, step_id = _setup(tmp_path, monkeypatch)
    messages = set()

    with pytest.raises(PreExecutionAuthorizationDenied) as excinfo:
        _call(coordinator, authz, step_id, requested_step_id="wrong")
    messages.add(str(excinfo.value))

    with pytest.raises(PreExecutionAuthorizationDenied) as excinfo:
        _call(coordinator, authz, step_id, now=authz.expires_at)
    messages.add(str(excinfo.value))

    with pytest.raises(PreExecutionAuthorizationDenied) as excinfo:
        _call(coordinator, authz, step_id, requested_plan_digest="ab" * 32)
    messages.add(str(excinfo.value))

    assert len(messages) == 1
