from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.errors import RateLimitExceededError
from pfsense_mcp.tier1.rate_policy import RateLimits, RatePolicy
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

_KEY = b"synthetic-test-integrity-key-32bytes!"


class _AcceptingVerifier:
    def verify(self, evidence: ConfirmationEvidence) -> bool:
        return evidence.proof == b"synthetic-valid-proof"


def _permissive_limits(**overrides):
    fields = {
        "max_outstanding_prepared_per_target": 100,
        "max_global_in_flight": 100,
        "target_cooldown_seconds": 0,
        "reconciliation_lockout_threshold": 100,
    }
    fields.update(overrides)
    return RateLimits(**fields)


def _store(tmp_path, *, rate_policy=None, clock=None):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    options = {}
    if clock is not None:
        options["clock"] = clock
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=_KEY,
        store_id="synthetic-store",
        confirmation_verifier=_AcceptingVerifier(),
        rate_policy=rate_policy,
        **options,
    )


def _evidence(contract):
    return ConfirmationEvidence(
        authority_id="synthetic-owner",
        algorithm="test-verifier",
        nonce="nonce-001",
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        target_identity_digest=contract.target_identity_digest,
        target_fingerprint=contract.target_fingerprint,
        intent_digest=contract.intent_digest,
        expires_at=contract.expires_at,
        issued_at=contract.created_at,
        proof=b"synthetic-valid-proof",
    )


def _confirmed(store, contract):
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    return store.confirm(contract.contract_id, evidence=_evidence(prepared), expected_version=prepared.state_version)


def test_rate_limits_rejects_negative_values():
    with pytest.raises(RateLimitExceededError):
        RateLimits(
            max_outstanding_prepared_per_target=-1,
            max_global_in_flight=1,
            target_cooldown_seconds=0,
            reconciliation_lockout_threshold=1,
        )


def test_no_rate_policy_configured_preserves_existing_behavior(tmp_path, contract_factory):
    store = _store(tmp_path, rate_policy=None)
    first = _confirmed(store, contract_factory())
    store.transition(
        first.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=first.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    # A second contract for the SAME target can also reach PREPARED with no policy configured.
    second = contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False})
    store.create(second)


def test_outstanding_prepared_per_target_limit_is_enforced(tmp_path, contract_factory):
    policy = RatePolicy(_permissive_limits(max_outstanding_prepared_per_target=1))
    store = _store(tmp_path, rate_policy=policy)

    first = contract_factory()
    _confirmed(store, first)  # reaches PREPARED (and confirmed) for this target

    second = contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False})
    with pytest.raises(RateLimitExceededError, match="outstanding PREPARED"):
        store.create(second)


def test_preparing_state_does_not_count_against_the_prepared_limit(tmp_path, contract_factory):
    """Only PREPARED (not PREPARING) counts -- see rate_policy.py's
    module note on why this is the deliberate reading of the spec."""

    policy = RatePolicy(_permissive_limits(max_outstanding_prepared_per_target=1))
    store = _store(tmp_path, rate_policy=policy)

    store.create(contract_factory())  # stays in PREPARING, never transitioned
    second = contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False})
    store.create(second)  # must succeed: zero contracts are PREPARED yet


def test_global_in_flight_limit_is_enforced_at_executing(tmp_path, contract_factory):
    policy = RatePolicy(_permissive_limits(max_global_in_flight=1))
    store = _store(tmp_path, rate_policy=policy)

    first = _confirmed(store, contract_factory())
    store.transition(
        first.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=first.state_version,
        target_state=RecoveryState.EXECUTING,
    )

    second = _confirmed(
        store, contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False})
    )
    with pytest.raises(RateLimitExceededError, match="in-flight"):
        store.transition(
            second.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=second.state_version,
            target_state=RecoveryState.EXECUTING,
        )
    # Refusal must be pre-send: the contract stays PREPARED, never partially EXECUTING.
    assert store.load(second.contract_id).state == RecoveryState.PREPARED


class _ManualClock:
    """A clock the test controls explicitly, rather than an
    auto-advancing iterator -- makes "cooldown expires after N seconds"
    assertable deterministically instead of hoping enough internal
    _now() calls happened to cross the boundary."""

    def __init__(self, start: datetime) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


def test_cooldown_blocks_immediate_reprepare_and_expires(tmp_path, contract_factory):
    epoch = datetime(2026, 1, 1, tzinfo=timezone.utc)
    clock = _ManualClock(epoch)

    policy = RatePolicy(_permissive_limits(target_cooldown_seconds=60))
    store = _store(tmp_path, rate_policy=policy, clock=clock)

    contract = contract_factory(now=epoch)
    confirmed = _confirmed(store, contract)
    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    store.mark_execution_verified(
        executing.contract_id,
        expected_version=executing.state_version,
        verified_target_fingerprint=executing.target_fingerprint,
    )

    same_target_new_contract = contract_factory(
        contract_id="contract-002", operation_id="operation-002", intent={"enabled": False}, now=epoch
    )
    with pytest.raises(RateLimitExceededError, match="cooldown"):
        store.create(same_target_new_contract)

    clock.advance(59)  # one second before the boundary: still within cooldown
    with pytest.raises(RateLimitExceededError, match="cooldown"):
        store.create(same_target_new_contract)

    clock.advance(1)  # exactly at the boundary: now == cooldown_until, no longer "<", cooldown has expired
    store.create(same_target_new_contract)  # must succeed now
    assert store.load(same_target_new_contract.contract_id).state == RecoveryState.PREPARING


def test_reconciliation_lockout_blocks_all_new_prepares(tmp_path, contract_factory):
    policy = RatePolicy(_permissive_limits(reconciliation_lockout_threshold=1))
    store = _store(tmp_path, rate_policy=policy)

    contract = contract_factory()
    confirmed = _confirmed(store, contract)
    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    store.transition(
        executing.contract_id,
        expected_state=RecoveryState.EXECUTING,
        expected_version=executing.state_version,
        target_state=RecoveryState.RECONCILIATION,
    )

    unrelated = contract_factory(
        contract_id="contract-002",
        operation_id="operation-002",
        target_identity={"name": "different-target.invalid"},
    )
    with pytest.raises(RateLimitExceededError, match="lockout"):
        store.create(unrelated)
