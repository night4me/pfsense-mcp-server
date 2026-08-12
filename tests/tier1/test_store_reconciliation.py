from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.errors import ConfirmationError, ContractConflictError
from pfsense_mcp.tier1.reconciliation import ReconciliationEvidence, ReconciliationOutcome
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

_KEY = b"synthetic-test-integrity-key-32bytes!"
_VALID_RECONCILIATION_PROOF = b"synthetic-valid-reconciliation-proof"


class _AcceptingConfirmationVerifier:
    def verify(self, evidence: ConfirmationEvidence) -> bool:
        return evidence.proof == b"synthetic-valid-proof"


class _AcceptingReconciliationVerifier:
    def verify(self, evidence: ReconciliationEvidence) -> bool:
        return evidence.proof == _VALID_RECONCILIATION_PROOF


# Stateless -- a single shared instance is safe and avoids constructing a
# fresh (identical) object in the function signature's default expression,
# which ruff's B008 correctly flags as evaluated once at import time
# regardless of intent.
_DEFAULT_RECONCILIATION_VERIFIER = _AcceptingReconciliationVerifier()


def _store(tmp_path, *, reconciliation_verifier=_DEFAULT_RECONCILIATION_VERIFIER):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=_KEY,
        store_id="synthetic-store",
        confirmation_verifier=_AcceptingConfirmationVerifier(),
        reconciliation_verifier=reconciliation_verifier,
    )


def _confirmation_evidence(contract):
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


def _to_reconciliation(store, contract):
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    confirmed = store.confirm(
        contract.contract_id, evidence=_confirmation_evidence(prepared), expected_version=prepared.state_version
    )
    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    return store.transition(
        executing.contract_id,
        expected_state=RecoveryState.EXECUTING,
        expected_version=executing.state_version,
        target_state=RecoveryState.RECONCILIATION,
    )


def _reconciliation_evidence(contract, *, outcome, proof=_VALID_RECONCILIATION_PROOF, state_version=None):
    return ReconciliationEvidence(
        authority_id="synthetic-operator",
        algorithm="test-reconciliation-verifier",
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        observed_state_version=contract.state_version if state_version is None else state_version,
        outcome=outcome,
        issued_at=datetime.now(timezone.utc),
        proof=proof,
        verified_target_fingerprint=(
            contract.target_fingerprint if outcome is ReconciliationOutcome.CONFIRMED_APPLIED else None
        ),
    )


@pytest.mark.parametrize(
    ("outcome", "expected_state"),
    [
        (ReconciliationOutcome.CONFIRMED_APPLIED, RecoveryState.VERIFIED),
        (ReconciliationOutcome.CONFIRMED_NOT_APPLIED, RecoveryState.FAILED),
        (ReconciliationOutcome.CONFIRMED_ROLLBACK_APPLIED, RecoveryState.ROLLED_BACK),
        (ReconciliationOutcome.CONFIRMED_ROLLBACK_NOT_APPLIED, RecoveryState.ROLLBACK_FAILED),
    ],
)
def test_each_outcome_resolves_to_its_declared_target_state(tmp_path, contract_factory, outcome, expected_state):
    store = _store(tmp_path)
    contract = _to_reconciliation(store, contract_factory())

    resolved = store.resolve_reconciliation(
        contract.contract_id, evidence=_reconciliation_evidence(contract, outcome=outcome)
    )
    assert resolved.state == expected_state
    assert store.load(contract.contract_id).state == expected_state
    if outcome is ReconciliationOutcome.CONFIRMED_APPLIED:
        assert resolved.verified_target_fingerprint == contract.target_fingerprint


def test_stale_observed_state_version_is_refused(tmp_path, contract_factory):
    store = _store(tmp_path)
    contract = _to_reconciliation(store, contract_factory())

    stale = _reconciliation_evidence(
        contract, outcome=ReconciliationOutcome.CONFIRMED_APPLIED, state_version=contract.state_version - 1
    )
    with pytest.raises(ConfirmationError, match="does not match"):
        store.resolve_reconciliation(contract.contract_id, evidence=stale)
    assert store.load(contract.contract_id).state == RecoveryState.RECONCILIATION


def test_evidence_for_a_different_contract_is_refused(tmp_path, contract_factory):
    store = _store(tmp_path)
    first = _to_reconciliation(store, contract_factory())
    other = contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False})
    store.create(other)

    mismatched = _reconciliation_evidence(other, outcome=ReconciliationOutcome.CONFIRMED_APPLIED)
    with pytest.raises(ConfirmationError, match="does not match"):
        store.resolve_reconciliation(first.contract_id, evidence=mismatched)


def test_no_verifier_configured_fails_closed(tmp_path, contract_factory):
    store = _store(tmp_path, reconciliation_verifier=None)
    contract = _to_reconciliation(store, contract_factory())

    with pytest.raises(ConfirmationError, match="No reconciliation verifier"):
        store.resolve_reconciliation(
            contract.contract_id,
            evidence=_reconciliation_evidence(contract, outcome=ReconciliationOutcome.CONFIRMED_APPLIED),
        )


def test_refused_signature_is_refused(tmp_path, contract_factory):
    store = _store(tmp_path)
    contract = _to_reconciliation(store, contract_factory())

    forged = _reconciliation_evidence(contract, outcome=ReconciliationOutcome.CONFIRMED_APPLIED, proof=b"forged")
    with pytest.raises(ConfirmationError, match="refused"):
        store.resolve_reconciliation(contract.contract_id, evidence=forged)
    assert store.load(contract.contract_id).state == RecoveryState.RECONCILIATION


def test_contract_not_in_reconciliation_is_refused(tmp_path, contract_factory):
    store = _store(tmp_path)
    contract = contract_factory()
    store.create(contract)

    with pytest.raises(ContractConflictError, match="not in RECONCILIATION"):
        store.resolve_reconciliation(
            contract.contract_id,
            evidence=_reconciliation_evidence(contract, outcome=ReconciliationOutcome.CONFIRMED_APPLIED),
        )


def test_resolution_produces_a_chained_audit_event(tmp_path, contract_factory):
    store = _store(tmp_path)
    contract = _to_reconciliation(store, contract_factory())

    store.resolve_reconciliation(
        contract.contract_id,
        evidence=_reconciliation_evidence(contract, outcome=ReconciliationOutcome.CONFIRMED_APPLIED),
    )
    events = store.audit_events(contract.contract_id)
    assert events[-1]["event_type"] == "reconciliation_resolved"
    assert events[-1]["current_state"] == RecoveryState.VERIFIED.value


def test_rollback_failed_outcome_keeps_target_reserved(tmp_path, contract_factory):
    store = _store(tmp_path)
    contract = _to_reconciliation(store, contract_factory())

    resolved = store.resolve_reconciliation(
        contract.contract_id,
        evidence=_reconciliation_evidence(contract, outcome=ReconciliationOutcome.CONFIRMED_ROLLBACK_NOT_APPLIED),
    )
    assert resolved.state == RecoveryState.ROLLBACK_FAILED

    competing = contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False})
    store.create(competing)
    prepared = store.transition(
        competing.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    confirmed = store.confirm(
        competing.contract_id, evidence=_confirmation_evidence(prepared), expected_version=prepared.state_version
    )
    with pytest.raises(ContractConflictError, match="reserved"):
        store.transition(
            confirmed.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=confirmed.state_version,
            target_state=RecoveryState.EXECUTING,
        )
