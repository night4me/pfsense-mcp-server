from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lab.reconciliation_authority import (
    LabReconciliationError,
    LabReconciliationPaths,
    emit_pending_evidence,
    load_signed_evidence,
    load_verifier,
    resolve_signed_evidence,
)
from lab.reconciliation_owner import sign_existing_pending
from lab.reconciliation_resume import main as resume_main
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.errors import ConfirmationError, ContractConflictError, ContractIntegrityError
from pfsense_mcp.tier1.reconciliation import ReconciliationOutcome
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

_INTEGRITY_KEY = b"stage3-integration-integrity-key!"
_A = "a" * 64
_B = "b" * 64


class _ConfirmationVerifier:
    def verify(self, evidence: ConfirmationEvidence) -> bool:
        return evidence.proof == b"valid-confirmation"


def _secure(path, value):
    path.write_bytes(value)
    os.chmod(path, 0o600)


def _authority(tmp_path):
    tmp_path.chmod(0o700)
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    paths = LabReconciliationPaths(tmp_path / "public.key", tmp_path / "pending.json", tmp_path / "signed.json")
    private_path = tmp_path / "private.key"
    _secure(paths.public_key_file, raw_public)
    _secure(private_path, raw_private)
    return paths, private_path


def _store(tmp_path, paths):
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=_INTEGRITY_KEY,
        store_id="lab-reconciliation-integration",
        confirmation_verifier=_ConfirmationVerifier(),
        reconciliation_verifier=load_verifier(paths),
    )


def _confirmation(contract):
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
        proof=b"valid-confirmation",
    )


def _uncertain(store, contract, *, rollback=False):
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    confirmed = store.confirm(
        contract.contract_id,
        evidence=_confirmation(prepared),
        expected_version=prepared.state_version,
    )
    executing = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    current = executing
    if rollback:
        current = store.mark_execution_verified(
            contract.contract_id,
            expected_version=executing.state_version,
            verified_target_fingerprint=_B,
            verified_lifecycle_locator=contract.lifecycle_locator,
        )
        current = store.transition(
            contract.contract_id,
            expected_state=RecoveryState.VERIFIED,
            expected_version=current.state_version,
            target_state=RecoveryState.ROLLING_BACK,
        )
    return store.transition(
        contract.contract_id,
        expected_state=current.state,
        expected_version=current.state_version,
        target_state=RecoveryState.RECONCILIATION,
    )


def _emit_sign_resolve(store, paths, private_path, contract, outcome, *, rollback=False):
    emit_pending_evidence(
        paths,
        store,
        contract_id=contract.contract_id,
        issued_at=datetime.now(timezone.utc),
        verified_target_fingerprint=None if rollback else _B,
        verified_lifecycle_locator=contract.lifecycle_locator,
        integrity_key=_INTEGRITY_KEY,
    )
    sign_existing_pending(
        paths=paths,
        private_key_file=private_path,
        outcome=outcome,
        contract_loader=store.load,
        audit_loader=store.audit_events,
        integrity_key=_INTEGRITY_KEY,
    )
    return resolve_signed_evidence(paths, store)


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (ReconciliationOutcome.CONFIRMED_APPLIED, RecoveryState.VERIFIED),
        (ReconciliationOutcome.CONFIRMED_NOT_APPLIED, RecoveryState.FAILED),
    ],
)
def test_forward_ambiguous_owner_sign_verify_and_resolve_end_to_end(tmp_path, contract_factory, outcome, expected):
    paths, private_path = _authority(tmp_path)
    store = _store(tmp_path, paths)
    uncertain = _uncertain(store, contract_factory(target_precondition={"fingerprint": "a"}))

    resolved = _emit_sign_resolve(store, paths, private_path, uncertain, outcome)

    assert resolved.state is expected
    assert resolved.verified_target_fingerprint == (_B if outcome is ReconciliationOutcome.CONFIRMED_APPLIED else None)
    assert store.load(uncertain.contract_id).state is expected


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (ReconciliationOutcome.CONFIRMED_ROLLBACK_APPLIED, RecoveryState.ROLLED_BACK),
        (ReconciliationOutcome.CONFIRMED_ROLLBACK_NOT_APPLIED, RecoveryState.ROLLBACK_FAILED),
    ],
)
def test_rollback_ambiguous_owner_sign_verify_and_resolve_end_to_end(tmp_path, contract_factory, outcome, expected):
    paths, private_path = _authority(tmp_path)
    store = _store(tmp_path, paths)
    uncertain = _uncertain(store, contract_factory(target_precondition={"fingerprint": "a"}), rollback=True)

    resolved = _emit_sign_resolve(store, paths, private_path, uncertain, outcome, rollback=True)

    assert resolved.state is expected
    assert resolved.target_fingerprint == uncertain.target_fingerprint
    assert resolved.verified_target_fingerprint == _B


def test_restart_pending_reconstructs_store_and_never_persists_transport_projection(tmp_path, contract_factory):
    paths, private_path = _authority(tmp_path)
    store = _store(tmp_path, paths)
    uncertain = _uncertain(store, contract_factory(target_precondition={"fingerprint": "a"}))
    emit_pending_evidence(
        paths,
        store,
        contract_id=uncertain.contract_id,
        issued_at=datetime.now(timezone.utc),
        verified_target_fingerprint=_B,
        verified_lifecycle_locator=uncertain.lifecycle_locator,
        integrity_key=_INTEGRITY_KEY,
    )

    restarted = _store(tmp_path, paths)
    sign_existing_pending(
        paths=paths,
        private_key_file=private_path,
        outcome=ReconciliationOutcome.CONFIRMED_APPLIED,
        contract_loader=restarted.load,
        audit_loader=restarted.audit_events,
        integrity_key=_INTEGRITY_KEY,
    )
    resolved = resolve_signed_evidence(paths, restarted)

    assert resolved.state is RecoveryState.VERIFIED
    store_bytes = (tmp_path / "contracts.sqlite3").read_bytes()
    assert b"ResolvedTransportTarget" not in store_bytes


def test_stale_signed_evidence_and_cross_operation_replay_fail_closed(tmp_path, contract_factory):
    paths, private_path = _authority(tmp_path)
    store = _store(tmp_path, paths)
    first = _uncertain(store, contract_factory(target_precondition={"fingerprint": "a"}))
    emit_pending_evidence(
        paths,
        store,
        contract_id=first.contract_id,
        issued_at=datetime.now(timezone.utc),
        verified_target_fingerprint=_B,
        verified_lifecycle_locator=first.lifecycle_locator,
        integrity_key=_INTEGRITY_KEY,
    )
    sign_existing_pending(
        paths=paths,
        private_key_file=private_path,
        outcome=ReconciliationOutcome.CONFIRMED_APPLIED,
        contract_loader=store.load,
        audit_loader=store.audit_events,
        integrity_key=_INTEGRITY_KEY,
    )
    evidence = load_signed_evidence(paths)
    store.resolve_reconciliation(first.contract_id, evidence=evidence)
    with pytest.raises((ContractConflictError, LabReconciliationError)):
        resolve_signed_evidence(paths, store)

    second = _uncertain(
        store,
        contract_factory(
            contract_id="contract-002",
            operation_id="operation-002",
            intent={"descr": "other"},
            target_precondition={"fingerprint": "c"},
        ),
    )
    with pytest.raises(ConfirmationError, match="does not match"):
        store.resolve_reconciliation(second.contract_id, evidence=evidence)
    assert store.load(second.contract_id).state is RecoveryState.RECONCILIATION


def test_pending_tamper_and_store_hmac_tamper_fail_before_resolution(tmp_path, contract_factory):
    paths, private_path = _authority(tmp_path)
    store = _store(tmp_path, paths)
    uncertain = _uncertain(store, contract_factory(target_precondition={"fingerprint": "a"}))
    emit_pending_evidence(
        paths,
        store,
        contract_id=uncertain.contract_id,
        issued_at=datetime.now(timezone.utc),
        verified_target_fingerprint=_B,
        verified_lifecycle_locator=uncertain.lifecycle_locator,
        integrity_key=_INTEGRITY_KEY,
    )
    raw = json.loads(paths.pending_file.read_bytes())
    raw["verified_target_fingerprint"] = "c" * 64
    paths.pending_file.write_text(json.dumps(raw))
    with pytest.raises(LabReconciliationError, match="integrity"):
        sign_existing_pending(
            paths=paths,
            private_key_file=private_path,
            outcome=ReconciliationOutcome.CONFIRMED_APPLIED,
            contract_loader=store.load,
            audit_loader=store.audit_events,
            integrity_key=_INTEGRITY_KEY,
        )

    database = tmp_path / "contracts.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE contracts SET payload = ? WHERE contract_id = ?", (b"tampered", uncertain.contract_id)
        )
    with pytest.raises(ContractIntegrityError):
        _store(tmp_path, paths).load(uncertain.contract_id)


def test_forward_and_rollback_outcomes_cannot_cross_uncertainty_boundary(tmp_path, contract_factory):
    paths, private_path = _authority(tmp_path)
    store = _store(tmp_path, paths)
    forward = _uncertain(store, contract_factory(target_precondition={"fingerprint": "a"}))
    emit_pending_evidence(
        paths,
        store,
        contract_id=forward.contract_id,
        issued_at=datetime.now(timezone.utc),
        verified_target_fingerprint=_B,
        verified_lifecycle_locator=forward.lifecycle_locator,
        integrity_key=_INTEGRITY_KEY,
    )
    with pytest.raises(LabReconciliationError, match="incompatible"):
        sign_existing_pending(
            paths=paths,
            private_key_file=private_path,
            outcome=ReconciliationOutcome.CONFIRMED_ROLLBACK_APPLIED,
            contract_loader=store.load,
            audit_loader=store.audit_events,
            integrity_key=_INTEGRITY_KEY,
        )
    assert not paths.signed_file.exists()


@pytest.mark.parametrize("argument", ["--operation-id", "--outcome", "--authority", "--file", "--payload"])
def test_resume_command_has_no_caller_selected_reconciliation_inputs(argument):
    with pytest.raises(SystemExit):
        resume_main([argument, "forbidden"])


def test_verifier_failure_never_changes_state_or_causes_send(tmp_path, contract_factory):
    paths, private_path = _authority(tmp_path)
    store = _store(tmp_path, paths)
    uncertain = _uncertain(store, contract_factory())
    emit_pending_evidence(
        paths,
        store,
        contract_id=uncertain.contract_id,
        issued_at=datetime.now(timezone.utc),
        verified_target_fingerprint=_B,
        verified_lifecycle_locator=uncertain.lifecycle_locator,
        integrity_key=_INTEGRITY_KEY,
    )
    sign_existing_pending(
        paths=paths,
        private_key_file=private_path,
        outcome=ReconciliationOutcome.CONFIRMED_APPLIED,
        contract_loader=store.load,
        audit_loader=store.audit_events,
        integrity_key=_INTEGRITY_KEY,
    )
    raw = json.loads(paths.signed_file.read_bytes())
    raw["proof"] = "AA=="
    paths.signed_file.write_text(json.dumps(raw))

    with pytest.raises(ConfirmationError, match="refused"):
        resolve_signed_evidence(paths, store)
    assert store.load(uncertain.contract_id).state is RecoveryState.RECONCILIATION
