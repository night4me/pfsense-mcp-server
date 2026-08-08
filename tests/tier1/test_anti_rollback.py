from __future__ import annotations

import os
import shutil
import sqlite3

import pytest

from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.errors import (
    AnchorConflictError,
    AnchorUnavailableError,
    ContractIntegrityError,
    WholeStoreRollbackDetected,
)
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

_KEY = b"synthetic-test-integrity-key-32bytes!"


class _AcceptingVerifier:
    def verify(self, evidence: ConfirmationEvidence) -> bool:
        return evidence.proof == b"synthetic-valid-proof"


class _FakeAnchor:
    """In-memory anti-rollback anchor test double -- never a real TPM or
    network call, per project convention for offline tests."""

    def __init__(self, value: int = 0, *, unavailable: bool = False) -> None:
        self.value = value
        self.unavailable = unavailable
        self.advance_calls: list[int] = []

    def read(self) -> int:
        if self.unavailable:
            raise AnchorUnavailableError("Anchor is unreachable.")
        return self.value

    def advance(self, *, expected_current: int) -> int:
        if self.unavailable:
            raise AnchorUnavailableError("Anchor is unreachable.")
        if expected_current != self.value:
            raise AnchorConflictError("Anchor was advanced concurrently.")
        self.value += 1
        self.advance_calls.append(self.value)
        return self.value


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


def _store(tmp_path, *, anchor=None):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=_KEY,
        store_id="synthetic-store",
        confirmation_verifier=_AcceptingVerifier(),
        anti_rollback_anchor=anchor,
    )


def _confirmed(store, contract):
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    return store.confirm(
        contract.contract_id,
        evidence=_evidence(prepared),
        expected_version=prepared.state_version,
    )


def test_no_anchor_configured_preserves_existing_behavior(tmp_path, contract_factory):
    store = _store(tmp_path, anchor=None)
    confirmed = _confirmed(store, contract_factory())

    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    assert executing.state == RecoveryState.EXECUTING


def test_anchor_ahead_proceeds_normally(tmp_path, contract_factory):
    anchor = _FakeAnchor(value=0)
    store = _store(tmp_path, anchor=anchor)
    confirmed = _confirmed(store, contract_factory())

    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    assert executing.state == RecoveryState.EXECUTING
    assert anchor.advance_calls == [1]


def test_anchor_unavailable_refuses_executing(tmp_path, contract_factory):
    anchor = _FakeAnchor(unavailable=True)
    store = _store(tmp_path, anchor=anchor)
    confirmed = _confirmed(store, contract_factory())

    with pytest.raises(AnchorUnavailableError):
        store.transition(
            confirmed.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=confirmed.state_version,
            target_state=RecoveryState.EXECUTING,
        )
    assert store.load(confirmed.contract_id).state == RecoveryState.PREPARED


def test_anchor_conflict_refuses_executing(tmp_path, contract_factory):
    class _RacingAnchor(_FakeAnchor):
        def advance(self, *, expected_current: int) -> int:
            raise AnchorConflictError("Anchor was advanced by a concurrent process.")

    anchor = _RacingAnchor(value=0)
    store = _store(tmp_path, anchor=anchor)
    confirmed = _confirmed(store, contract_factory())

    with pytest.raises(AnchorConflictError):
        store.transition(
            confirmed.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=confirmed.state_version,
            target_state=RecoveryState.EXECUTING,
        )
    assert store.load(confirmed.contract_id).state == RecoveryState.PREPARED


def test_whole_store_rollback_is_detected_when_anchor_configured(tmp_path, contract_factory):
    """Companion to test_store.py's
    test_whole_store_rollback_remains_an_explicit_external_anchor_blocker,
    which proves the store alone cannot detect a whole-file restore. This
    test proves that adding a configured, independently-durable anchor
    closes exactly that gap."""

    anchor = _FakeAnchor(value=0)
    store = _store(tmp_path, anchor=anchor)
    confirmed = _confirmed(store, contract_factory())

    old_copy = tmp_path / "authenticated-old-copy.sqlite3"
    shutil.copy2(tmp_path / "contracts.sqlite3", old_copy)

    # Advance past this point: EXECUTING acquisition durably advances both
    # the anchor (independently) and the store's own persisted mark.
    store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    os.replace(old_copy, tmp_path / "contracts.sqlite3")

    restarted = _store(tmp_path, anchor=anchor)
    rolled_back = restarted.load(confirmed.contract_id)
    assert rolled_back.state == RecoveryState.PREPARED  # store file itself is silently rolled back

    second = contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False})
    second_confirmed = _confirmed(restarted, second)
    with pytest.raises(WholeStoreRollbackDetected):
        restarted.transition(
            second_confirmed.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=second_confirmed.state_version,
            target_state=RecoveryState.EXECUTING,
        )


def test_anchor_reset_backward_is_also_detected(tmp_path, contract_factory):
    """The symmetric case to the whole-store-rollback test: the anchor
    itself is tampered/reset to an earlier value while the store file is
    untouched. This is also a real anomaly (a compromised or
    misconfigured anchor backend) and must also refuse, not just the
    file-restored direction."""

    anchor = _FakeAnchor(value=0)
    store = _store(tmp_path, anchor=anchor)
    first = _confirmed(store, contract_factory())
    store.transition(
        first.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=first.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    assert anchor.value == 1

    anchor.value = 0  # simulate a reset/rollback of the anchor itself
    second = _confirmed(
        store, contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False})
    )
    with pytest.raises(WholeStoreRollbackDetected):
        store.transition(
            second.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=second.state_version,
            target_state=RecoveryState.EXECUTING,
        )


def test_high_water_mark_defaults_to_zero_for_a_fresh_store(tmp_path):
    store = _store(tmp_path)
    with sqlite3.connect(tmp_path / "contracts.sqlite3") as connection:
        assert store._high_water_mark.read(connection) == 0


def test_anchor_with_preexisting_nonzero_history_refuses_first_use(tmp_path, contract_factory):
    """An anchor that already has unrelated history (nonzero at the time
    this store is first used) is indistinguishable, from the store's own
    file, from a store that was rolled back to a point before its
    first-ever EXECUTING attempt (both show "no row" locally). This class
    deliberately does not try to guess which case it is -- the anchor
    must be dedicated to this store and start at 0, or be explicitly
    provisioned to the correct baseline by whoever sets up the concrete
    backend. This test documents that refusal, not a defect."""

    anchor = _FakeAnchor(value=7)
    store = _store(tmp_path, anchor=anchor)
    confirmed = _confirmed(store, contract_factory())

    with pytest.raises(WholeStoreRollbackDetected):
        store.transition(
            confirmed.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=confirmed.state_version,
            target_state=RecoveryState.EXECUTING,
        )


def test_high_water_mark_rejects_tampered_value(tmp_path, contract_factory):
    anchor = _FakeAnchor(value=0)
    store = _store(tmp_path, anchor=anchor)
    confirmed = _confirmed(store, contract_factory())
    store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )

    with sqlite3.connect(tmp_path / "contracts.sqlite3") as connection:
        connection.execute("UPDATE anchor_state SET value = '0' WHERE key = 'high_water_mark'")
        connection.commit()

    with sqlite3.connect(tmp_path / "contracts.sqlite3") as connection:
        with pytest.raises(ContractIntegrityError, match="integrity verification"):
            store._high_water_mark.read(connection)
