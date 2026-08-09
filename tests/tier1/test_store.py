from __future__ import annotations

import json
import os
import shutil
import sqlite3
import threading
from datetime import datetime, timezone

import pytest

from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.errors import (
    ConfirmationError,
    ContractConflictError,
    ContractIntegrityError,
    ContractNotFoundError,
    ContractValidationError,
    IllegalTransitionError,
)
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

_KEY = b"synthetic-test-integrity-key-32bytes!"


class _AcceptingVerifier:
    def verify(self, evidence):
        return evidence.proof == b"synthetic-valid-proof"


_VERIFIER = _AcceptingVerifier()


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


def _store(tmp_path, *, fault_hook=None, clock=None, confirmation_verifier=_VERIFIER):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    options = {"fault_hook": fault_hook, "confirmation_verifier": confirmation_verifier}
    if clock is not None:
        options["clock"] = clock
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3", integrity_key=_KEY, store_id="synthetic-store", **options
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


def test_create_load_and_restart_preserve_authoritative_contract(tmp_path, contract_factory):
    store = _store(tmp_path)
    contract = contract_factory()
    store.create(contract)

    restarted = _store(tmp_path)
    loaded = restarted.load(contract.contract_id)

    assert loaded == contract
    assert (tmp_path / "contracts.sqlite3").stat().st_mode & 0o777 == 0o600


def test_mac_framing_is_unambiguous_across_component_boundaries(tmp_path):
    store = _store(tmp_path)

    assert store._mac(b"a", b"bc") != store._mac(b"ab", b"c")
    assert store._mac(b"audit-event", b"{}") != store._mac(b"audit-even", b"t{}")


def test_whole_store_rollback_remains_an_explicit_external_anchor_blocker(tmp_path, contract_factory):
    store = _store(tmp_path)
    contract = contract_factory()
    store.create(contract)
    old_copy = tmp_path / "authenticated-old-copy.sqlite3"
    shutil.copy2(tmp_path / "contracts.sqlite3", old_copy)

    store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    os.replace(old_copy, tmp_path / "contracts.sqlite3")

    rolled_back = _store(tmp_path).load(contract.contract_id)
    assert rolled_back.state == RecoveryState.PREPARING
    assert rolled_back.state_version == 0


def test_create_requires_unconfirmed_preparing_state(tmp_path, contract_factory):
    store = _store(tmp_path)
    with pytest.raises(ContractValidationError, match="PREPARING"):
        store.create(contract_factory(state=RecoveryState.PREPARED))

    prepared = contract_factory(state=RecoveryState.PREPARED)
    forged = prepared.with_confirmation(
        authority_id="forged-owner", evidence_digest="f" * 64, confirmed_at=prepared.created_at
    )
    with pytest.raises(ContractValidationError, match="unconfirmed"):
        store.create(forged)


def test_store_rejects_symlink_and_unsafe_existing_file(tmp_path, monkeypatch):
    os.chmod(tmp_path, 0o700)
    target = tmp_path / "target.sqlite3"
    target.touch(mode=0o600)
    link = tmp_path / "link.sqlite3"
    link.symlink_to(target)

    with pytest.raises(ContractValidationError, match="non-symlink"):
        SqliteRecoveryContractStore(link, integrity_key=_KEY, store_id="synthetic-store")

    os.chmod(target, 0o640)
    with pytest.raises(ContractValidationError, match="owner-only"):
        SqliteRecoveryContractStore(target, integrity_key=_KEY, store_id="synthetic-store")

    monkeypatch.delattr(os, "O_NOFOLLOW")
    os.chmod(target, 0o600)
    with pytest.raises(ContractValidationError, match="Linux O_NOFOLLOW"):
        SqliteRecoveryContractStore(target, integrity_key=_KEY, store_id="synthetic-store")


def test_store_rejects_unsafe_parent_and_missing_contract(tmp_path):
    os.chmod(tmp_path, 0o755)
    with pytest.raises(ContractValidationError, match="mode 0700"):
        SqliteRecoveryContractStore(
            tmp_path / "contracts.sqlite3",
            integrity_key=_KEY,
            store_id="synthetic-store",
        )

    os.chmod(tmp_path, 0o700)
    store = _store(tmp_path)
    with pytest.raises(ContractNotFoundError, match="not found"):
        store.load("missing-contract")


@pytest.mark.parametrize("store_id", ["", "unsafe\nstore", "store/path", "x" * 129])
def test_store_identifier_is_bounded_and_safe(tmp_path, store_id):
    os.chmod(tmp_path, 0o700)
    with pytest.raises(ContractValidationError, match="identifier"):
        SqliteRecoveryContractStore(tmp_path / "store.sqlite3", integrity_key=_KEY, store_id=store_id)


def test_store_rejects_truncated_or_incompatible_database(tmp_path):
    os.chmod(tmp_path, 0o700)
    truncated = tmp_path / "truncated.sqlite3"
    truncated.write_bytes(b"not-a-sqlite-database")
    os.chmod(truncated, 0o600)
    with pytest.raises(ContractIntegrityError, match="opened safely"):
        SqliteRecoveryContractStore(truncated, integrity_key=_KEY, store_id="synthetic-store")

    malformed = tmp_path / "malformed.sqlite3"
    with sqlite3.connect(malformed) as connection:
        connection.execute("CREATE TABLE contracts(contract_id TEXT PRIMARY KEY)")
    os.chmod(malformed, 0o600)
    with pytest.raises(ContractIntegrityError, match="schema"):
        SqliteRecoveryContractStore(malformed, integrity_key=_KEY, store_id="synthetic-store")


def test_store_rejects_schema_without_required_constraints(tmp_path):
    os.chmod(tmp_path, 0o700)
    malformed = tmp_path / "unconstrained.sqlite3"
    with sqlite3.connect(malformed) as connection:
        connection.executescript(
            """
            CREATE TABLE metadata (key TEXT, value TEXT NOT NULL);
            CREATE TABLE contracts (
                contract_id TEXT, operation_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
                target_identity_digest TEXT NOT NULL, state TEXT NOT NULL,
                state_version INTEGER NOT NULL, payload BLOB NOT NULL, mac TEXT NOT NULL
            );
            CREATE TABLE target_reservations (target_identity_digest TEXT, contract_id TEXT NOT NULL);
            CREATE TABLE audit_events (
                sequence INTEGER, contract_id TEXT NOT NULL, event_type TEXT NOT NULL,
                previous_state TEXT, current_state TEXT NOT NULL, state_version INTEGER NOT NULL,
                recorded_at TEXT NOT NULL, mac TEXT NOT NULL
            );
            """
        )
    os.chmod(malformed, 0o600)

    with pytest.raises(ContractIntegrityError, match="schema"):
        SqliteRecoveryContractStore(malformed, integrity_key=_KEY, store_id="synthetic-store")


def test_wrong_integrity_key_or_store_identity_cannot_replay_database(tmp_path, contract_factory):
    store = _store(tmp_path)
    contract = contract_factory()
    store.create(contract)

    wrong_key = SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=b"different-synthetic-integrity-key!",
        store_id="synthetic-store",
    )
    with pytest.raises(ContractIntegrityError, match="integrity"):
        wrong_key.load(contract.contract_id)

    with pytest.raises(ContractIntegrityError, match="metadata"):
        SqliteRecoveryContractStore(
            tmp_path / "contracts.sqlite3",
            integrity_key=_KEY,
            store_id="different-store",
        )


def test_duplicate_contract_operation_or_idempotency_is_refused(tmp_path, contract_factory):
    store = _store(tmp_path)
    first = contract_factory()
    store.create(first)

    for duplicate in (
        contract_factory(contract_id="contract-002", operation_id=first.operation_id),
        contract_factory(contract_id="contract-003", operation_id="operation-003"),
    ):
        with pytest.raises(ContractConflictError):
            store.create(duplicate)


def test_stale_version_and_duplicate_execution_are_refused(tmp_path, contract_factory):
    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())
    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )

    with pytest.raises(ContractConflictError):
        store.transition(
            confirmed.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=confirmed.state_version,
            target_state=RecoveryState.EXECUTING,
        )
    assert store.load(executing.contract_id).state == RecoveryState.EXECUTING


def test_same_target_cannot_be_acquired_concurrently(tmp_path, contract_factory):
    store = _store(tmp_path)
    first = _confirmed(store, contract_factory())
    second_contract = contract_factory(
        contract_id="contract-002", operation_id="operation-002", intent={"enabled": False}
    )
    second = _confirmed(store, second_contract)
    store.transition(
        first.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=first.state_version,
        target_state=RecoveryState.EXECUTING,
    )

    with pytest.raises(ContractConflictError, match="reserved"):
        store.transition(
            second.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=second.state_version,
            target_state=RecoveryState.EXECUTING,
        )


def test_atomic_target_reservation_allows_only_one_thread(tmp_path, contract_factory):
    store = _store(tmp_path)
    first = _confirmed(store, contract_factory())
    second_contract = contract_factory(
        contract_id="contract-002", operation_id="operation-002", intent={"enabled": False}
    )
    second = _confirmed(store, second_contract)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def acquire(contract):
        barrier.wait()
        try:
            store.transition(
                contract.contract_id,
                expected_state=RecoveryState.PREPARED,
                expected_version=contract.state_version,
                target_state=RecoveryState.EXECUTING,
            )
        except ContractConflictError:
            outcomes.append("refused")
        else:
            outcomes.append("acquired")

    threads = [threading.Thread(target=acquire, args=(contract,)) for contract in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["acquired", "refused"]


def test_different_targets_can_be_acquired_without_false_conflict(tmp_path, contract_factory):
    store = _store(tmp_path)
    first = _confirmed(store, contract_factory())
    second = _confirmed(
        store,
        contract_factory(
            contract_id="contract-002",
            operation_id="operation-002",
            target_identity={"name": "other-target.invalid"},
        ),
    )
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def acquire(contract):
        barrier.wait()
        store.transition(
            contract.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=contract.state_version,
            target_state=RecoveryState.EXECUTING,
        )
        outcomes.append(contract.contract_id)

    threads = [threading.Thread(target=acquire, args=(contract,)) for contract in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["contract-001", "contract-002"]


def test_concurrent_duplicate_idempotency_allows_one_contract(tmp_path, contract_factory):
    store = _store(tmp_path)
    contracts = (
        contract_factory(contract_id="contract-001", operation_id="operation-001"),
        contract_factory(contract_id="contract-002", operation_id="operation-002"),
    )
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def create(contract):
        barrier.wait()
        try:
            store.create(contract)
        except ContractConflictError:
            outcomes.append("refused")
        else:
            outcomes.append("created")

    threads = [threading.Thread(target=create, args=(contract,)) for contract in contracts]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["created", "refused"]


def test_expired_or_unconfirmed_contract_cannot_execute(tmp_path, contract_factory):
    store = _store(tmp_path)
    unconfirmed = contract_factory()
    store.create(unconfirmed)
    unconfirmed = store.transition(
        unconfirmed.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    with pytest.raises(ContractConflictError):
        store.transition(
            unconfirmed.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=unconfirmed.state_version,
            target_state=RecoveryState.EXECUTING,
        )

    current = [datetime.now(timezone.utc)]
    expiring_store = _store(tmp_path / "expiring", clock=lambda: current[0])
    expired = contract_factory(contract_id="contract-002", operation_id="operation-002", now=current[0])
    confirmed = _confirmed(expiring_store, expired)
    current[0] = confirmed.expires_at
    with pytest.raises(ContractConflictError):
        expiring_store.transition(
            confirmed.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=confirmed.state_version,
            target_state=RecoveryState.EXECUTING,
        )


def test_expired_preparation_can_only_be_marked_expired(tmp_path, contract_factory):
    current = [datetime.now(timezone.utc)]
    store = _store(tmp_path, clock=lambda: current[0])
    contract = contract_factory(now=current[0])
    store.create(contract)
    current[0] = contract.expires_at

    with pytest.raises(ContractConflictError, match="only transition"):
        store.transition(
            contract.contract_id,
            expected_state=RecoveryState.PREPARING,
            expected_version=0,
            target_state=RecoveryState.PREPARED,
        )
    expired = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.EXPIRED,
    )
    assert expired.state == RecoveryState.EXPIRED


def test_confirmation_uses_store_clock_and_refuses_expired_contract(tmp_path, contract_factory):
    current = [datetime.now(timezone.utc)]
    store = _store(tmp_path, clock=lambda: current[0])
    contract = contract_factory(now=current[0])
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    current[0] = contract.expires_at
    with pytest.raises(ContractConflictError, match="expired before confirmation"):
        store.confirm(contract.contract_id, evidence=_evidence(prepared), expected_version=prepared.state_version)


def test_confirmation_fails_closed_without_owner_verifier(tmp_path, contract_factory):
    store = _store(tmp_path, confirmation_verifier=None)
    contract = contract_factory()
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    with pytest.raises(ConfirmationError, match="No owner confirmation verifier"):
        store.confirm(
            contract.contract_id,
            evidence=_evidence(prepared),
            expected_version=prepared.state_version,
        )


@pytest.mark.parametrize("behavior", ["refuse", "raise"])
def test_confirmation_verifier_failure_is_sanitized(tmp_path, contract_factory, behavior):
    class RejectingVerifier:
        def verify(self, evidence):
            if behavior == "raise":
                raise RuntimeError("synthetic proof details")
            return False

    store = _store(tmp_path, confirmation_verifier=RejectingVerifier())
    contract = contract_factory()
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    with pytest.raises(ConfirmationError) as captured:
        store.confirm(
            contract.contract_id,
            evidence=_evidence(prepared),
            expected_version=prepared.state_version,
        )
    assert "synthetic proof details" not in str(captured.value)


def test_confirmation_verifier_does_not_catch_base_exception(tmp_path, contract_factory):
    class InterruptingVerifier:
        def verify(self, evidence):
            raise KeyboardInterrupt

    store = _store(tmp_path, confirmation_verifier=InterruptingVerifier())
    contract = contract_factory()
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    with pytest.raises(KeyboardInterrupt):
        store.confirm(
            contract.contract_id,
            evidence=_evidence(prepared),
            expected_version=prepared.state_version,
        )


def test_corrupt_contract_fails_integrity_check(tmp_path, contract_factory):
    store = _store(tmp_path)
    contract = contract_factory()
    store.create(contract)
    path = tmp_path / "contracts.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE contracts SET payload = ? WHERE contract_id = ?", (b"{}", contract.contract_id))

    with pytest.raises(ContractIntegrityError, match="integrity"):
        store.load(contract.contract_id)


@pytest.mark.parametrize("tamper", ["delete", "change"])
def test_audit_history_tampering_fails_closed(tmp_path, contract_factory, tamper):
    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())
    path = tmp_path / "contracts.sqlite3"
    with sqlite3.connect(path) as connection:
        if tamper == "delete":
            connection.execute(
                "DELETE FROM audit_events WHERE contract_id = ? AND state_version = 1",
                (confirmed.contract_id,),
            )
        else:
            connection.execute(
                "UPDATE audit_events SET current_state = ? WHERE contract_id = ? AND state_version = 1",
                (RecoveryState.FAILED.value, confirmed.contract_id),
            )

    with pytest.raises(ContractIntegrityError, match="audit"):
        store.load(confirmed.contract_id)


def test_missing_store_metadata_is_not_silently_recreated(tmp_path, contract_factory):
    store = _store(tmp_path)
    store.create(contract_factory())
    with sqlite3.connect(tmp_path / "contracts.sqlite3") as connection:
        connection.execute("DELETE FROM metadata")

    with pytest.raises(ContractIntegrityError, match="metadata is missing"):
        _store(tmp_path)


@pytest.mark.parametrize("extra", [True, False])
def test_unknown_or_duplicate_stored_fields_fail_closed(tmp_path, contract_factory, extra):
    store = _store(tmp_path)
    contract = contract_factory()
    store.create(contract)
    path = tmp_path / "contracts.sqlite3"
    with sqlite3.connect(path) as connection:
        payload = connection.execute(
            "SELECT payload FROM contracts WHERE contract_id = ?", (contract.contract_id,)
        ).fetchone()[0]
        if extra:
            value = json.loads(payload)
            value["unknown"] = "field"
            malformed = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        else:
            malformed = payload[:-1] + b',"state":"preparing"}'
        connection.execute(
            "UPDATE contracts SET payload = ?, mac = ? WHERE contract_id = ?",
            (malformed, store._mac(malformed), contract.contract_id),
        )

    with pytest.raises(ContractIntegrityError, match="field"):
        store.load(contract.contract_id)


def test_tampered_index_cannot_hide_interrupted_contract(tmp_path, contract_factory):
    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())
    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    with sqlite3.connect(tmp_path / "contracts.sqlite3") as connection:
        connection.execute(
            "UPDATE contracts SET state = ? WHERE contract_id = ?",
            (RecoveryState.PREPARED.value, executing.contract_id),
        )

    with pytest.raises(ContractIntegrityError, match="index"):
        store.interrupted()


def test_crash_before_commit_rolls_back_and_after_commit_is_recoverable(tmp_path, contract_factory):
    def before(point):
        if point == "before_commit":
            raise RuntimeError("synthetic crash")

    before_store = _store(tmp_path / "before", fault_hook=before)
    with pytest.raises(RuntimeError, match="synthetic crash"):
        before_store.create(contract_factory())
    with pytest.raises(ContractNotFoundError):
        before_store.load("contract-001")

    def after(point):
        if point == "after_commit":
            raise RuntimeError("synthetic crash")

    after_path = tmp_path / "after"
    after_path.mkdir(mode=0o700)
    after_store = _store(after_path, fault_hook=after)
    with pytest.raises(RuntimeError, match="synthetic crash"):
        after_store.create(contract_factory())
    assert _store(after_path).load("contract-001").state == RecoveryState.PREPARING


@pytest.mark.parametrize("fault_point", ["before_transaction", "after_record_write", "before_commit"])
def test_create_faults_before_commit_leave_no_partial_record(tmp_path, contract_factory, fault_point):
    def fail(point):
        if point == fault_point:
            raise RuntimeError("synthetic fault")

    store = _store(tmp_path, fault_hook=fail)
    with pytest.raises(RuntimeError, match="synthetic fault"):
        store.create(contract_factory())
    with pytest.raises(ContractNotFoundError):
        _store(tmp_path).load("contract-001")


def test_transition_fault_rolls_back_record_audit_and_reservation(tmp_path, contract_factory):
    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())

    def fail(point):
        if point == "after_record_write":
            raise RuntimeError("synthetic fault")

    failing = _store(tmp_path, fault_hook=fail)
    with pytest.raises(RuntimeError, match="synthetic fault"):
        failing.transition(
            confirmed.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=confirmed.state_version,
            target_state=RecoveryState.EXECUTING,
        )

    loaded = store.load(confirmed.contract_id)
    assert loaded.state == RecoveryState.PREPARED
    assert len(store.audit_events(confirmed.contract_id)) == confirmed.state_version + 1


def test_restart_moves_interrupted_execution_to_reconciliation(tmp_path, contract_factory):
    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())
    store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )

    restarted = _store(tmp_path)
    reconciled = restarted.reconcile_interrupted()

    assert [item.state for item in reconciled] == [RecoveryState.RECONCILIATION]
    assert restarted.load(confirmed.contract_id).state == RecoveryState.RECONCILIATION

    competing = _confirmed(
        restarted,
        contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False}),
    )
    with pytest.raises(ContractConflictError, match="reserved"):
        restarted.transition(
            competing.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=competing.state_version,
            target_state=RecoveryState.EXECUTING,
        )


def test_missing_or_stale_target_reservation_fails_integrity(tmp_path, contract_factory):
    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())
    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    with sqlite3.connect(tmp_path / "contracts.sqlite3") as connection:
        connection.execute("DELETE FROM target_reservations WHERE contract_id = ?", (executing.contract_id,))
    with pytest.raises(ContractIntegrityError, match="reservation"):
        store.load(executing.contract_id)


def test_interrupted_rollback_keeps_target_locked(tmp_path, contract_factory):
    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())
    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    verified = store.transition(
        executing.contract_id,
        expected_state=RecoveryState.EXECUTING,
        expected_version=executing.state_version,
        target_state=RecoveryState.VERIFIED,
    )
    rolling_back = store.transition(
        verified.contract_id,
        expected_state=RecoveryState.VERIFIED,
        expected_version=verified.state_version,
        target_state=RecoveryState.ROLLING_BACK,
    )
    reconciled = _store(tmp_path).reconcile_interrupted()[0]
    assert reconciled.state == RecoveryState.RECONCILIATION

    competing = _confirmed(
        store,
        contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False}),
    )
    with pytest.raises(ContractConflictError, match="reserved"):
        store.transition(
            competing.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=competing.state_version,
            target_state=RecoveryState.EXECUTING,
        )
    assert rolling_back.target_identity_digest == reconciled.target_identity_digest


def test_verified_releases_target_and_later_rollback_refuses_on_conflict(tmp_path, contract_factory):
    """VERIFIED is not a reservation state (see TIER1_ARCHITECTURE.md's
    Rollback section): the target becomes claimable immediately after
    verification, before any rollback decision is made. This is the
    accepted, documented behavior — this test proves both halves of it:
    (1) the released target really is claimable by unrelated work, and
    (2) a later rollback attempt against the original contract correctly
    refuses via conflict rather than silently succeeding or corrupting
    state, once that target has been reclaimed."""

    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())
    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    verified = store.transition(
        executing.contract_id,
        expected_state=RecoveryState.EXECUTING,
        expected_version=executing.state_version,
        target_state=RecoveryState.VERIFIED,
    )

    competing = _confirmed(
        store,
        contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False}),
    )
    competing_executing = store.transition(
        competing.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=competing.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    assert competing_executing.target_identity_digest == verified.target_identity_digest

    with pytest.raises(ContractConflictError, match="reserved"):
        store.transition(
            verified.contract_id,
            expected_state=RecoveryState.VERIFIED,
            expected_version=verified.state_version,
            target_state=RecoveryState.ROLLING_BACK,
        )


def test_failed_rollback_keeps_target_locked(tmp_path, contract_factory):
    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())
    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    verified = store.transition(
        executing.contract_id,
        expected_state=RecoveryState.EXECUTING,
        expected_version=executing.state_version,
        target_state=RecoveryState.VERIFIED,
    )
    rolling_back = store.transition(
        verified.contract_id,
        expected_state=RecoveryState.VERIFIED,
        expected_version=verified.state_version,
        target_state=RecoveryState.ROLLING_BACK,
    )
    failed = store.transition(
        rolling_back.contract_id,
        expected_state=RecoveryState.ROLLING_BACK,
        expected_version=rolling_back.state_version,
        target_state=RecoveryState.ROLLBACK_FAILED,
    )
    assert store.load(failed.contract_id).state == RecoveryState.ROLLBACK_FAILED

    competing = _confirmed(
        store,
        contract_factory(contract_id="contract-002", operation_id="operation-002", intent={"enabled": False}),
    )
    with pytest.raises(ContractConflictError, match="reserved"):
        store.transition(
            competing.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=competing.state_version,
            target_state=RecoveryState.EXECUTING,
        )


def test_generic_store_transition_cannot_claim_manual_reconciliation(tmp_path, contract_factory):
    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())
    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    reconciled = store.transition(
        executing.contract_id,
        expected_state=RecoveryState.EXECUTING,
        expected_version=executing.state_version,
        target_state=RecoveryState.RECONCILIATION,
    )

    with pytest.raises(IllegalTransitionError, match="not authorized"):
        store.transition(
            reconciled.contract_id,
            expected_state=RecoveryState.RECONCILIATION,
            expected_version=reconciled.state_version,
            target_state=RecoveryState.FAILED,
        )
    assert store.load(reconciled.contract_id).state == RecoveryState.RECONCILIATION


def test_atomic_audit_contains_only_state_metadata(tmp_path, contract_factory):
    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())
    events = store.audit_events(confirmed.contract_id)

    assert [event["event_type"] for event in events] == [
        "contract_created",
        "state_transition",
        "contract_confirmed",
    ]
    serialized = repr(events)
    assert "opaque" not in serialized
    assert "synthetic-target" not in serialized
