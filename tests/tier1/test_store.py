from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from pfsense_mcp.tier1.errors import (
    ContractConflictError,
    ContractIntegrityError,
    ContractNotFoundError,
    ContractValidationError,
    IllegalTransitionError,
)
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

_KEY = b"synthetic-test-integrity-key-32bytes!"


def _store(tmp_path, *, fault_hook=None):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=_KEY,
        store_id="synthetic-store",
        fault_hook=fault_hook,
    )


def _confirmed(store, contract):
    store.create(contract)
    return store.confirm(
        contract.contract_id,
        actor_id="owner-approval",
        confirmed_at=datetime.now(timezone.utc),
        expected_version=0,
    )


def test_create_load_and_restart_preserve_authoritative_contract(tmp_path, contract_factory):
    store = _store(tmp_path)
    contract = contract_factory()
    store.create(contract)

    restarted = _store(tmp_path)
    loaded = restarted.load(contract.contract_id)

    assert loaded == contract
    assert (tmp_path / "contracts.sqlite3").stat().st_mode & 0o777 == 0o600


def test_store_rejects_symlink_and_unsafe_existing_file(tmp_path):
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
    second_contract = contract_factory(contract_id="contract-002", operation_id="operation-002")
    second_contract = replace(second_contract, idempotency_key="f" * 64)
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
    second_contract = replace(
        contract_factory(contract_id="contract-002", operation_id="operation-002"),
        idempotency_key="f" * 64,
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


def test_expired_or_unconfirmed_contract_cannot_execute(tmp_path, contract_factory):
    store = _store(tmp_path)
    unconfirmed = contract_factory()
    store.create(unconfirmed)
    with pytest.raises(ContractConflictError):
        store.transition(
            unconfirmed.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=0,
            target_state=RecoveryState.EXECUTING,
        )

    expired = contract_factory(contract_id="contract-002", operation_id="operation-002")
    expired = replace(expired, idempotency_key="e" * 64)
    confirmed = _confirmed(store, expired)
    with pytest.raises(ContractConflictError):
        store.transition(
            confirmed.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=confirmed.state_version,
            target_state=RecoveryState.EXECUTING,
            now=confirmed.expires_at,
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
    with pytest.raises(Exception):
        before_store.load("contract-001")

    def after(point):
        if point == "after_commit":
            raise RuntimeError("synthetic crash")

    after_path = tmp_path / "after"
    after_path.mkdir(mode=0o700)
    after_store = _store(after_path, fault_hook=after)
    with pytest.raises(RuntimeError, match="synthetic crash"):
        after_store.create(contract_factory())
    assert _store(after_path).load("contract-001").state == RecoveryState.PREPARED


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


def test_reconciliation_exit_requires_explicit_manual_action(tmp_path, contract_factory):
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
    resolved = store.transition(
        reconciled.contract_id,
        expected_state=RecoveryState.RECONCILIATION,
        expected_version=reconciled.state_version,
        target_state=RecoveryState.FAILED,
        manual=True,
    )
    assert resolved.state == RecoveryState.FAILED


def test_atomic_audit_contains_only_state_metadata(tmp_path, contract_factory):
    store = _store(tmp_path)
    confirmed = _confirmed(store, contract_factory())
    events = store.audit_events(confirmed.contract_id)

    assert [event["event_type"] for event in events] == ["contract_created", "contract_confirmed"]
    serialized = repr(events)
    assert "opaque" not in serialized
    assert "synthetic-target" not in serialized
