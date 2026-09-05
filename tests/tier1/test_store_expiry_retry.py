"""2026-09-05 owner-directed retry/idempotency redesign -- Slice 1
(schema + store primitives only). Every store here is a fresh `tmp_path`
fixture; nothing in this file ever opens a real alias/Batch1 production
store. See docs/tier1/specs/ and the forthcoming ADR for the full design
rationale this test suite proves.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.errors import ContractConflictError
from pfsense_mcp.tier1.state_machine import BLOCKING_IDEMPOTENCY_STATES, RecoveryState, blocks_fresh_idempotency_attempt
from pfsense_mcp.tier1.store import _ACTIVE_IDEMPOTENCY_INDEX_NAME, SqliteRecoveryContractStore

_KEY = b"synthetic-test-integrity-key-32bytes!"
_NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)


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


def _drive_to_terminal(store, contract, target_state):
    """`store.create()` only accepts a contract at PREPARING/version 0
    (see store.py's own precondition) -- there is no way to insert a
    contract directly into a terminal/blocking state. Every fixture that
    needs one must instead create it as PREPARING and walk it through the
    real, legal state-machine transitions, exactly like test_store.py's
    own `_confirmed()` helper does."""

    store.create(contract)
    if target_state is RecoveryState.EXPIRED:
        return store.transition(
            contract.contract_id,
            expected_state=RecoveryState.PREPARING,
            expected_version=0,
            target_state=RecoveryState.EXPIRED,
        )
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    confirmed = store.confirm(
        contract.contract_id, evidence=_evidence(prepared), expected_version=prepared.state_version
    )
    executing = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    if target_state is RecoveryState.FAILED:
        return store.transition(
            contract.contract_id,
            expected_state=RecoveryState.EXECUTING,
            expected_version=executing.state_version,
            target_state=RecoveryState.FAILED,
        )
    if target_state is RecoveryState.ROLLED_BACK:
        verified = store.mark_execution_verified(
            contract.contract_id,
            expected_version=executing.state_version,
            verified_target_fingerprint=executing.target_fingerprint,
            verified_lifecycle_locator=executing.lifecycle_locator,
        )
        rolling_back = store.transition(
            contract.contract_id,
            expected_state=RecoveryState.VERIFIED,
            expected_version=verified.state_version,
            target_state=RecoveryState.ROLLING_BACK,
        )
        return store.mark_rollback_verified(
            contract.contract_id,
            expected_version=rolling_back.state_version,
            verified_lifecycle_locator=rolling_back.lifecycle_locator,
        )
    raise ValueError(f"_drive_to_terminal: unsupported target_state {target_state}")


# ---------------------------------------------------------------------------
# 1. RecoveryState classification
# ---------------------------------------------------------------------------


def test_blocking_idempotency_states_are_exactly_the_documented_set():
    assert {
        RecoveryState.PREPARING,
        RecoveryState.PREPARED,
        RecoveryState.EXECUTING,
        RecoveryState.VERIFIED,
        RecoveryState.RECONCILIATION,
        RecoveryState.ROLLING_BACK,
        RecoveryState.ROLLBACK_FAILED,
    } == BLOCKING_IDEMPOTENCY_STATES


def test_permitted_history_states_are_exactly_the_complement():
    permitted = {state for state in RecoveryState if not blocks_fresh_idempotency_attempt(state)}
    assert permitted == {RecoveryState.FAILED, RecoveryState.ROLLED_BACK, RecoveryState.EXPIRED}


@pytest.mark.parametrize("state", sorted(BLOCKING_IDEMPOTENCY_STATES, key=lambda s: s.value))
def test_every_blocking_state_reports_blocking(state):
    assert blocks_fresh_idempotency_attempt(state) is True


@pytest.mark.parametrize("state", [RecoveryState.FAILED, RecoveryState.ROLLED_BACK, RecoveryState.EXPIRED])
def test_every_permitted_state_reports_not_blocking(state):
    assert blocks_fresh_idempotency_attempt(state) is False


# ---------------------------------------------------------------------------
# 2. Active-idempotency partial index enforcement
# ---------------------------------------------------------------------------


def test_two_contracts_in_blocking_states_with_same_idempotency_key_collide(tmp_path, contract_factory):
    store = _store(tmp_path)
    first = contract_factory(contract_id="contract-001", operation_id="operation-001", state=RecoveryState.PREPARING)
    second = contract_factory(contract_id="contract-002", operation_id="operation-002", state=RecoveryState.PREPARING)
    assert first.idempotency_key == second.idempotency_key
    store.create(first)
    with pytest.raises(ContractConflictError, match="already exists"):
        store.create(second)


@pytest.mark.parametrize("terminal_state", [RecoveryState.FAILED, RecoveryState.ROLLED_BACK, RecoveryState.EXPIRED])
def test_blocking_and_permitted_history_coexist_for_the_same_key(tmp_path, contract_factory, terminal_state):
    store = _store(tmp_path)
    historical = contract_factory(contract_id="contract-historical", operation_id="operation-historical")
    fresh = contract_factory(
        contract_id="contract-fresh", operation_id="operation-fresh", state=RecoveryState.PREPARING
    )
    assert historical.idempotency_key == fresh.idempotency_key
    _drive_to_terminal(store, historical, terminal_state)
    store.create(fresh)  # must not raise
    loaded_historical = store.load("contract-historical")
    loaded_fresh = store.load("contract-fresh")
    assert loaded_historical.state is terminal_state
    assert loaded_fresh.state is RecoveryState.PREPARING


def test_multiple_permitted_historical_attempts_all_coexist(tmp_path, contract_factory):
    store = _store(tmp_path)
    for index, state in enumerate([RecoveryState.FAILED, RecoveryState.ROLLED_BACK, RecoveryState.EXPIRED]):
        _drive_to_terminal(
            store, contract_factory(contract_id=f"contract-{index}", operation_id=f"operation-{index}"), state
        )
    history = store.find_historical_by_idempotency_key(store.load("contract-0").idempotency_key)
    assert {c.contract_id for c in history} == {"contract-0", "contract-1", "contract-2"}
    assert {c.state for c in history} == {RecoveryState.FAILED, RecoveryState.ROLLED_BACK, RecoveryState.EXPIRED}


def test_a_second_blocking_attempt_cannot_be_created_while_one_permitted_and_one_blocking_already_exist(
    tmp_path, contract_factory
):
    store = _store(tmp_path)
    _drive_to_terminal(
        store,
        contract_factory(contract_id="contract-old-failed", operation_id="operation-old-failed"),
        RecoveryState.FAILED,
    )
    store.create(
        contract_factory(contract_id="contract-active", operation_id="operation-active", state=RecoveryState.PREPARING)
    )
    with pytest.raises(ContractConflictError):
        store.create(
            contract_factory(
                contract_id="contract-second-active",
                operation_id="operation-second-active",
                state=RecoveryState.PREPARING,
            )
        )


# ---------------------------------------------------------------------------
# 3. find_by_idempotency_key() / find_historical_by_idempotency_key() semantics
# ---------------------------------------------------------------------------


def test_find_by_idempotency_key_returns_none_when_no_contract_exists(tmp_path):
    store = _store(tmp_path)
    assert store.find_by_idempotency_key("nonexistent-key") is None


def test_find_by_idempotency_key_returns_none_when_only_terminal_rows_exist(tmp_path, contract_factory):
    store = _store(tmp_path)
    contract = contract_factory()
    _drive_to_terminal(store, contract, RecoveryState.FAILED)
    assert store.find_by_idempotency_key(contract.idempotency_key) is None


def test_find_by_idempotency_key_returns_the_one_blocking_row_ignoring_terminal_history(tmp_path, contract_factory):
    store = _store(tmp_path)
    _drive_to_terminal(
        store, contract_factory(contract_id="contract-old", operation_id="operation-old"), RecoveryState.FAILED
    )
    active = contract_factory(
        contract_id="contract-active", operation_id="operation-active", state=RecoveryState.PREPARING
    )
    store.create(active)
    found = store.find_by_idempotency_key(active.idempotency_key)
    assert found is not None
    assert found.contract_id == "contract-active"
    assert found.state is RecoveryState.PREPARING


def test_find_historical_by_idempotency_key_returns_empty_tuple_for_unknown_key(tmp_path):
    store = _store(tmp_path)
    assert store.find_historical_by_idempotency_key("nonexistent-key") == ()


def test_find_historical_by_idempotency_key_returns_every_row_regardless_of_state(tmp_path, contract_factory):
    store = _store(tmp_path)
    _drive_to_terminal(
        store, contract_factory(contract_id="contract-a", operation_id="operation-a"), RecoveryState.FAILED
    )
    active = contract_factory(contract_id="contract-b", operation_id="operation-b", state=RecoveryState.PREPARING)
    store.create(active)
    history = store.find_historical_by_idempotency_key(active.idempotency_key)
    assert len(history) == 2
    assert {c.contract_id for c in history} == {"contract-a", "contract-b"}


# ---------------------------------------------------------------------------
# 4. expire_prepared()
# ---------------------------------------------------------------------------


def _prepared_and_expired(store, contract_factory, *, contract_id="contract-001", operation_id="operation-001"):
    created_at = _NOW - timedelta(minutes=10)
    contract = contract_factory(
        contract_id=contract_id, operation_id=operation_id, state=RecoveryState.PREPARING, now=created_at
    )
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    assert prepared.is_expired(now=_NOW) is True
    return prepared


def test_expire_prepared_succeeds_for_a_genuinely_expired_unconfirmed_prepared_contract(tmp_path, contract_factory):
    store = _store(tmp_path, clock=lambda: _NOW - timedelta(minutes=10))
    prepared = _prepared_and_expired(store, contract_factory)
    expired = store.expire_prepared(prepared.contract_id, expected_version=prepared.state_version, now=_NOW)
    assert expired.state is RecoveryState.EXPIRED
    assert expired.state_version == prepared.state_version + 1


def test_expire_prepared_frees_the_idempotency_key_for_a_fresh_blocking_attempt(tmp_path, contract_factory):
    store = _store(tmp_path, clock=lambda: _NOW - timedelta(minutes=10))
    prepared = _prepared_and_expired(store, contract_factory)
    store.expire_prepared(prepared.contract_id, expected_version=prepared.state_version, now=_NOW)
    assert store.find_by_idempotency_key(prepared.idempotency_key) is None
    fresh = contract_factory(
        contract_id="contract-fresh-retry",
        operation_id="operation-fresh-retry",
        state=RecoveryState.PREPARING,
        now=_NOW - timedelta(minutes=10),
    )
    assert fresh.idempotency_key == prepared.idempotency_key
    store.create(fresh)  # must not raise
    found = store.find_by_idempotency_key(fresh.idempotency_key)
    assert found is not None and found.contract_id == "contract-fresh-retry"
    # the original expired contract's own row and history remain, untouched
    original = store.load(prepared.contract_id)
    assert original.state is RecoveryState.EXPIRED


def test_expire_prepared_refuses_a_contract_that_is_not_prepared(tmp_path, contract_factory):
    store = _store(tmp_path, clock=lambda: _NOW - timedelta(minutes=10))
    contract = contract_factory(state=RecoveryState.PREPARING, now=_NOW - timedelta(minutes=10))
    store.create(contract)
    with pytest.raises(ContractConflictError, match="not PREPARED"):
        store.expire_prepared(contract.contract_id, expected_version=0, now=_NOW)


def test_expire_prepared_refuses_a_contract_that_has_not_yet_expired(tmp_path, contract_factory):
    store = _store(tmp_path, clock=lambda: _NOW)
    contract = contract_factory(state=RecoveryState.PREPARING, now=_NOW)
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    assert prepared.is_expired(now=_NOW) is False
    with pytest.raises(ContractConflictError, match="not yet expired"):
        store.expire_prepared(prepared.contract_id, expected_version=prepared.state_version, now=_NOW)


def test_expire_prepared_refuses_a_confirmed_contract(tmp_path, contract_factory):
    """`confirm()` itself refuses an already-expired contract (see its own
    `is_expired(now=confirmed_at)` precondition), so this fixture must
    confirm the contract while still fresh -- `expire_prepared()`'s
    is_confirmed check fires unconditionally before its own expiry check,
    so no clock manipulation is needed to prove the refusal here."""

    store = _store(tmp_path)
    contract = contract_factory()
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    confirmed = store.confirm(
        contract.contract_id, evidence=_evidence(prepared), expected_version=prepared.state_version
    )
    with pytest.raises(ContractConflictError, match="confirmation evidence"):
        store.expire_prepared(confirmed.contract_id, expected_version=confirmed.state_version, now=_NOW)


def test_expire_prepared_refuses_a_stale_expected_version(tmp_path, contract_factory):
    store = _store(tmp_path, clock=lambda: _NOW - timedelta(minutes=10))
    prepared = _prepared_and_expired(store, contract_factory)
    with pytest.raises(ContractConflictError, match="state changed"):
        store.expire_prepared(prepared.contract_id, expected_version=prepared.state_version + 1, now=_NOW)


def test_double_expire_prepared_is_race_safe_second_call_cleanly_fails(tmp_path, contract_factory):
    store = _store(tmp_path, clock=lambda: _NOW - timedelta(minutes=10))
    prepared = _prepared_and_expired(store, contract_factory)
    first = store.expire_prepared(prepared.contract_id, expected_version=prepared.state_version, now=_NOW)
    assert first.state is RecoveryState.EXPIRED
    # A second caller holding the same (now-stale) expected_version must
    # cleanly fail, not double-transition or corrupt state.
    with pytest.raises(ContractConflictError):
        store.expire_prepared(prepared.contract_id, expected_version=prepared.state_version, now=_NOW)


def test_expire_prepared_appends_a_proper_audit_event(tmp_path, contract_factory):
    store = _store(tmp_path, clock=lambda: _NOW - timedelta(minutes=10))
    prepared = _prepared_and_expired(store, contract_factory)
    store.expire_prepared(prepared.contract_id, expected_version=prepared.state_version, now=_NOW)
    events = store.audit_events(prepared.contract_id)
    last = events[-1]
    assert last["previous_state"] == RecoveryState.PREPARED.value
    assert last["current_state"] == RecoveryState.EXPIRED.value
    assert last["state_version"] == prepared.state_version + 1


def test_expire_prepared_makes_zero_anti_rollback_anchor_contact(tmp_path, contract_factory):
    """PREPARED -> EXPIRED never enters EXECUTING, so
    `before_executing_transition()` -- the only place `transition()` ever
    touches the configured anchor -- is structurally unreachable here.
    Proven with a poisoned anchor stub that raises if touched at all."""

    class _PoisonedAnchor:
        def read(self) -> int:
            raise AssertionError("anchor.read() must never be called by expire_prepared()")

        def advance(self, *, expected_current: int) -> int:
            raise AssertionError("anchor.advance() must never be called by expire_prepared()")

    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    store = SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=_KEY,
        store_id="synthetic-store",
        anti_rollback_anchor=_PoisonedAnchor(),
        clock=lambda: _NOW - timedelta(minutes=10),
    )
    prepared = _prepared_and_expired(store, contract_factory)
    expired = store.expire_prepared(prepared.contract_id, expected_version=prepared.state_version, now=_NOW)
    assert expired.state is RecoveryState.EXPIRED  # would have raised above if the anchor were ever touched


def test_expire_prepared_module_imports_no_transport_or_pfsense_client():
    """Zero-transport-interaction, proven structurally: store.py imports
    nothing from pfsense_client/write_api_client/transport at all."""

    import pfsense_mcp.tier1.store as store_module

    with open(store_module.__file__) as handle:
        source = handle.read()
    for forbidden in ("pfsense_client", "write_api_client", "transport_target", "httpx"):
        assert forbidden not in source, f"store.py must never import {forbidden}"


# ---------------------------------------------------------------------------
# 5. derive_idempotency_key() regression -- byte-identical output
# ---------------------------------------------------------------------------


def test_derive_idempotency_key_output_is_unchanged_for_fixed_inputs():
    from pfsense_mcp.capabilities import Capability
    from pfsense_mcp.tier1.contract import derive_idempotency_key

    key = derive_idempotency_key(
        capability=Capability.ALIAS_WRITE,
        endpoint_symbol="SYNTHETIC_ENDPOINT",
        http_method="PATCH",
        target_identity_digest="a" * 64,
        target_fingerprint="b" * 64,
        lifecycle_locator=7,
        intent_digest="c" * 64,
        snapshot_digest="d" * 64,
        rollback_plan_version="synthetic-v1",
    )
    # Regression pin: this exact digest must never change for this exact
    # input tuple -- a change here would mean derive_idempotency_key()'s
    # own canonicalization changed, silently breaking every already-
    # persisted contract's own self-verifying idempotency binding
    # (RecoveryContract.__post_init__ re-derives and compares this on
    # every load) for both the alias-description and Batch-1 capabilities.
    assert key == "4b2e89facc71c05eb878eddeb3433c6665fec53abe93cc3969f47bb5bd8d9fdd"


# ---------------------------------------------------------------------------
# 6. Schema migration (v7 fixture -> v8), fixture-only
# ---------------------------------------------------------------------------


def _build_legacy_v7_store(path):
    """Hand-builds a v7-shaped fixture database (the exact schema
    real SqliteRecoveryContractStore instances persist today, per direct
    inspection of the real Batch1 store this session) -- never opens or
    touches any real alias/Batch1 production store."""

    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE contracts (
                contract_id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL UNIQUE,
                idempotency_key TEXT NOT NULL UNIQUE,
                target_identity_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                state_version INTEGER NOT NULL,
                payload BLOB NOT NULL,
                mac TEXT NOT NULL
            );
            CREATE TABLE target_reservations (
                target_identity_digest TEXT PRIMARY KEY,
                contract_id TEXT NOT NULL UNIQUE REFERENCES contracts(contract_id) ON DELETE CASCADE
            );
            CREATE TABLE audit_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_id TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                previous_state TEXT,
                current_state TEXT NOT NULL,
                state_version INTEGER NOT NULL,
                recorded_at TEXT NOT NULL,
                mac TEXT NOT NULL,
                UNIQUE(contract_id, state_version)
            );
            CREATE TABLE anchor_state (key TEXT PRIMARY KEY, value TEXT NOT NULL, mac TEXT NOT NULL);
            CREATE TABLE rate_cooldowns (target_identity_digest TEXT PRIMARY KEY, cooldown_until TEXT NOT NULL);
            """
        )
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES ('schema_version', '7'), ('store_id', 'synthetic-store')"
        )
        connection.commit()
    finally:
        connection.close()


def test_migration_from_v7_preserves_every_historical_contract_and_audit_event(tmp_path, contract_factory):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / "contracts.sqlite3"
    _build_legacy_v7_store(path)

    # Populate via a THROWAWAY v8-shaped store pointed at a scratch file,
    # to get real, correctly-MAC'd payloads to copy into the legacy fixture
    # -- never construct fixture rows by hand with a fake MAC.
    scratch_dir = tmp_path / "scratch"
    scratch_dir.mkdir(mode=0o700)
    scratch_store = SqliteRecoveryContractStore(
        scratch_dir / "scratch.sqlite3", integrity_key=_KEY, store_id="synthetic-store", confirmation_verifier=_VERIFIER
    )
    contract_a = contract_factory(contract_id="legacy-a", operation_id="legacy-op-a")
    contract_b = contract_factory(
        contract_id="legacy-b",
        operation_id="legacy-op-b",
        state=RecoveryState.PREPARING,
        target_identity={"name": "other-target.invalid"},
    )
    _drive_to_terminal(scratch_store, contract_a, RecoveryState.FAILED)
    scratch_store.create(contract_b)

    legacy_connection = sqlite3.connect(path)
    scratch_connection = sqlite3.connect(scratch_dir / "scratch.sqlite3")
    try:
        for row in scratch_connection.execute("SELECT * FROM contracts"):
            legacy_connection.execute("INSERT INTO contracts VALUES (?, ?, ?, ?, ?, ?, ?, ?)", row)
        for row in scratch_connection.execute("SELECT * FROM audit_events"):
            legacy_connection.execute(
                "INSERT INTO audit_events(sequence, contract_id, event_type, previous_state, current_state, "
                "state_version, recorded_at, mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                row,
            )
        legacy_connection.commit()
    finally:
        legacy_connection.close()
        scratch_connection.close()

    os.chmod(path, 0o600)

    migrated_store = SqliteRecoveryContractStore(path, integrity_key=_KEY, store_id="synthetic-store")

    with sqlite3.connect(path) as verify_connection:
        schema_version = verify_connection.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()[0]
        assert schema_version == "8"
        index_row = verify_connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (_ACTIVE_IDEMPOTENCY_INDEX_NAME,)
        ).fetchone()
        assert index_row is not None
        assert "WHERE state IN" in index_row[0]

    loaded_a = migrated_store.load("legacy-a")
    loaded_b = migrated_store.load("legacy-b")
    assert loaded_a.state is RecoveryState.FAILED
    assert loaded_b.state is RecoveryState.PREPARING
    events_a = migrated_store.audit_events("legacy-a")
    events_b = migrated_store.audit_events("legacy-b")
    assert len(events_a) >= 1
    assert len(events_b) >= 1


def test_migration_from_v7_allows_a_fresh_blocking_attempt_for_a_historically_terminal_key(tmp_path, contract_factory):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / "contracts.sqlite3"
    _build_legacy_v7_store(path)

    scratch_dir = tmp_path / "scratch2"
    scratch_dir.mkdir(mode=0o700)
    scratch_store = SqliteRecoveryContractStore(
        scratch_dir / "scratch.sqlite3", integrity_key=_KEY, store_id="synthetic-store", confirmation_verifier=_VERIFIER
    )
    terminal = contract_factory(contract_id="legacy-terminal", operation_id="legacy-op-terminal")
    _drive_to_terminal(scratch_store, terminal, RecoveryState.FAILED)

    legacy_connection = sqlite3.connect(path)
    scratch_connection = sqlite3.connect(scratch_dir / "scratch.sqlite3")
    try:
        for row in scratch_connection.execute("SELECT * FROM contracts"):
            legacy_connection.execute("INSERT INTO contracts VALUES (?, ?, ?, ?, ?, ?, ?, ?)", row)
        legacy_connection.commit()
    finally:
        legacy_connection.close()
        scratch_connection.close()
    os.chmod(path, 0o600)

    migrated_store = SqliteRecoveryContractStore(path, integrity_key=_KEY, store_id="synthetic-store")
    assert migrated_store.find_by_idempotency_key(terminal.idempotency_key) is None

    fresh = contract_factory(
        contract_id="legacy-fresh-retry", operation_id="legacy-op-fresh-retry", state=RecoveryState.PREPARING
    )
    assert fresh.idempotency_key == terminal.idempotency_key
    migrated_store.create(fresh)  # must not raise -- this is exactly the retry this design enables
    assert migrated_store.find_by_idempotency_key(fresh.idempotency_key).contract_id == "legacy-fresh-retry"


def test_migration_is_idempotent_reopening_an_already_migrated_store_does_not_re_migrate(tmp_path, contract_factory):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / "contracts.sqlite3"
    _build_legacy_v7_store(path)
    os.chmod(path, 0o600)

    first_open = SqliteRecoveryContractStore(path, integrity_key=_KEY, store_id="synthetic-store")
    contract = contract_factory(state=RecoveryState.PREPARING)
    first_open.create(contract)

    second_open = SqliteRecoveryContractStore(path, integrity_key=_KEY, store_id="synthetic-store")
    loaded = second_open.load(contract.contract_id)
    assert loaded.state is RecoveryState.PREPARING
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT value FROM metadata WHERE key = 'schema_version'").fetchone()[0] == "8"
