from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from pfsense_mcp.security_operation_journal import (
    AdministrativeOperationType,
    AdministrativeTransactionState,
    AuthoritativeRestartObservation,
    AuthoritativeServerState,
    DurableOperationState,
    ExclusiveOperationLock,
    JournalSnapshot,
    LocalArtifactObservation,
    LockObservation,
    LockState,
    OperationBinding,
    OperationJournal,
    OperationJournalError,
    OperationLockError,
    RecoveryAction,
    RestartClassification,
    classify_restart,
)

KEY = b"j" * 32
T0 = "2026-08-19T20:00:00Z"
T1 = "2026-08-19T20:00:01Z"
T2 = "2026-08-19T20:00:02Z"


@pytest.fixture
def secure_dir(tmp_path: Path) -> Path:
    path = tmp_path / "state"
    path.mkdir(mode=0o700)
    return path


def binding(operation_id: str = "op-1") -> OperationBinding:
    return OperationBinding(
        operation_id=operation_id,
        operation_type=AdministrativeOperationType.BOOTSTRAP,
        target_identity="lab-one",
        target_origin="https://lab.invalid",
        account_identity="pfsense-mcp",
        approved_profile="write_protected",
        schema_version="v2.10",
        schema_evidence_digest="a" * 64,
        starting_auth_methods=("KeyAuth",),
    )


def authoritative(
    *,
    state: AuthoritativeServerState = AuthoritativeServerState.CLEAN,
    final: bool = False,
    recovery: RecoveryAction | None = None,
) -> AuthoritativeRestartObservation:
    item = binding()
    return AuthoritativeRestartObservation(
        target_identity=item.target_identity,
        target_origin=item.target_origin,
        account_identity=item.account_identity,
        approved_profile=item.approved_profile,
        schema_version=item.schema_version,
        schema_evidence_digest=item.schema_evidence_digest,
        auth_methods=item.starting_auth_methods,
        server_state=state,
        final_verification_complete=final,
        applicable_recovery=recovery,
    )


def decision(snapshot: JournalSnapshot | None, observation: AuthoritativeRestartObservation | None):
    return classify_restart(
        journal=snapshot,
        journal_trusted=True,
        lock=LockObservation(LockState.RELEASED, snapshot.latest.binding.operation_id if snapshot else None),
        artifacts=LocalArtifactObservation(trusted=True),
        authoritative=observation,
    )


def test_create_append_load_and_complete(secure_dir: Path):
    journal = OperationJournal(secure_dir / "operation.jsonl", KEY)
    snapshot = journal.create(binding(), timestamp=T0)
    snapshot = journal.append(
        operation_id="op-1",
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp=T1,
    )
    snapshot = journal.append(
        operation_id="op-1",
        state=DurableOperationState.COMPLETED,
        transaction_state=AdministrativeTransactionState.VERIFIED,
        mutation_index=1,
        timestamp=T2,
    )
    assert journal.load() == snapshot
    assert oct((secure_dir / "operation.jsonl").stat().st_mode & 0o777) == "0o600"
    assert (
        decision(snapshot, authoritative(state=AuthoritativeServerState.EXPECTED_COMPLETED, final=True)).classification
        is RestartClassification.CLEAN_COMPLETED
    )


def test_clean_no_operation():
    result = classify_restart(
        journal=None,
        journal_trusted=True,
        lock=LockObservation(LockState.ABSENT),
        artifacts=LocalArtifactObservation(trusted=True),
        authoritative=None,
    )
    assert result.classification is RestartClassification.CLEAN_NO_OPERATION


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (DurableOperationState.PRE_SEND_READY, RestartClassification.PRE_SEND_RESUMABLE),
        (DurableOperationState.MUTATION_INTENT_RECORDED, RestartClassification.MUTATION_SENT_RESULT_UNKNOWN),
        (DurableOperationState.MUTATION_RESULT_UNKNOWN, RestartClassification.MUTATION_SENT_RESULT_UNKNOWN),
        (DurableOperationState.SERVER_STATE_PARTIAL, RestartClassification.PARTIAL_SERVER_STATE),
        (DurableOperationState.RECOVERY_REQUIRED, RestartClassification.RECOVERY_REQUIRED),
        (DurableOperationState.FINAL_VERIFICATION_PENDING, RestartClassification.COMPLETED_NEEDS_FINAL_VERIFICATION),
    ],
)
def test_restart_classifications(secure_dir: Path, state: DurableOperationState, expected: RestartClassification):
    journal = OperationJournal(secure_dir / "operation.jsonl", KEY)
    snapshot = journal.create(binding(), timestamp=T0)
    snapshot = journal.append(
        operation_id="op-1",
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp=T1,
    )
    if state is not DurableOperationState.PRE_SEND_READY:
        snapshot = journal.append(
            operation_id="op-1",
            state=DurableOperationState.MUTATION_INTENT_RECORDED,
            transaction_state=AdministrativeTransactionState.RECOVERY_MUTATION_SENT,
            mutation_index=1,
            timestamp=T2,
        )
    if state is DurableOperationState.MUTATION_RESULT_UNKNOWN:
        snapshot = journal.append(
            operation_id="op-1",
            state=state,
            transaction_state=AdministrativeTransactionState.RECOVERY_MUTATION_SENT,
            mutation_index=1,
            timestamp="2026-08-19T20:00:03Z",
        )
    elif state is DurableOperationState.SERVER_STATE_PARTIAL:
        snapshot = journal.append(
            operation_id="op-1",
            state=state,
            transaction_state=AdministrativeTransactionState.USER_CREATED,
            mutation_index=1,
            timestamp="2026-08-19T20:00:03Z",
        )
    elif state is DurableOperationState.RECOVERY_REQUIRED:
        snapshot = journal.append(
            operation_id="op-1",
            state=state,
            transaction_state=AdministrativeTransactionState.RECOVERY_OBJECT_IDENTIFIED,
            mutation_index=1,
            timestamp="2026-08-19T20:00:03Z",
            recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        )
    elif state is DurableOperationState.FINAL_VERIFICATION_PENDING:
        snapshot = journal.append(
            operation_id="op-1",
            state=state,
            transaction_state=AdministrativeTransactionState.BOOTSTRAP_PRIVILEGE_REVOKED,
            mutation_index=1,
            timestamp="2026-08-19T20:00:03Z",
        )
    observation = authoritative(
        state=AuthoritativeServerState.EXPECTED_PARTIAL
        if state is DurableOperationState.SERVER_STATE_PARTIAL
        else AuthoritativeServerState.CLEAN,
        recovery=RecoveryAction.REVOKE_ORPHAN_KEY if state is DurableOperationState.SERVER_STATE_PARTIAL else None,
    )
    assert decision(snapshot, observation).classification is expected


def test_target_schema_and_auth_drift_require_recovery(secure_dir: Path):
    journal = OperationJournal(secure_dir / "operation.jsonl", KEY)
    snapshot = journal.create(binding(), timestamp=T0)
    base = authoritative()
    for changed in (
        {**base.__dict__, "target_identity": "other"},
        {**base.__dict__, "schema_version": "v3"},
        {**base.__dict__, "auth_methods": ("KeyAuth", "BasicAuth")},
    ):
        assert (
            decision(snapshot, AuthoritativeRestartObservation(**changed)).classification
            is RestartClassification.RECOVERY_REQUIRED
        )


def test_missing_lock_with_unfinished_journal_still_blocks_new_bootstrap(secure_dir: Path):
    journal = OperationJournal(secure_dir / "operation.jsonl", KEY)
    snapshot = journal.create(binding(), timestamp=T0)
    result = classify_restart(
        journal=snapshot,
        journal_trusted=True,
        lock=LockObservation(LockState.ABSENT),
        artifacts=LocalArtifactObservation(trusted=True),
        authoritative=authoritative(),
    )
    assert result.classification is RestartClassification.PRE_SEND_RESUMABLE
    assert result.classification is not RestartClassification.CLEAN_NO_OPERATION


def test_lock_acquire_release_concurrency_and_stale_detection(secure_dir: Path):
    path = secure_dir / "operation.lock"
    first = ExclusiveOperationLock(path, KEY)
    first.acquire("op-1", timestamp=T0)
    assert ExclusiveOperationLock(path, KEY).inspect() == LockObservation(LockState.ACTIVE_HELD, "op-1")
    with pytest.raises(OperationLockError):
        ExclusiveOperationLock(path, KEY).acquire("op-2", timestamp=T1)
    first.release(timestamp=T1)
    assert ExclusiveOperationLock(path, KEY).inspect() == LockObservation(LockState.RELEASED, "op-1")
    second = ExclusiveOperationLock(path, KEY)
    second.acquire("op-2", timestamp=T2)
    os.close(second._descriptor)  # simulate process death without writing released metadata
    second._descriptor = None
    assert ExclusiveOperationLock(path, KEY).inspect() == LockObservation(LockState.ACTIVE_STALE, "op-2")
    with pytest.raises(OperationLockError, match="restart classification"):
        ExclusiveOperationLock(path, KEY).acquire("op-3", timestamp=T2)


def test_unsafe_existing_lock_mode_is_refused_not_repaired(secure_dir: Path):
    path = secure_dir / "operation.lock"
    path.write_text("unsafe")
    path.chmod(0o644)
    with pytest.raises(OperationLockError):
        ExclusiveOperationLock(path, KEY).acquire("op-1", timestamp=T0)
    assert oct(path.stat().st_mode & 0o777) == "0o644"
    assert ExclusiveOperationLock(path, KEY).inspect().state is LockState.CORRUPT


@pytest.mark.parametrize("target", ["journal", "head"])
def test_symlink_refused(secure_dir: Path, target: str):
    path = secure_dir / "operation.jsonl"
    if target == "journal":
        path.symlink_to(secure_dir / "elsewhere")
    else:
        (path.with_name("operation.jsonl.head")).symlink_to(secure_dir / "elsewhere")
    with pytest.raises(OperationJournalError):
        OperationJournal(path, KEY).create(binding(), timestamp=T0)


def test_unsafe_parent_and_file_permissions_refused(tmp_path: Path, secure_dir: Path):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(OperationJournalError, match="owner-controlled"):
        OperationJournal(unsafe / "journal", KEY).create(binding(), timestamp=T0)
    journal = OperationJournal(secure_dir / "journal", KEY)
    journal.create(binding(), timestamp=T0)
    (secure_dir / "journal").chmod(0o644)
    with pytest.raises(OperationJournalError):
        journal.load()


@pytest.mark.parametrize("mutation", ["truncate", "corrupt", "wrong_mac", "replay", "duplicate"])
def test_malformed_tampered_replayed_journal_fails_closed(secure_dir: Path, mutation: str):
    path = secure_dir / "journal"
    journal = OperationJournal(path, KEY)
    journal.create(binding(), timestamp=T0)
    journal.append(
        operation_id="op-1",
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp=T1,
    )
    lines = path.read_bytes().splitlines(keepends=True)
    if mutation == "truncate":
        path.write_bytes(b"".join(lines)[:-4])
    elif mutation == "corrupt":
        path.write_bytes(b"[" + b"".join(lines)[1:])
    elif mutation == "wrong_mac":
        value = json.loads(lines[-1])
        value["transaction_state"] = "changed"
        lines[-1] = json.dumps(value).encode() + b"\n"
        path.write_bytes(b"".join(lines))
    elif mutation == "replay":
        path.write_bytes(lines[0])
    else:
        path.write_bytes(b"".join([*lines, lines[-1]]))
    with pytest.raises(OperationJournalError):
        journal.load()


def test_wrong_key_and_corrupt_head_fail_closed(secure_dir: Path):
    path = secure_dir / "journal"
    journal = OperationJournal(path, KEY)
    journal.create(binding(), timestamp=T0)
    with pytest.raises(OperationJournalError, match="authentication"):
        OperationJournal(path, b"x" * 32).load()
    path.with_name("journal.head").write_text("{}\n")
    with pytest.raises(OperationJournalError, match="head"):
        journal.load()


def test_wrong_json_field_types_fail_closed(secure_dir: Path):
    path = secure_dir / "journal"
    journal = OperationJournal(path, KEY)
    journal.create(binding(), timestamp=T0)
    value = json.loads(path.read_text())
    value["sequence"] = "0"
    path.write_text(json.dumps(value) + "\n")
    with pytest.raises(OperationJournalError, match="field types"):
        journal.load()


def test_duplicate_id_wrong_id_and_illegal_transitions_refused(secure_dir: Path):
    path = secure_dir / "journal"
    journal = OperationJournal(path, KEY)
    journal.create(binding(), timestamp=T0)
    with pytest.raises(OperationJournalError):
        journal.create(binding(), timestamp=T0)
    with pytest.raises(OperationJournalError, match="Operation id"):
        journal.append(
            operation_id="op-2",
            state=DurableOperationState.PRE_SEND_READY,
            transaction_state=AdministrativeTransactionState.NOT_STARTED,
            mutation_index=1,
            timestamp=T1,
        )
    with pytest.raises(OperationJournalError, match="Illegal"):
        journal.append(
            operation_id="op-1",
            state=DurableOperationState.COMPLETED,
            transaction_state=AdministrativeTransactionState.VERIFIED,
            mutation_index=0,
            timestamp=T1,
        )


def test_completed_cannot_return_to_running(secure_dir: Path):
    journal = OperationJournal(secure_dir / "journal", KEY)
    journal.create(binding(), timestamp=T0)
    journal.append(
        operation_id="op-1",
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp=T1,
    )
    journal.append(
        operation_id="op-1",
        state=DurableOperationState.COMPLETED,
        transaction_state=AdministrativeTransactionState.VERIFIED,
        mutation_index=1,
        timestamp=T2,
    )
    with pytest.raises(OperationJournalError, match="Illegal"):
        journal.append(
            operation_id="op-1",
            state=DurableOperationState.PRE_SEND_READY,
            transaction_state=AdministrativeTransactionState.NOT_STARTED,
            mutation_index=2,
            timestamp="2026-08-19T20:00:03Z",
        )


def test_secret_like_values_are_never_generated_by_state_model(secure_dir: Path):
    journal = OperationJournal(secure_dir / "journal", KEY)
    journal.create(binding(), timestamp=T0)
    text = (secure_dir / "journal").read_text() + (secure_dir / "journal.head").read_text()
    assert "password" not in text.lower()
    assert "api_key" not in text.lower()
    assert "authorization" not in text.lower()


def test_untrusted_state_and_mismatched_lock_fail_closed(secure_dir: Path):
    journal = OperationJournal(secure_dir / "journal", KEY)
    snapshot = journal.create(binding(), timestamp=T0)
    for kwargs in (
        {"journal_trusted": False, "lock": LockObservation(LockState.RELEASED, "op-1")},
        {"journal_trusted": True, "lock": LockObservation(LockState.CORRUPT)},
        {"journal_trusted": True, "lock": LockObservation(LockState.RELEASED, "other")},
    ):
        result = classify_restart(
            journal=snapshot,
            artifacts=LocalArtifactObservation(trusted=True),
            authoritative=authoritative(),
            **kwargs,
        )
        assert result.classification is RestartClassification.CORRUPT_OR_UNTRUSTED_LOCAL_STATE


def test_active_operation_lock_never_classifies_as_resumable(secure_dir: Path):
    journal = OperationJournal(secure_dir / "journal", KEY)
    snapshot = journal.create(binding(), timestamp=T0)
    result = classify_restart(
        journal=snapshot,
        journal_trusted=True,
        lock=LockObservation(LockState.ACTIVE_HELD, "op-1"),
        artifacts=LocalArtifactObservation(trusted=True),
        authoritative=authoritative(),
    )
    assert result.classification is RestartClassification.RECOVERY_REQUIRED


@pytest.mark.parametrize(
    "changed",
    [
        {"account_identity": "other"},
        {"approved_profile": "read_only"},
        {"starting_auth_methods": ("BasicAuth",)},
        {"target_origin": "http://lab.invalid"},
    ],
)
def test_binding_scope_is_closed(secure_dir: Path, changed: dict[str, object]):
    values = {**binding().__dict__, **changed}
    with pytest.raises(OperationJournalError):
        OperationJournal(secure_dir / "journal", KEY).create(OperationBinding(**values), timestamp=T0)


def test_binding_scope_accepts_the_readonly_pair_together(secure_dir: Path):
    """POST-v1.0 MANAGED READ-ONLY DEFENSE IN DEPTH mission (2026-08-29):
    the closed set this module enforces (`_VALID_ACCOUNT_PROFILE_
    PAIRS`) now has two members -- confirms the *new* pair, changed
    together (never account_identity alone, as the parametrized
    rejection test above already proves for a mismatched half-pair),
    is accepted. The original write_protected pair's own acceptance
    behavior is unchanged, covered by every other test in this file
    that calls `binding()` unmodified."""

    values = {**binding().__dict__, "account_identity": "pfsense-mcp-readonly", "approved_profile": "read_only"}
    snapshot = OperationJournal(secure_dir / "journal", KEY).create(OperationBinding(**values), timestamp=T0)
    assert snapshot.latest.binding.account_identity == "pfsense-mcp-readonly"
    assert snapshot.latest.binding.approved_profile == "read_only"


def test_binding_scope_rejects_the_readonly_account_with_the_wrong_profile(secure_dir: Path):
    """The mirror image of the parametrized `approved_profile="read_only"`
    case above: pairing the *new* account identity with the wrong
    profile must still be rejected -- the set is closed over exact
    pairs, never either field independently."""

    values = {**binding().__dict__, "account_identity": "pfsense-mcp-readonly"}
    with pytest.raises(OperationJournalError):
        OperationJournal(secure_dir / "journal", KEY).create(OperationBinding(**values), timestamp=T0)
