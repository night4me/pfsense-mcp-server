"""Offline durable state for owner-directed ADR-033 administration.

This module has no transport, endpoint, CLI, or mutation authority.  It stores
only secret-free operation metadata in an HMAC-chained journal, owns a local
advisory lock, and classifies restart evidence supplied by a caller.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import stat
from contextlib import suppress
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from .secure_file import open_nofollow, validate_descriptor

_DOMAIN = b"pfsense-mcp-adr033-operation-journal-v1\x00"
_HEAD_DOMAIN = b"pfsense-mcp-adr033-operation-head-v1\x00"
_LOCK_DOMAIN = b"pfsense-mcp-adr033-operation-lock-v1\x00"
_MAX_JOURNAL_BYTES = 4 * 1024 * 1024
_MAX_METADATA_BYTES = 64 * 1024
_ZERO_MAC = "0" * 64

#: The closed set of (account_identity, approved_profile) pairs this
#: journal will ever create a record for -- a hardcoded allowlist, not
#: caller-configurable, exactly like the single-pair check it replaces.
#: POST-v1.0 MANAGED READ-ONLY DEFENSE IN DEPTH mission (2026-08-29)
#: added the second pair; the original write_protected pair's own
#: behavior is unchanged -- it still must match both fields together,
#: exactly as before.
_VALID_ACCOUNT_PROFILE_PAIRS = frozenset(
    {
        ("pfsense-mcp", "write_protected"),
        ("pfsense-mcp-readonly", "read_only"),
    }
)


class OperationJournalError(Exception):
    """Local operation state is unsafe, malformed, or unauthenticated."""


class OperationLockError(Exception):
    """Exclusive local operation ownership could not be established."""


class AdministrativeOperationType(str, Enum):
    BOOTSTRAP = "bootstrap"
    RECOVER_ORPHAN_KEY = "recover_orphan_key"
    RECOVER_DEDICATED_USER = "recover_dedicated_user"


class DurableOperationState(str, Enum):
    CREATED = "created"
    PRE_SEND_READY = "pre_send_ready"
    MUTATION_INTENT_RECORDED = "mutation_intent_recorded"
    MUTATION_RESULT_UNKNOWN = "mutation_result_unknown"
    SERVER_STATE_PARTIAL = "server_state_partial"
    RECOVERY_REQUIRED = "recovery_required"
    FINAL_VERIFICATION_PENDING = "final_verification_pending"
    COMPLETED = "completed"


class AdministrativeTransactionState(str, Enum):
    NOT_STARTED = "not_started"
    USER_CREATED = "user_created"
    BOOTSTRAP_PRIVILEGE_GRANTED = "bootstrap_privilege_granted"
    KEY_GENERATED = "key_generated"
    BOOTSTRAP_PRIVILEGE_REVOKED = "bootstrap_privilege_revoked"
    VERIFIED = "verified"
    RECOVERY_OBJECT_IDENTIFIED = "recovery_object_identified"
    RECOVERY_MUTATION_SENT = "recovery_mutation_sent"
    RECOVERY_VERIFIED = "recovery_verified"


class RecoveryAction(str, Enum):
    REVOKE_ORPHAN_KEY = "revoke_orphan_key"
    DELETE_DEDICATED_USER = "delete_dedicated_user"


class RestartClassification(str, Enum):
    CLEAN_NO_OPERATION = "clean_no_operation"
    CLEAN_COMPLETED = "clean_completed"
    PRE_SEND_RESUMABLE = "pre_send_resumable"
    MUTATION_SENT_RESULT_UNKNOWN = "mutation_sent_result_unknown"
    PARTIAL_SERVER_STATE = "partial_server_state"
    RECOVERY_REQUIRED = "recovery_required"
    COMPLETED_NEEDS_FINAL_VERIFICATION = "completed_needs_final_verification"
    CORRUPT_OR_UNTRUSTED_LOCAL_STATE = "corrupt_or_untrusted_local_state"


class LockState(str, Enum):
    ABSENT = "absent"
    RELEASED = "released"
    ACTIVE_HELD = "active_held"
    ACTIVE_STALE = "active_stale"
    CORRUPT = "corrupt"


class AuthoritativeServerState(str, Enum):
    CLEAN = "clean"
    EXPECTED_PARTIAL = "expected_partial"
    EXPECTED_COMPLETED = "expected_completed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OperationBinding:
    operation_id: str
    operation_type: AdministrativeOperationType
    target_identity: str
    target_origin: str
    account_identity: str
    approved_profile: str
    schema_version: str
    schema_evidence_digest: str
    starting_auth_methods: tuple[str, ...]


@dataclass(frozen=True)
class JournalRecord:
    sequence: int
    binding: OperationBinding
    state: DurableOperationState
    transaction_state: AdministrativeTransactionState
    mutation_index: int
    recovery_action: RecoveryAction | None
    timestamp: str
    previous_mac: str
    mac: str


@dataclass(frozen=True)
class JournalSnapshot:
    records: tuple[JournalRecord, ...]

    @property
    def latest(self) -> JournalRecord:
        return self.records[-1]


@dataclass(frozen=True)
class LockObservation:
    state: LockState
    operation_id: str | None = None


@dataclass(frozen=True)
class LocalArtifactObservation:
    trusted: bool
    key_custody_present: bool = False


@dataclass(frozen=True)
class AuthoritativeRestartObservation:
    target_identity: str
    target_origin: str
    account_identity: str
    approved_profile: str
    schema_version: str
    schema_evidence_digest: str
    auth_methods: tuple[str, ...]
    server_state: AuthoritativeServerState
    final_verification_complete: bool = False
    applicable_recovery: RecoveryAction | None = None


@dataclass(frozen=True)
class RestartDecision:
    classification: RestartClassification
    operation_id: str | None
    recovery_action: RecoveryAction | None = None


_ALLOWED: dict[DurableOperationState, frozenset[DurableOperationState]] = {
    DurableOperationState.CREATED: frozenset({DurableOperationState.PRE_SEND_READY}),
    DurableOperationState.PRE_SEND_READY: frozenset(
        {DurableOperationState.MUTATION_INTENT_RECORDED, DurableOperationState.COMPLETED}
    ),
    DurableOperationState.MUTATION_INTENT_RECORDED: frozenset(
        {
            DurableOperationState.MUTATION_RESULT_UNKNOWN,
            DurableOperationState.SERVER_STATE_PARTIAL,
            DurableOperationState.FINAL_VERIFICATION_PENDING,
            DurableOperationState.RECOVERY_REQUIRED,
        }
    ),
    DurableOperationState.MUTATION_RESULT_UNKNOWN: frozenset(
        {DurableOperationState.SERVER_STATE_PARTIAL, DurableOperationState.RECOVERY_REQUIRED}
    ),
    DurableOperationState.SERVER_STATE_PARTIAL: frozenset(
        {
            DurableOperationState.PRE_SEND_READY,
            DurableOperationState.RECOVERY_REQUIRED,
            DurableOperationState.FINAL_VERIFICATION_PENDING,
        }
    ),
    DurableOperationState.RECOVERY_REQUIRED: frozenset(),
    DurableOperationState.FINAL_VERIFICATION_PENDING: frozenset(
        {DurableOperationState.COMPLETED, DurableOperationState.RECOVERY_REQUIRED}
    ),
    DurableOperationState.COMPLETED: frozenset(),
}


def _error(message: str) -> OperationJournalError:
    return OperationJournalError(message)


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _payload(record: JournalRecord) -> dict[str, Any]:
    value = asdict(record)
    value.pop("mac")
    value["binding"]["operation_type"] = record.binding.operation_type.value
    value["state"] = record.state.value
    value["transaction_state"] = record.transaction_state.value
    value["recovery_action"] = record.recovery_action.value if record.recovery_action else None
    return value


def _mac(key: bytes, record: JournalRecord) -> str:
    return hmac.new(key, _DOMAIN + _canonical(_payload(record)), hashlib.sha256).hexdigest()


def _head_mac(key: bytes, sequence: int, record_mac: str) -> str:
    return hmac.new(key, _HEAD_DOMAIN + f"{sequence}:{record_mac}".encode(), hashlib.sha256).hexdigest()


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) < 32:
        raise OperationJournalError("Operation journal integrity key must contain at least 32 bytes")


def _validate_parent(path: Path) -> None:
    try:
        metadata = path.parent.stat(follow_symlinks=False)
    except OSError:
        raise OperationJournalError(f"Operation journal directory is unavailable: {path.parent}") from None
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise OperationJournalError(f"Operation journal directory is not owner-controlled: {path.parent}")


def _read_secure(path: Path, maximum: int) -> bytes:
    descriptor = open_nofollow(path, on_error=_error)
    try:
        validate_descriptor(path, descriptor, max_bytes=maximum, on_error=_error)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _binding_from(value: dict[str, Any]) -> OperationBinding:
    expected = {
        "operation_id",
        "operation_type",
        "target_identity",
        "target_origin",
        "account_identity",
        "approved_profile",
        "schema_version",
        "schema_evidence_digest",
        "starting_auth_methods",
    }
    if set(value) != expected:
        raise OperationJournalError("Operation journal binding fields are malformed")
    string_fields = expected - {"starting_auth_methods"}
    if any(not isinstance(value[name], str) for name in string_fields) or not isinstance(
        value["starting_auth_methods"], list
    ):
        raise OperationJournalError("Operation journal binding field types are malformed")
    if any(not isinstance(method, str) for method in value["starting_auth_methods"]):
        raise OperationJournalError("Operation journal authentication methods are malformed")
    return OperationBinding(
        operation_id=str(value["operation_id"]),
        operation_type=AdministrativeOperationType(value["operation_type"]),
        target_identity=str(value["target_identity"]),
        target_origin=str(value["target_origin"]),
        account_identity=str(value["account_identity"]),
        approved_profile=str(value["approved_profile"]),
        schema_version=str(value["schema_version"]),
        schema_evidence_digest=str(value["schema_evidence_digest"]),
        starting_auth_methods=tuple(value["starting_auth_methods"]),
    )


def _record_from(value: dict[str, Any]) -> JournalRecord:
    expected = {
        "sequence",
        "binding",
        "state",
        "transaction_state",
        "mutation_index",
        "recovery_action",
        "timestamp",
        "previous_mac",
        "mac",
    }
    if set(value) != expected:
        raise OperationJournalError("Operation journal record fields are malformed")
    if (
        not isinstance(value["sequence"], int)
        or isinstance(value["sequence"], bool)
        or not isinstance(value["mutation_index"], int)
        or isinstance(value["mutation_index"], bool)
        or any(
            not isinstance(value[name], str)
            for name in ("state", "transaction_state", "timestamp", "previous_mac", "mac")
        )
        or not isinstance(value["binding"], dict)
        or (value["recovery_action"] is not None and not isinstance(value["recovery_action"], str))
    ):
        raise OperationJournalError("Operation journal record field types are malformed")
    recovery = value["recovery_action"]
    return JournalRecord(
        sequence=int(value["sequence"]),
        binding=_binding_from(value["binding"]),
        state=DurableOperationState(value["state"]),
        transaction_state=AdministrativeTransactionState(value["transaction_state"]),
        mutation_index=int(value["mutation_index"]),
        recovery_action=RecoveryAction(recovery) if recovery is not None else None,
        timestamp=str(value["timestamp"]),
        previous_mac=str(value["previous_mac"]),
        mac=str(value["mac"]),
    )


class OperationJournal:
    """HMAC-chained journal with an authenticated, atomically replaced head."""

    def __init__(self, path: Path, integrity_key: bytes) -> None:
        _validate_key(integrity_key)
        self._path = path
        self._head_path = path.with_name(f"{path.name}.head")
        self._key = integrity_key

    def create(self, binding: OperationBinding, *, timestamp: str) -> JournalSnapshot:
        _validate_parent(self._path)
        if not all((binding.operation_id, binding.target_identity, binding.target_origin, binding.account_identity)):
            raise OperationJournalError("Operation binding contains an empty identity field")
        if (binding.account_identity, binding.approved_profile) not in _VALID_ACCOUNT_PROFILE_PAIRS:
            raise OperationJournalError("Operation binding is outside the fixed ADR-033 account/profile scope")
        if binding.starting_auth_methods != ("KeyAuth",):
            raise OperationJournalError("Operation binding must start from exact KeyAuth-only state")
        parsed_origin = urlsplit(binding.target_origin)
        if (
            parsed_origin.scheme != "https"
            or not parsed_origin.hostname
            or parsed_origin.username
            or parsed_origin.password
        ):
            raise OperationJournalError("Operation target origin must be an HTTPS origin without credentials")
        record = JournalRecord(
            0,
            binding,
            DurableOperationState.CREATED,
            AdministrativeTransactionState.NOT_STARTED,
            0,
            None,
            timestamp,
            _ZERO_MAC,
            "",
        )
        record = JournalRecord(**{**asdict(record), "binding": binding, "mac": _mac(self._key, record)})
        line = _canonical({**_payload(record), "mac": record.mac}) + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(self._path, flags, 0o600)
        except OSError:
            raise OperationJournalError(f"Operation journal already exists or is unsafe: {self._path}") from None
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, line)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._write_head(record.sequence, record.mac, create=True)
        self._fsync_parent()
        return JournalSnapshot((record,))

    def load(self) -> JournalSnapshot:
        raw = _read_secure(self._path, _MAX_JOURNAL_BYTES)
        if not raw or not raw.endswith(b"\n"):
            raise OperationJournalError("Operation journal is empty or truncated")
        records: list[JournalRecord] = []
        for line in raw.splitlines():
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError
                record = _record_from(value)
            except (ValueError, TypeError, KeyError):
                raise OperationJournalError("Operation journal contains malformed data") from None
            expected_sequence = len(records)
            expected_previous = records[-1].mac if records else _ZERO_MAC
            if record.sequence != expected_sequence or record.previous_mac != expected_previous:
                raise OperationJournalError("Operation journal sequence or integrity linkage is invalid")
            if not hmac.compare_digest(record.mac, _mac(self._key, record)):
                raise OperationJournalError("Operation journal authentication failed")
            if records:
                self._validate_transition(records[-1], record)
            records.append(record)
        self._verify_head(records[-1])
        return JournalSnapshot(tuple(records))

    def append(
        self,
        *,
        operation_id: str,
        state: DurableOperationState,
        transaction_state: AdministrativeTransactionState,
        mutation_index: int,
        timestamp: str,
        recovery_action: RecoveryAction | None = None,
    ) -> JournalSnapshot:
        snapshot = self.load()
        previous = snapshot.latest
        if operation_id != previous.binding.operation_id:
            raise OperationJournalError("Operation id does not match the durable journal")
        candidate = JournalRecord(
            previous.sequence + 1,
            previous.binding,
            state,
            transaction_state,
            mutation_index,
            recovery_action,
            timestamp,
            previous.mac,
            "",
        )
        candidate = JournalRecord(
            **{**asdict(candidate), "binding": previous.binding, "mac": _mac(self._key, candidate)}
        )
        self._validate_transition(previous, candidate)
        try:
            descriptor = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            raise OperationJournalError("Operation journal could not be opened securely for append") from None
        try:
            validate_descriptor(self._path, descriptor, max_bytes=_MAX_JOURNAL_BYTES, on_error=_error)
            line = _canonical({**_payload(candidate), "mac": candidate.mac}) + b"\n"
            if os.write(descriptor, line) != len(line):
                raise OperationJournalError("Operation journal append was incomplete")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._write_head(candidate.sequence, candidate.mac, create=False)
        self._fsync_parent()
        return JournalSnapshot((*snapshot.records, candidate))

    def _validate_transition(self, previous: JournalRecord, candidate: JournalRecord) -> None:
        if candidate.binding != previous.binding:
            raise OperationJournalError("Operation binding changed within the journal")
        if candidate.state not in _ALLOWED[previous.state]:
            raise OperationJournalError(
                f"Illegal durable operation transition: {previous.state.value} -> {candidate.state.value}"
            )
        if candidate.mutation_index < previous.mutation_index or candidate.mutation_index > previous.mutation_index + 1:
            raise OperationJournalError("Mutation index is out of order")
        if (
            candidate.state is DurableOperationState.PRE_SEND_READY
            and candidate.mutation_index != previous.mutation_index + 1
        ):
            raise OperationJournalError("Each new pre-send checkpoint must advance the mutation index")
        if candidate.state is DurableOperationState.RECOVERY_REQUIRED and candidate.recovery_action is None:
            raise OperationJournalError("Recovery-required state must name one closed recovery action")
        if candidate.state is not DurableOperationState.RECOVERY_REQUIRED and candidate.recovery_action is not None:
            raise OperationJournalError("Recovery action is only valid in recovery-required state")
        if candidate.timestamp < previous.timestamp:
            raise OperationJournalError("Operation journal timestamps are out of order")

    def _write_head(self, sequence: int, record_mac: str, *, create: bool) -> None:
        head = {"sequence": sequence, "record_mac": record_mac, "mac": _head_mac(self._key, sequence, record_mac)}
        data = _canonical(head) + b"\n"
        if create:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            try:
                descriptor = os.open(self._head_path, flags, 0o600)
            except OSError:
                raise OperationJournalError(
                    f"Operation journal head already exists or is unsafe: {self._head_path}"
                ) from None
            try:
                os.write(descriptor, data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return
        if self._head_path.is_symlink():
            raise OperationJournalError("Operation journal head must not be a symbolic link")
        temp = self._head_path.with_name(f".{self._head_path.name}.{os.getpid()}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(temp, flags, 0o600)
            try:
                os.write(descriptor, data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temp, self._head_path)
        finally:
            with suppress(FileNotFoundError):
                temp.unlink()

    def _verify_head(self, record: JournalRecord) -> None:
        try:
            head = json.loads(_read_secure(self._head_path, _MAX_METADATA_BYTES))
            if set(head) != {"sequence", "record_mac", "mac"}:
                raise ValueError
            expected = _head_mac(self._key, int(head["sequence"]), str(head["record_mac"]))
        except (ValueError, TypeError, KeyError):
            raise OperationJournalError("Operation journal head is malformed") from None
        if not hmac.compare_digest(str(head["mac"]), expected):
            raise OperationJournalError("Operation journal head authentication failed")
        if int(head["sequence"]) != record.sequence or str(head["record_mac"]) != record.mac:
            raise OperationJournalError("Operation journal rollback or head mismatch detected")

    def _fsync_parent(self) -> None:
        descriptor = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class ExclusiveOperationLock:
    """Owner-only advisory lock whose authenticated metadata survives crashes."""

    def __init__(self, path: Path, integrity_key: bytes) -> None:
        _validate_key(integrity_key)
        self._path = path
        self._key = integrity_key
        self._descriptor: int | None = None
        self._operation_id: str | None = None

    def acquire(self, operation_id: str, *, timestamp: str) -> None:
        if not operation_id:
            raise OperationLockError("Operation id must not be empty")
        _validate_parent(self._path)
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(self._path, flags, 0o600)
            validate_descriptor(self._path, descriptor, max_bytes=_MAX_METADATA_BYTES, on_error=OperationLockError)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError, OperationLockError):
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            raise OperationLockError("Another ADR-033 administrative operation holds the local lock") from None
        existing = self._read_metadata(descriptor)
        if existing is not None and existing.get("active") is True:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
            raise OperationLockError("Stale or ambiguous active lock metadata requires restart classification")
        self._write_metadata(descriptor, operation_id, timestamp, active=True)
        self._descriptor, self._operation_id = descriptor, operation_id

    def release(self, *, timestamp: str) -> None:
        if self._descriptor is None or self._operation_id is None:
            raise OperationLockError("Operation lock is not held by this object")
        self._write_metadata(self._descriptor, self._operation_id, timestamp, active=False)
        fcntl.flock(self._descriptor, fcntl.LOCK_UN)
        os.close(self._descriptor)
        self._descriptor = None
        self._operation_id = None

    def inspect(self) -> LockObservation:
        if not self._path.exists() and not self._path.is_symlink():
            return LockObservation(LockState.ABSENT)
        try:
            descriptor = os.open(self._path, os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            return LockObservation(LockState.CORRUPT)
        try:
            validate_descriptor(self._path, descriptor, max_bytes=_MAX_METADATA_BYTES, on_error=OperationLockError)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                metadata = self._read_metadata(descriptor)
                return LockObservation(LockState.ACTIVE_HELD, str(metadata.get("operation_id")) if metadata else None)
            metadata = self._read_metadata(descriptor)
            if metadata is None:
                return LockObservation(LockState.CORRUPT)
            return LockObservation(
                LockState.ACTIVE_STALE if metadata["active"] else LockState.RELEASED,
                str(metadata["operation_id"]),
            )
        except OperationLockError:
            return LockObservation(LockState.CORRUPT)
        finally:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _write_metadata(self, descriptor: int, operation_id: str, timestamp: str, *, active: bool) -> None:
        payload = {"operation_id": operation_id, "active": active, "timestamp": timestamp}
        payload["mac"] = hmac.new(self._key, _LOCK_DOMAIN + _canonical(payload), hashlib.sha256).hexdigest()
        data = _canonical(payload) + b"\n"
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, data)
        os.fsync(descriptor)

    def _read_metadata(self, descriptor: int) -> dict[str, Any] | None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = os.read(descriptor, _MAX_METADATA_BYTES + 1)
        if not raw:
            return None
        try:
            value = json.loads(raw)
            if set(value) != {"operation_id", "active", "timestamp", "mac"}:
                raise ValueError
            supplied = str(value.pop("mac"))
            expected = hmac.new(self._key, _LOCK_DOMAIN + _canonical(value), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(supplied, expected):
                raise ValueError
            value["mac"] = supplied
            return cast(dict[str, Any], value)
        except (ValueError, TypeError):
            raise OperationLockError("Operation lock metadata is malformed or unauthenticated") from None


def classify_restart(
    *,
    journal: JournalSnapshot | None,
    journal_trusted: bool,
    lock: LockObservation,
    artifacts: LocalArtifactObservation,
    authoritative: AuthoritativeRestartObservation | None,
) -> RestartDecision:
    """Pure classification only; never reads a file, contacts a target, or mutates."""

    if not journal_trusted or not artifacts.trusted or lock.state is LockState.CORRUPT:
        return RestartDecision(RestartClassification.CORRUPT_OR_UNTRUSTED_LOCAL_STATE, None)
    if journal is None:
        if lock.state not in {LockState.ABSENT, LockState.RELEASED} or artifacts.key_custody_present:
            return RestartDecision(RestartClassification.CORRUPT_OR_UNTRUSTED_LOCAL_STATE, lock.operation_id)
        return RestartDecision(RestartClassification.CLEAN_NO_OPERATION, None)
    latest = journal.latest
    operation_id = latest.binding.operation_id
    if lock.operation_id is not None and lock.operation_id != operation_id:
        return RestartDecision(RestartClassification.CORRUPT_OR_UNTRUSTED_LOCAL_STATE, operation_id)
    if lock.state is LockState.ACTIVE_HELD:
        return RestartDecision(RestartClassification.RECOVERY_REQUIRED, operation_id, latest.recovery_action)
    if authoritative is None:
        return RestartDecision(RestartClassification.RECOVERY_REQUIRED, operation_id, latest.recovery_action)
    binding = latest.binding
    if (
        authoritative.target_identity != binding.target_identity
        or authoritative.target_origin != binding.target_origin
        or authoritative.account_identity != binding.account_identity
        or authoritative.approved_profile != binding.approved_profile
        or authoritative.schema_version != binding.schema_version
        or authoritative.schema_evidence_digest != binding.schema_evidence_digest
        or authoritative.auth_methods != binding.starting_auth_methods
    ):
        return RestartDecision(RestartClassification.RECOVERY_REQUIRED, operation_id, latest.recovery_action)
    if latest.state is DurableOperationState.COMPLETED:
        if (
            authoritative.final_verification_complete
            and authoritative.server_state is AuthoritativeServerState.EXPECTED_COMPLETED
        ):
            return RestartDecision(RestartClassification.CLEAN_COMPLETED, operation_id)
        return RestartDecision(RestartClassification.COMPLETED_NEEDS_FINAL_VERIFICATION, operation_id)
    if latest.state in {DurableOperationState.CREATED, DurableOperationState.PRE_SEND_READY}:
        if authoritative.server_state is AuthoritativeServerState.CLEAN:
            return RestartDecision(RestartClassification.PRE_SEND_RESUMABLE, operation_id)
        return RestartDecision(
            RestartClassification.PARTIAL_SERVER_STATE, operation_id, authoritative.applicable_recovery
        )
    if latest.state in {DurableOperationState.MUTATION_INTENT_RECORDED, DurableOperationState.MUTATION_RESULT_UNKNOWN}:
        return RestartDecision(RestartClassification.MUTATION_SENT_RESULT_UNKNOWN, operation_id)
    if latest.state is DurableOperationState.FINAL_VERIFICATION_PENDING:
        return RestartDecision(RestartClassification.COMPLETED_NEEDS_FINAL_VERIFICATION, operation_id)
    if latest.state is DurableOperationState.SERVER_STATE_PARTIAL:
        return RestartDecision(
            RestartClassification.PARTIAL_SERVER_STATE, operation_id, authoritative.applicable_recovery
        )
    return RestartDecision(RestartClassification.RECOVERY_REQUIRED, operation_id, latest.recovery_action)
