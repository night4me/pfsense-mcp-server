"""Crash-aware SQLite persistence for inert Tier 1 contracts.

The store is not constructed by production bootstrap. Protected artifacts are
opaque ciphertext supplied by a future owner-approved key provider; this module
never receives plaintext snapshots, targets, or mutation intents.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from pfsense_mcp.capabilities import Capability

from .anti_rollback import AnchorProvisioningStatus, AntiRollbackAnchor, HighWaterMark, ProvisioningRecord
from .canonical import frame_bytes, frame_str
from .confirmation import ConfirmationEvidence, ConfirmationVerifier
from .contract import ProtectedArtifact, RecoveryContract
from .errors import (
    ConfirmationError,
    ContractConflictError,
    ContractIntegrityError,
    ContractNotFoundError,
    ContractValidationError,
)
from .rate_policy import RatePolicy, is_cooldown_state
from .reconciliation import OUTCOME_TARGET_STATE, ReconciliationEvidence, ReconciliationVerifier
from .state_machine import RecoveryState, require_transition

_SCHEMA_VERSION = 4
_STORE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_RESERVATION_STATES = frozenset(
    {
        RecoveryState.EXECUTING,
        RecoveryState.RECONCILIATION,
        RecoveryState.ROLLING_BACK,
        RecoveryState.ROLLBACK_FAILED,
    }
)
_INTERRUPTED_STATES = frozenset({RecoveryState.EXECUTING, RecoveryState.ROLLING_BACK})
FaultHook = Callable[[str], None]
Clock = Callable[[], datetime]
_SELECT_CONTRACT_BY_ID = (
    "SELECT payload, mac, contract_id, operation_id, idempotency_key, "
    "target_identity_digest, state, state_version FROM contracts WHERE contract_id = ?"
)
_SELECT_ALL_CONTRACTS = (
    "SELECT payload, mac, contract_id, operation_id, idempotency_key, "
    "target_identity_digest, state, state_version FROM contracts ORDER BY contract_id"
)
_CONTRACT_FIELDS = frozenset(
    {
        "capability",
        "confirmation_digest",
        "confirmed_at",
        "contract_id",
        "created_at",
        "endpoint_symbol",
        "expires_at",
        "http_method",
        "idempotency_key",
        "intent_digest",
        "operation_id",
        "protected_intent",
        "protected_snapshot",
        "protected_target_identity",
        "rollback_plan_version",
        "snapshot_digest",
        "state",
        "state_version",
        "target_fingerprint",
        "target_identity_digest",
    }
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractIntegrityError("Stored Recovery Contract contains a duplicate field.")
        result[key] = value
    return result


def _artifact_to_dict(artifact: ProtectedArtifact) -> dict[str, str]:
    return {
        "algorithm": artifact.algorithm,
        "ciphertext": base64.b64encode(artifact.ciphertext).decode("ascii"),
        "key_id": artifact.key_id,
    }


def _artifact_from_dict(value: object) -> ProtectedArtifact:
    if not isinstance(value, dict) or set(value) != {"algorithm", "ciphertext", "key_id"}:
        raise ContractIntegrityError("Stored protected artifact is invalid.")
    if not all(isinstance(value[field], str) for field in ("algorithm", "ciphertext", "key_id")):
        raise ContractIntegrityError("Stored protected artifact is invalid.")
    try:
        return ProtectedArtifact(
            algorithm=value["algorithm"],
            ciphertext=base64.b64decode(value["ciphertext"], validate=True),
            key_id=value["key_id"],
        )
    except (ValueError, ContractValidationError) as exc:
        raise ContractIntegrityError("Stored protected artifact is invalid.") from exc


def _contract_payload(contract: RecoveryContract) -> bytes:
    payload = {
        "capability": contract.capability.name,
        "confirmation_digest": contract.confirmation_digest,
        "confirmed_at": contract.confirmed_at.isoformat() if contract.confirmed_at else None,
        "contract_id": contract.contract_id,
        "created_at": contract.created_at.isoformat(),
        "endpoint_symbol": contract.endpoint_symbol,
        "expires_at": contract.expires_at.isoformat(),
        "http_method": contract.http_method,
        "idempotency_key": contract.idempotency_key,
        "intent_digest": contract.intent_digest,
        "operation_id": contract.operation_id,
        "protected_intent": _artifact_to_dict(contract.protected_intent),
        "protected_snapshot": _artifact_to_dict(contract.protected_snapshot),
        "protected_target_identity": _artifact_to_dict(contract.protected_target_identity),
        "rollback_plan_version": contract.rollback_plan_version,
        "snapshot_digest": contract.snapshot_digest,
        "state": contract.state.value,
        "state_version": contract.state_version,
        "target_fingerprint": contract.target_fingerprint,
        "target_identity_digest": contract.target_identity_digest,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _contract_from_payload(payload: bytes) -> RecoveryContract:
    try:
        value = json.loads(payload, object_pairs_hook=_strict_object)
        if not isinstance(value, dict) or set(value) != _CONTRACT_FIELDS:
            raise ContractIntegrityError("Stored Recovery Contract fields are invalid.")
        return RecoveryContract(
            contract_id=value["contract_id"],
            operation_id=value["operation_id"],
            idempotency_key=value["idempotency_key"],
            capability=Capability[value["capability"]],
            endpoint_symbol=value["endpoint_symbol"],
            http_method=value["http_method"],
            target_identity_digest=value["target_identity_digest"],
            target_fingerprint=value["target_fingerprint"],
            intent_digest=value["intent_digest"],
            snapshot_digest=value["snapshot_digest"],
            rollback_plan_version=value["rollback_plan_version"],
            created_at=datetime.fromisoformat(value["created_at"]),
            expires_at=datetime.fromisoformat(value["expires_at"]),
            state=RecoveryState(value["state"]),
            state_version=value["state_version"],
            protected_target_identity=_artifact_from_dict(value["protected_target_identity"]),
            protected_intent=_artifact_from_dict(value["protected_intent"]),
            protected_snapshot=_artifact_from_dict(value["protected_snapshot"]),
            confirmation_digest=value["confirmation_digest"],
            confirmed_at=datetime.fromisoformat(value["confirmed_at"]) if value["confirmed_at"] else None,
        )
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, ContractValidationError) as exc:
        raise ContractIntegrityError("Stored Recovery Contract is invalid.") from exc


class SqliteRecoveryContractStore:
    """Authoritative compare-and-set store with target reservations and HMAC integrity."""

    def __init__(
        self,
        path: Path,
        *,
        integrity_key: bytes,
        store_id: str,
        fault_hook: FaultHook | None = None,
        clock: Clock = _utc_now,
        confirmation_verifier: ConfirmationVerifier | None = None,
        reconciliation_verifier: ReconciliationVerifier | None = None,
        anti_rollback_anchor: AntiRollbackAnchor | None = None,
        rate_policy: RatePolicy | None = None,
    ) -> None:
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise ContractValidationError("Recovery store integrity key must be at least 32 bytes.")
        if not isinstance(store_id, str) or not _STORE_ID.fullmatch(store_id):
            raise ContractValidationError("Recovery store identifier is invalid.")
        if not callable(clock):
            raise ContractValidationError("Recovery store clock is invalid.")
        self._path = path
        self._integrity_key = bytes(integrity_key)
        self._store_id = store_id
        self._fault_hook = fault_hook
        self._clock = clock
        self._confirmation_verifier = confirmation_verifier
        self._reconciliation_verifier = reconciliation_verifier
        # rate_policy is intentionally optional, like anti_rollback_anchor:
        # it is damage containment, not authorization, and every numeric
        # default is explicitly provisional pending disposable-lab
        # evidence (ADR-015). When configured, every check below is fully
        # enforced.
        self._rate_policy = rate_policy
        # anti_rollback_anchor is intentionally optional: no concrete
        # AntiRollbackAnchor backend is selected yet (see ADR-011, pending
        # owner confirmation of production host hardware). When configured,
        # it is fully enforced before every EXECUTING transition. Refusing
        # EXECUTING outright when unconfigured is the activation-time
        # behavior described in whole_store_anti_rollback.md and is not yet
        # switched on here -- see that spec's Activation requirements.
        self._anti_rollback_anchor = anti_rollback_anchor
        self._high_water_mark = HighWaterMark(integrity_key=self._integrity_key, store_id=store_id)
        self._provisioning_record = ProvisioningRecord(integrity_key=self._integrity_key, store_id=store_id)
        self._prepare_path()
        self._initialize_schema()

    def _prepare_path(self) -> None:
        if not hasattr(os, "O_NOFOLLOW"):
            raise ContractValidationError("Recovery store requires Linux O_NOFOLLOW support.")
        parent = self._path.parent
        try:
            parent_info = parent.lstat()
        except OSError:
            raise ContractValidationError(f"Recovery store parent directory does not exist: {parent}") from None
        if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
            raise ContractValidationError("Recovery store parent must be a real directory.")
        if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) & 0o077:
            raise ContractValidationError("Recovery store parent must be owned by the effective user with mode 0700.")
        if self._path.exists() or self._path.is_symlink():
            info = self._path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ContractValidationError("Recovery store must be a regular non-symlink file.")
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ContractValidationError("Recovery store must be owner-only.")
            return
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW
        fd = os.open(self._path, flags, 0o600)
        os.close(fd)

    def _now(self) -> datetime:
        instant = self._clock()
        if instant.tzinfo is None or instant.utcoffset() != timezone.utc.utcoffset(instant):
            raise ContractValidationError("Recovery store clock must return UTC.")
        return instant

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.DatabaseError:
            if connection is not None:
                connection.close()
            raise ContractIntegrityError("Recovery store database could not be opened safely.") from None

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        expected_columns = {
            "metadata": (("key", "TEXT", 0, 1), ("value", "TEXT", 1, 0)),
            "contracts": (
                ("contract_id", "TEXT", 0, 1),
                ("operation_id", "TEXT", 1, 0),
                ("idempotency_key", "TEXT", 1, 0),
                ("target_identity_digest", "TEXT", 1, 0),
                ("state", "TEXT", 1, 0),
                ("state_version", "INTEGER", 1, 0),
                ("payload", "BLOB", 1, 0),
                ("mac", "TEXT", 1, 0),
            ),
            "target_reservations": (("target_identity_digest", "TEXT", 0, 1), ("contract_id", "TEXT", 1, 0)),
            "audit_events": (
                ("sequence", "INTEGER", 0, 1),
                ("contract_id", "TEXT", 1, 0),
                ("event_type", "TEXT", 1, 0),
                ("previous_state", "TEXT", 0, 0),
                ("current_state", "TEXT", 1, 0),
                ("state_version", "INTEGER", 1, 0),
                ("recorded_at", "TEXT", 1, 0),
                ("mac", "TEXT", 1, 0),
            ),
            "anchor_state": (
                ("key", "TEXT", 0, 1),
                ("value", "TEXT", 1, 0),
                ("mac", "TEXT", 1, 0),
            ),
            "rate_cooldowns": (
                ("target_identity_digest", "TEXT", 0, 1),
                ("cooldown_until", "TEXT", 1, 0),
            ),
        }
        actual_columns = {
            table: tuple((row[1], row[2], row[3], row[5]) for row in connection.execute(f"PRAGMA table_info({table})"))
            for table in expected_columns
        }
        if actual_columns != expected_columns:
            raise ContractIntegrityError("Recovery store schema does not match the required version.")
        expected_unique = {
            "metadata": {("key",)},
            "contracts": {("contract_id",), ("operation_id",), ("idempotency_key",)},
            "target_reservations": {("target_identity_digest",), ("contract_id",)},
            "audit_events": {("contract_id", "state_version")},
            "anchor_state": {("key",)},
            "rate_cooldowns": {("target_identity_digest",)},
        }
        for table, expected in expected_unique.items():
            actual = {
                tuple(row[2] for row in connection.execute(f"PRAGMA index_info({index[1]})"))
                for index in connection.execute(f"PRAGMA index_list({table})")
                if index[2]
            }
            if actual != expected:
                raise ContractIntegrityError("Recovery store schema uniqueness constraints are invalid.")
        expected_foreign_key = (("contracts", "contract_id", "contract_id", "CASCADE"),)
        for table in ("target_reservations", "audit_events"):
            actual_foreign_keys = tuple(
                (row[2], row[3], row[4], row[6]) for row in connection.execute(f"PRAGMA foreign_key_list({table})")
            )
            if actual_foreign_keys != expected_foreign_key:
                raise ContractIntegrityError("Recovery store schema foreign keys are invalid.")

    def _initialize_schema(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS contracts (
                    contract_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    target_identity_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    state_version INTEGER NOT NULL,
                    payload BLOB NOT NULL,
                    mac TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS target_reservations (
                    target_identity_digest TEXT PRIMARY KEY,
                    contract_id TEXT NOT NULL UNIQUE REFERENCES contracts(contract_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS audit_events (
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
                CREATE TABLE IF NOT EXISTS anchor_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    mac TEXT NOT NULL
                );
                -- rate_cooldowns is deliberately unauthenticated (no mac
                -- column), unlike every other table here: it is damage
                -- containment (rate_policy.py), not an authorization or
                -- integrity boundary. A same-effective-user attacker who
                -- could tamper with it already has file-level access this
                -- store's threat model does not attempt to defend against.
                CREATE TABLE IF NOT EXISTS rate_cooldowns (
                    target_identity_digest TEXT PRIMARY KEY,
                    cooldown_until TEXT NOT NULL
                );
                """
            )
            self._verify_schema(connection)
            existing = dict(connection.execute("SELECT key, value FROM metadata"))
            expected = {"schema_version": str(_SCHEMA_VERSION), "store_id": self._store_id}
            if existing and existing != expected:
                raise ContractIntegrityError("Recovery store metadata does not match this build or store identity.")
            if not existing:
                has_state = connection.execute(
                    "SELECT EXISTS(SELECT 1 FROM contracts) OR EXISTS(SELECT 1 FROM audit_events)"
                ).fetchone()[0]
                if has_state:
                    raise ContractIntegrityError("Recovery store metadata is missing from a non-empty store.")
                connection.executemany("INSERT INTO metadata(key, value) VALUES (?, ?)", expected.items())
        os.chmod(self._path, 0o600)

    def _mac(self, *components: bytes) -> str:
        """Length-frame the store ID and every component before HMAC'ing,
        so distinct component boundaries can never collide (the same
        framing discipline canonical.py's digest_value() already applies
        — see frame_str/frame_bytes). A NUL or other ad hoc delimiter must
        never be reintroduced here."""

        framed = frame_str(self._store_id)
        for component in components:
            framed += frame_bytes(component)
        return hmac.new(self._integrity_key, framed, hashlib.sha256).hexdigest()

    def _audit_mac(
        self,
        *,
        contract_id: str,
        event_type: str,
        previous_state: str | None,
        current_state: str,
        state_version: int,
        recorded_at: str,
    ) -> str:
        payload = json.dumps(
            {
                "contract_id": contract_id,
                "current_state": current_state,
                "event_type": event_type,
                "previous_state": previous_state,
                "recorded_at": recorded_at,
                "state_version": state_version,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return self._mac(b"audit-event", payload)

    def _decode_row(self, row: sqlite3.Row | tuple[object, ...]) -> RecoveryContract:
        raw_payload = row[0]
        if not isinstance(raw_payload, bytes):
            raise ContractIntegrityError("Stored Recovery Contract payload is invalid.")
        payload = raw_payload
        supplied_mac = str(row[1])
        if not hmac.compare_digest(supplied_mac, self._mac(payload)):
            raise ContractIntegrityError("Stored Recovery Contract failed integrity verification.")
        contract = _contract_from_payload(payload)
        indexed = (str(row[2]), str(row[3]), str(row[4]), str(row[5]), str(row[6]), row[7])
        expected = (
            contract.contract_id,
            contract.operation_id,
            contract.idempotency_key,
            contract.target_identity_digest,
            contract.state.value,
            contract.state_version,
        )
        if indexed != expected:
            raise ContractIntegrityError("Stored Recovery Contract index does not match its protected record.")
        return contract

    def _verify_reservation(self, connection: sqlite3.Connection, contract: RecoveryContract) -> None:
        row = connection.execute(
            "SELECT target_identity_digest FROM target_reservations WHERE contract_id = ?",
            (contract.contract_id,),
        ).fetchone()
        expected = contract.target_identity_digest if contract.state in _RESERVATION_STATES else None
        actual = str(row[0]) if row is not None else None
        if actual != expected:
            raise ContractIntegrityError("Recovery Contract target reservation is inconsistent.")

    def _verified_audit_rows(
        self, connection: sqlite3.Connection, contract: RecoveryContract
    ) -> tuple[tuple[object, ...], ...]:
        rows = connection.execute(
            """SELECT contract_id, event_type, previous_state, current_state,
                      state_version, recorded_at, mac
               FROM audit_events WHERE contract_id = ? ORDER BY state_version""",
            (contract.contract_id,),
        ).fetchall()
        if len(rows) != contract.state_version + 1:
            raise ContractIntegrityError("Recovery Contract audit history is incomplete.")
        previous_current: str | None = None
        for expected_version, row in enumerate(rows):
            contract_id, event_type, previous_state, current_state, state_version, recorded_at, supplied_mac = row
            if contract_id != contract.contract_id or state_version != expected_version:
                raise ContractIntegrityError("Recovery Contract audit history ordering is invalid.")
            if expected_version == 0:
                if event_type != "contract_created" or previous_state is not None:
                    raise ContractIntegrityError("Recovery Contract audit origin is invalid.")
            elif previous_state != previous_current:
                raise ContractIntegrityError("Recovery Contract audit state chain is invalid.")
            try:
                recorded = datetime.fromisoformat(str(recorded_at))
            except ValueError as exc:
                raise ContractIntegrityError("Recovery Contract audit timestamp is invalid.") from exc
            if recorded.tzinfo is None or recorded.utcoffset() != timezone.utc.utcoffset(recorded):
                raise ContractIntegrityError("Recovery Contract audit timestamp is invalid.")
            expected_mac = self._audit_mac(
                contract_id=str(contract_id),
                event_type=str(event_type),
                previous_state=str(previous_state) if previous_state is not None else None,
                current_state=str(current_state),
                state_version=int(state_version),
                recorded_at=str(recorded_at),
            )
            if not hmac.compare_digest(str(supplied_mac), expected_mac):
                raise ContractIntegrityError("Recovery Contract audit event failed integrity verification.")
            previous_current = str(current_state)
        if previous_current != contract.state.value:
            raise ContractIntegrityError("Recovery Contract audit state does not match the authoritative record.")
        return tuple(rows)

    def _verify_related_state(self, connection: sqlite3.Connection, contract: RecoveryContract) -> None:
        self._verify_reservation(connection, contract)
        self._verified_audit_rows(connection, contract)

    def _invoke_fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    def create(self, contract: RecoveryContract) -> None:
        if contract.state != RecoveryState.PREPARING or contract.state_version != 0 or contract.is_confirmed:
            raise ContractValidationError("New Recovery Contract must start unconfirmed at PREPARING version zero.")
        now = self._now()
        if contract.created_at > now or contract.is_expired(now=now):
            raise ContractValidationError("New Recovery Contract validity window does not include the store clock.")
        payload = _contract_payload(contract)
        with self._connect() as connection:
            try:
                self._invoke_fault("before_transaction")
                connection.execute("BEGIN IMMEDIATE")
                if self._rate_policy is not None:
                    self._rate_policy.check_prepare_allowed(
                        connection,
                        target_identity_digest=contract.target_identity_digest,
                        capability=contract.capability,
                        now=now,
                    )
                connection.execute(
                    "INSERT INTO contracts VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        contract.contract_id,
                        contract.operation_id,
                        contract.idempotency_key,
                        contract.target_identity_digest,
                        contract.state.value,
                        contract.state_version,
                        payload,
                        self._mac(payload),
                    ),
                )
                self._insert_audit(connection, contract, "contract_created", previous_state=None)
                self._invoke_fault("after_record_write")
                self._invoke_fault("before_commit")
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ContractConflictError("Recovery Contract identity or idempotency key already exists.") from exc
        self._invoke_fault("after_commit")

    def load(self, contract_id: str) -> RecoveryContract:
        with self._connect() as connection:
            row = connection.execute(_SELECT_CONTRACT_BY_ID, (contract_id,)).fetchone()
            if row is None:
                raise ContractNotFoundError("Authoritative Recovery Contract was not found.")
            contract = self._decode_row(row)
            if contract.contract_id != contract_id:
                raise ContractIntegrityError("Stored Recovery Contract identity does not match its index.")
            self._verify_related_state(connection, contract)
        return contract

    def confirm(self, contract_id: str, *, evidence: ConfirmationEvidence, expected_version: int) -> RecoveryContract:
        current = self.load(contract_id)
        if current.state_version != expected_version:
            raise ContractConflictError("Recovery Contract version changed before confirmation.")
        confirmed_at = self._now()
        if current.is_expired(now=confirmed_at):
            raise ContractConflictError("Recovery Contract expired before confirmation.")
        evidence.verify_bindings(current)
        verifier = self._confirmation_verifier
        if verifier is None:
            raise ConfirmationError("No owner confirmation verifier is configured.")
        try:
            verified = verifier.verify(evidence)
        except Exception:
            raise ConfirmationError("Owner confirmation verification failed.") from None
        if not verified:
            raise ConfirmationError("Owner confirmation evidence was refused.")
        confirmed = current.with_confirmation(
            authority_id=evidence.authority_id,
            evidence_digest=evidence.evidence_digest,
            confirmed_at=confirmed_at,
        )
        return self._replace(current, confirmed, event_type="contract_confirmed")

    def resolve_reconciliation(self, contract_id: str, *, evidence: ReconciliationEvidence) -> RecoveryContract:
        """The only caller of require_transition(..., manual=True) in
        this codebase -- RECONCILIATION's declared exits are all
        manual-only (state_machine.py) and this is the sole authenticated
        path that uses that authority. A stale observed_state_version
        (the contract moved since the operator observed it) is refused,
        not silently applied to whatever the current state happens to
        be."""

        current = self.load(contract_id)
        if current.state != RecoveryState.RECONCILIATION:
            raise ContractConflictError("Recovery Contract is not in RECONCILIATION.")
        evidence.verify_bindings(
            contract_id=current.contract_id,
            operation_id=current.operation_id,
            state_version=current.state_version,
        )
        verifier = self._reconciliation_verifier
        if verifier is None:
            raise ConfirmationError("No reconciliation verifier is configured.")
        try:
            verified = verifier.verify(evidence)
        except Exception:
            raise ConfirmationError("Reconciliation verification failed.") from None
        if not verified:
            raise ConfirmationError("Reconciliation evidence was refused.")
        target_state = OUTCOME_TARGET_STATE[evidence.outcome]
        require_transition(current.state, target_state, manual=True)
        updated = replace(current, state=target_state, state_version=current.state_version + 1)
        return self._replace(current, updated, event_type="reconciliation_resolved")

    def rotate_artifacts(
        self,
        contract_id: str,
        *,
        expected_version: int,
        protected_target_identity: ProtectedArtifact,
        protected_intent: ProtectedArtifact,
        protected_snapshot: ProtectedArtifact,
    ) -> RecoveryContract:
        """Atomically replace a contract's protected artifacts (e.g. after
        key rotation) without changing its state. Compare-and-set against
        expected_version; reservation is unaffected since the state does
        not change. Used only by key_lifecycle.rotate_key()."""

        current = self.load(contract_id)
        if current.state_version != expected_version:
            raise ContractConflictError("Recovery Contract version changed before artifact rotation.")
        updated = replace(
            current,
            protected_target_identity=protected_target_identity,
            protected_intent=protected_intent,
            protected_snapshot=protected_snapshot,
            state_version=current.state_version + 1,
        )
        return self._replace(current, updated, event_type="artifacts_rotated")

    def all_contracts(self) -> tuple[RecoveryContract, ...]:
        """Every authoritative contract, verified, in contract_id order.
        Used only by key_lifecycle.rotate_key() and operator tooling —
        never by ordinary execution/reconciliation paths."""

        with self._connect() as connection:
            rows = connection.execute(_SELECT_ALL_CONTRACTS).fetchall()
            contracts = tuple(self._decode_row(row) for row in rows)
            for contract in contracts:
                self._verify_related_state(connection, contract)
            return contracts

    def provision_anchor_baseline(self, *, value: int, handle: str) -> None:
        """One-time administrative operation (Slice B primitive; never
        called by normal contract lifecycle operations): seeds this
        store's `HighWaterMark` with an externally-observed anchor
        value -- e.g. a TPM counter's real initial value, obtained and
        verified per docs/tier1/specs/anti_rollback_tpm_host_witness.md's
        provisioning state machine (S7) -- and, once re-read and
        confirmed to agree (S8), durably marks provisioning complete
        (S9). This is the single, exact entry point a future provisioning
        script (or its manual equivalent) calls to perform the store-side
        half of anchor provisioning; it performs no TPM or network I/O
        itself.

        Insert-only throughout, atomically, within one transaction:
        raises `AnchorAlreadyProvisionedError` if either the high-water
        mark or the completion marker already exists for this store —
        neither is ever silently overwritten. Raises
        `ContractIntegrityError` if the immediate re-read after seeding
        does not exactly match `value` (paranoid self-check, not assumed
        from the write alone).

        `value` must already have been obtained from the real,
        authoritative anchor by the caller — this method does not
        validate it against any live TPM/witness backend, and does not
        assume it is 0 or any other specific number (a freshly-defined
        TPM counter's real first value is unpredictable and non-zero;
        see the provisioning spec's "Initial baseline" section)."""

        if not isinstance(handle, str) or not handle:
            raise ContractValidationError("Anchor handle must be a non-empty string.")
        provisioned_at = self._now().isoformat()
        with self._connect() as connection:
            self._high_water_mark.seed(connection, value=value)
            reread = self._high_water_mark.read(connection)
            if reread != value:
                raise ContractIntegrityError("Anchor baseline verification failed immediately after seeding.")
            self._provisioning_record.mark_complete(
                connection,
                handle=handle,
                verified_value=value,
                provisioned_at=provisioned_at,
                high_water_mark=self._high_water_mark,
            )

    def anchor_provisioning_status(self) -> AnchorProvisioningStatus:
        """Read-only status accessor for operator tooling (e.g.
        `scripts/tier1_store_bootstrap.py`) — never called by
        `provision_anchor_baseline()` or any execution/reconciliation
        path. Lets a caller ask "is this store's anchor already
        provisioned, and with what?" without reaching into
        `self._high_water_mark`/`self._provisioning_record` directly or
        opening its own connection — the one sanctioned way to inspect
        this state from outside the class."""

        with self._connect() as connection:
            seeded = self._high_water_mark.is_seeded(connection)
            baseline = self._high_water_mark.read(connection) if seeded else None
            marker = self._provisioning_record.read(connection)
        return AnchorProvisioningStatus(
            seeded=seeded,
            baseline=baseline,
            complete=marker is not None,
            handle=str(marker["handle"]) if marker is not None else None,
            provisioned_at=str(marker["provisioned_at"]) if marker is not None else None,
        )

    def transition(
        self,
        contract_id: str,
        *,
        expected_state: RecoveryState,
        expected_version: int,
        target_state: RecoveryState,
    ) -> RecoveryContract:
        require_transition(expected_state, target_state)
        current = self.load(contract_id)
        if current.state != expected_state or current.state_version != expected_version:
            raise ContractConflictError("Recovery Contract state changed before atomic transition.")
        instant = self._now()
        if (
            current.state in {RecoveryState.PREPARING, RecoveryState.PREPARED}
            and current.is_expired(now=instant)
            and target_state != RecoveryState.EXPIRED
        ):
            raise ContractConflictError("Expired Recovery Contract may only transition to EXPIRED.")
        if target_state == RecoveryState.EXECUTING:
            if not current.is_confirmed or current.is_expired(now=instant):
                raise ContractConflictError("Recovery Contract is unconfirmed or expired.")
            if self._anti_rollback_anchor is not None or self._rate_policy is not None:
                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    if self._anti_rollback_anchor is not None:
                        self._high_water_mark.before_executing_transition(self._anti_rollback_anchor, connection)
                    if self._rate_policy is not None:
                        self._rate_policy.check_execute_allowed(connection, now=instant)
                    connection.commit()
        updated = replace(current, state=target_state, state_version=current.state_version + 1)
        return self._replace(current, updated, event_type="state_transition")

    def _replace(self, current: RecoveryContract, updated: RecoveryContract, *, event_type: str) -> RecoveryContract:
        payload = _contract_payload(updated)
        with self._connect() as connection:
            try:
                self._invoke_fault("before_transaction")
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(_SELECT_CONTRACT_BY_ID, (current.contract_id,)).fetchone()
                if row is None:
                    raise ContractNotFoundError("Authoritative Recovery Contract was not found.")
                authoritative = self._decode_row(row)
                self._verify_related_state(connection, authoritative)
                if authoritative.state != current.state or authoritative.state_version != current.state_version:
                    raise ContractConflictError("Recovery Contract compare-and-set failed.")
                if updated.state in _RESERVATION_STATES and current.state not in _RESERVATION_STATES:
                    connection.execute(
                        "INSERT INTO target_reservations VALUES (?, ?)",
                        (updated.target_identity_digest, updated.contract_id),
                    )
                elif updated.state not in _RESERVATION_STATES and current.state in _RESERVATION_STATES:
                    connection.execute("DELETE FROM target_reservations WHERE contract_id = ?", (updated.contract_id,))
                cursor = connection.execute(
                    """UPDATE contracts
                       SET state = ?, state_version = ?, payload = ?, mac = ?
                       WHERE contract_id = ? AND state = ? AND state_version = ?""",
                    (
                        updated.state.value,
                        updated.state_version,
                        payload,
                        self._mac(payload),
                        updated.contract_id,
                        current.state.value,
                        current.state_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ContractConflictError("Recovery Contract compare-and-set failed.")
                self._insert_audit(connection, updated, event_type, previous_state=current.state)
                if self._rate_policy is not None and is_cooldown_state(updated.state):
                    self._rate_policy.record_terminal(
                        connection, target_identity_digest=updated.target_identity_digest, now=self._now()
                    )
                self._invoke_fault("after_record_write")
                self._invoke_fault("before_commit")
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ContractConflictError("Canonical target is already reserved by another operation.") from exc
            except Exception:
                connection.rollback()
                raise
        self._invoke_fault("after_commit")
        return updated

    def reconcile_interrupted(self) -> tuple[RecoveryContract, ...]:
        reconciled: list[RecoveryContract] = []
        for current in self.interrupted():
            reconciled.append(
                self.transition(
                    current.contract_id,
                    expected_state=current.state,
                    expected_version=current.state_version,
                    target_state=RecoveryState.RECONCILIATION,
                )
            )
        return tuple(reconciled)

    def interrupted(self) -> tuple[RecoveryContract, ...]:
        with self._connect() as connection:
            rows = connection.execute(_SELECT_ALL_CONTRACTS).fetchall()
            contracts = tuple(self._decode_row(row) for row in rows)
            for contract in contracts:
                self._verify_related_state(connection, contract)
            return tuple(contract for contract in contracts if contract.state in _INTERRUPTED_STATES)

    def audit_events(self, contract_id: str) -> tuple[dict[str, object], ...]:
        with self._connect() as connection:
            row = connection.execute(_SELECT_CONTRACT_BY_ID, (contract_id,)).fetchone()
            if row is None:
                raise ContractNotFoundError("Authoritative Recovery Contract was not found.")
            contract = self._decode_row(row)
            self._verify_reservation(connection, contract)
            rows = self._verified_audit_rows(connection, contract)
        return tuple(
            {
                "event_type": row[1],
                "previous_state": row[2],
                "current_state": row[3],
                "state_version": row[4],
                "recorded_at": row[5],
            }
            for row in rows
        )

    def _insert_audit(
        self,
        connection: sqlite3.Connection,
        contract: RecoveryContract,
        event_type: str,
        *,
        previous_state: RecoveryState | None,
    ) -> None:
        recorded_at = self._now().isoformat()
        previous = previous_state.value if previous_state else None
        current = contract.state.value
        connection.execute(
            """INSERT INTO audit_events(
                   contract_id, event_type, previous_state, current_state, state_version, recorded_at, mac
               ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                contract.contract_id,
                event_type,
                previous,
                current,
                contract.state_version,
                recorded_at,
                self._audit_mac(
                    contract_id=contract.contract_id,
                    event_type=event_type,
                    previous_state=previous,
                    current_state=current,
                    state_version=contract.state_version,
                    recorded_at=recorded_at,
                ),
            ),
        )
