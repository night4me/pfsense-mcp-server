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
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from pfsense_mcp.capabilities import Capability

from .contract import ProtectedArtifact, RecoveryContract
from .errors import (
    ContractConflictError,
    ContractIntegrityError,
    ContractNotFoundError,
    ContractValidationError,
)
from .state_machine import RecoveryState, require_transition

_SCHEMA_VERSION = 1
_ACQUISITION_STATES = frozenset({RecoveryState.EXECUTING, RecoveryState.ROLLING_BACK})
_INTERRUPTED_STATES = frozenset({RecoveryState.EXECUTING, RecoveryState.ROLLING_BACK})
FaultHook = Callable[[str], None]
_SELECT_CONTRACT_BY_ID = (
    "SELECT payload, mac, contract_id, operation_id, idempotency_key, "
    "target_identity_digest, state, state_version FROM contracts WHERE contract_id = ?"
)
_SELECT_ALL_CONTRACTS = (
    "SELECT payload, mac, contract_id, operation_id, idempotency_key, "
    "target_identity_digest, state, state_version FROM contracts ORDER BY contract_id"
)


def _artifact_to_dict(artifact: ProtectedArtifact) -> dict[str, str]:
    return {
        "algorithm": artifact.algorithm,
        "ciphertext": base64.b64encode(artifact.ciphertext).decode("ascii"),
        "key_id": artifact.key_id,
    }


def _artifact_from_dict(value: object) -> ProtectedArtifact:
    if not isinstance(value, dict) or set(value) != {"algorithm", "ciphertext", "key_id"}:
        raise ContractIntegrityError("Stored protected artifact is invalid.")
    try:
        return ProtectedArtifact(
            algorithm=str(value["algorithm"]),
            ciphertext=base64.b64decode(str(value["ciphertext"]), validate=True),
            key_id=str(value["key_id"]),
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
        value = json.loads(payload)
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
    except (KeyError, TypeError, ValueError, ContractValidationError) as exc:
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
    ) -> None:
        if len(integrity_key) < 32:
            raise ContractValidationError("Recovery store integrity key must be at least 32 bytes.")
        if not store_id or len(store_id) > 128:
            raise ContractValidationError("Recovery store identifier is invalid.")
        self._path = path
        self._integrity_key = bytes(integrity_key)
        self._store_id = store_id
        self._fault_hook = fault_hook
        self._prepare_path()
        self._initialize_schema()

    def _prepare_path(self) -> None:
        parent = self._path.parent
        parent_info = parent.lstat()
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
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self._path, flags, 0o600)
        os.close(fd)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

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
                    contract_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    previous_state TEXT,
                    current_state TEXT NOT NULL,
                    state_version INTEGER NOT NULL,
                    recorded_at TEXT NOT NULL
                );
                """
            )
            existing = dict(connection.execute("SELECT key, value FROM metadata"))
            expected = {"schema_version": str(_SCHEMA_VERSION), "store_id": self._store_id}
            if existing and existing != expected:
                raise ContractIntegrityError("Recovery store metadata does not match this build or store identity.")
            if not existing:
                connection.executemany("INSERT INTO metadata(key, value) VALUES (?, ?)", expected.items())
        os.chmod(self._path, 0o600)

    def _mac(self, payload: bytes) -> str:
        return hmac.new(self._integrity_key, self._store_id.encode() + b"\0" + payload, hashlib.sha256).hexdigest()

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

    def _invoke_fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    def create(self, contract: RecoveryContract) -> None:
        if contract.state not in {RecoveryState.PREPARING, RecoveryState.PREPARED} or contract.state_version != 0:
            raise ContractValidationError("New Recovery Contract must start at version zero in a preparation state.")
        payload = _contract_payload(contract)
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
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
        return contract

    def confirm(
        self, contract_id: str, *, actor_id: str, confirmed_at: datetime, expected_version: int
    ) -> RecoveryContract:
        current = self.load(contract_id)
        if current.state_version != expected_version:
            raise ContractConflictError("Recovery Contract version changed before confirmation.")
        confirmed = current.with_confirmation(actor_id=actor_id, confirmed_at=confirmed_at)
        return self._replace(current, confirmed, event_type="contract_confirmed")

    def transition(
        self,
        contract_id: str,
        *,
        expected_state: RecoveryState,
        expected_version: int,
        target_state: RecoveryState,
        manual: bool = False,
        now: datetime | None = None,
    ) -> RecoveryContract:
        require_transition(expected_state, target_state, manual=manual)
        current = self.load(contract_id)
        if current.state != expected_state or current.state_version != expected_version:
            raise ContractConflictError("Recovery Contract state changed before atomic transition.")
        instant = now if now is not None else datetime.now(timezone.utc)
        if target_state == RecoveryState.EXECUTING:
            if not current.is_confirmed or current.is_expired(now=instant):
                raise ContractConflictError("Recovery Contract is unconfirmed or expired.")
        updated = replace(current, state=target_state, state_version=current.state_version + 1)
        return self._replace(current, updated, event_type="state_transition")

    def _replace(self, current: RecoveryContract, updated: RecoveryContract, *, event_type: str) -> RecoveryContract:
        payload = _contract_payload(updated)
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(_SELECT_CONTRACT_BY_ID, (current.contract_id,)).fetchone()
                if row is None:
                    raise ContractNotFoundError("Authoritative Recovery Contract was not found.")
                authoritative = self._decode_row(row)
                if authoritative.state != current.state or authoritative.state_version != current.state_version:
                    raise ContractConflictError("Recovery Contract compare-and-set failed.")
                if updated.state in _ACQUISITION_STATES:
                    connection.execute(
                        "INSERT INTO target_reservations VALUES (?, ?)",
                        (updated.target_identity_digest, updated.contract_id),
                    )
                else:
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
        contracts = (self._decode_row(row) for row in rows)
        return tuple(contract for contract in contracts if contract.state in _INTERRUPTED_STATES)

    def audit_events(self, contract_id: str) -> tuple[dict[str, object], ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT event_type, previous_state, current_state, state_version, recorded_at
                   FROM audit_events WHERE contract_id = ? ORDER BY sequence""",
                (contract_id,),
            ).fetchall()
        return tuple(
            {
                "event_type": row[0],
                "previous_state": row[1],
                "current_state": row[2],
                "state_version": row[3],
                "recorded_at": row[4],
            }
            for row in rows
        )

    @staticmethod
    def _insert_audit(
        connection: sqlite3.Connection,
        contract: RecoveryContract,
        event_type: str,
        *,
        previous_state: RecoveryState | None,
    ) -> None:
        connection.execute(
            """INSERT INTO audit_events(
                   contract_id, event_type, previous_state, current_state, state_version, recorded_at
               ) VALUES (?, ?, ?, ?, ?, ?)""",
            (
                contract.contract_id,
                event_type,
                previous_state.value if previous_state else None,
                contract.state.value,
                contract.state_version,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
