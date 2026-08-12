"""LAB-T1-only pinned reconciliation verification and evidence files."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from pfsense_mcp.secure_file import open_nofollow, validate_descriptor
from pfsense_mcp.tier1.contract import RecoveryContract
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority
from pfsense_mcp.tier1.reconciliation import ReconciliationEvidence, ReconciliationOutcome
from pfsense_mcp.tier1.reconciliation_providers import ACCEPTED_ALGORITHM, Ed25519ReconciliationVerifier
from pfsense_mcp.tier1.state_machine import RecoveryState

LAB_RECONCILIATION_AUTHORITY_ID = "lab-t1-reconciliation-owner-v1"
_MAX_FILE = 16 * 1024


class LabReconciliationError(RuntimeError):
    pass


@dataclass(frozen=True)
class LabReconciliationPaths:
    public_key_file: Path
    pending_file: Path
    signed_file: Path
    authority_id: str = LAB_RECONCILIATION_AUTHORITY_ID

    def __post_init__(self) -> None:
        if self.authority_id != LAB_RECONCILIATION_AUTHORITY_ID:
            raise LabReconciliationError("LAB-T1 reconciliation authority identifier is not pinned")
        if len({self.public_key_file, self.pending_file, self.signed_file}) != 3:
            raise LabReconciliationError("LAB-T1 reconciliation file paths must be distinct")


@dataclass(frozen=True)
class PendingReconciliation:
    contract_id: str
    operation_id: str
    observed_state_version: int
    uncertainty_origin: RecoveryState
    issued_at: datetime
    verified_target_fingerprint: str | None
    verified_lifecycle_locator: int | None

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value for value in (self.contract_id, self.operation_id)):
            raise LabReconciliationError("pending reconciliation identity is malformed")
        if type(self.observed_state_version) is not int or self.observed_state_version < 0:
            raise LabReconciliationError("pending reconciliation state version is malformed")
        if self.uncertainty_origin not in {RecoveryState.EXECUTING, RecoveryState.ROLLING_BACK}:
            raise LabReconciliationError("reconciliation uncertainty origin is invalid")
        if (
            not isinstance(self.issued_at, datetime)
            or self.issued_at.tzinfo is None
            or self.issued_at.utcoffset() != timezone.utc.utcoffset(self.issued_at)
        ):
            raise LabReconciliationError("pending reconciliation timestamp must be UTC")
        if self.verified_target_fingerprint is not None and (
            not isinstance(self.verified_target_fingerprint, str)
            or len(self.verified_target_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in self.verified_target_fingerprint)
        ):
            raise LabReconciliationError("pending reconciliation fingerprint is malformed")
        if self.verified_lifecycle_locator is not None and (
            type(self.verified_lifecycle_locator) is not int
            or not 0 <= self.verified_lifecycle_locator <= 2_147_483_647
        ):
            raise LabReconciliationError("pending reconciliation locator is malformed")
        if self.uncertainty_origin is RecoveryState.ROLLING_BACK and self.verified_target_fingerprint is not None:
            raise LabReconciliationError("rollback reconciliation cannot carry a forward fingerprint")
        if self.verified_target_fingerprint is not None and self.verified_lifecycle_locator is None:
            raise LabReconciliationError("applied reconciliation binding is incomplete")

    @classmethod
    def from_contract(
        cls,
        contract: RecoveryContract,
        *,
        issued_at: datetime,
        uncertainty_origin: RecoveryState,
        verified_target_fingerprint: str | None,
        verified_lifecycle_locator: int | None,
    ) -> "PendingReconciliation":
        if contract.state is not RecoveryState.RECONCILIATION:
            raise LabReconciliationError("operation is not in reconciliation")
        if uncertainty_origin not in {RecoveryState.EXECUTING, RecoveryState.ROLLING_BACK}:
            raise LabReconciliationError("reconciliation uncertainty origin is invalid")
        return cls(
            contract.contract_id,
            contract.operation_id,
            contract.state_version,
            uncertainty_origin,
            issued_at,
            verified_target_fingerprint,
            verified_lifecycle_locator,
        )

    def evidence(self, outcome: ReconciliationOutcome, proof: bytes) -> ReconciliationEvidence:
        _require_outcome_for_origin(self.uncertainty_origin, outcome)
        applied = outcome is ReconciliationOutcome.CONFIRMED_APPLIED
        rollback_applied = outcome is ReconciliationOutcome.CONFIRMED_ROLLBACK_APPLIED
        return ReconciliationEvidence(
            authority_id=LAB_RECONCILIATION_AUTHORITY_ID,
            algorithm=ACCEPTED_ALGORITHM,
            contract_id=self.contract_id,
            operation_id=self.operation_id,
            observed_state_version=self.observed_state_version,
            outcome=outcome,
            issued_at=self.issued_at,
            proof=proof,
            verified_target_fingerprint=self.verified_target_fingerprint if applied else None,
            verified_lifecycle_locator=self.verified_lifecycle_locator if applied or rollback_applied else None,
        )


def _read_secure(path: Path) -> bytes:
    fd = open_nofollow(path, on_error=LabReconciliationError)
    try:
        validate_descriptor(path, fd, max_bytes=_MAX_FILE, on_error=LabReconciliationError)
        return os.read(fd, _MAX_FILE + 1)
    finally:
        os.close(fd)


def load_verifier(paths: LabReconciliationPaths) -> Ed25519ReconciliationVerifier:
    public_key = _read_secure(paths.public_key_file)
    if len(public_key) != 32:
        raise LabReconciliationError("LAB-T1 reconciliation public key is malformed")
    return Ed25519ReconciliationVerifier((PinnedAuthority(paths.authority_id, public_key),))


def _pending_payload(pending: PendingReconciliation) -> dict[str, object]:
    return {
        "schema_version": 2,
        "authority_id": LAB_RECONCILIATION_AUTHORITY_ID,
        "algorithm": ACCEPTED_ALGORITHM,
        "contract_id": pending.contract_id,
        "operation_id": pending.operation_id,
        "observed_state_version": pending.observed_state_version,
        "uncertainty_origin": pending.uncertainty_origin.value,
        "issued_at": pending.issued_at.isoformat(),
        "verified_target_fingerprint": pending.verified_target_fingerprint,
        "verified_lifecycle_locator": pending.verified_lifecycle_locator,
    }


def _pending_mac(pending: PendingReconciliation, integrity_key: bytes) -> str:
    if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
        raise LabReconciliationError("LAB-T1 reconciliation integrity key is invalid")
    canonical = json.dumps(_pending_payload(pending), sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(integrity_key, b"lab-t1-reconciliation-pending-v2\0" + canonical, hashlib.sha256).hexdigest()


def pending_to_bytes(pending: PendingReconciliation, *, integrity_key: bytes) -> bytes:
    payload = _pending_payload(pending)
    payload["integrity_mac"] = _pending_mac(pending, integrity_key)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def load_pending(paths: LabReconciliationPaths, *, integrity_key: bytes) -> PendingReconciliation:
    try:
        raw = json.loads(_read_secure(paths.pending_file))
        expected = {
            "schema_version",
            "authority_id",
            "algorithm",
            "contract_id",
            "operation_id",
            "observed_state_version",
            "uncertainty_origin",
            "issued_at",
            "verified_target_fingerprint",
            "verified_lifecycle_locator",
            "integrity_mac",
        }
        if set(raw) != expected or raw["schema_version"] != 2:
            raise ValueError
        if raw["authority_id"] != LAB_RECONCILIATION_AUTHORITY_ID or raw["algorithm"] != ACCEPTED_ALGORITHM:
            raise ValueError
        issued = datetime.fromisoformat(raw["issued_at"])
        if issued.tzinfo is None or issued.utcoffset() != timezone.utc.utcoffset(issued):
            raise ValueError
        pending = PendingReconciliation(
            raw["contract_id"],
            raw["operation_id"],
            raw["observed_state_version"],
            RecoveryState(raw["uncertainty_origin"]),
            issued,
            raw["verified_target_fingerprint"],
            raw["verified_lifecycle_locator"],
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        raise LabReconciliationError("pending LAB-T1 reconciliation evidence is malformed") from None

    if not hmac.compare_digest(raw["integrity_mac"], _pending_mac(pending, integrity_key)):
        raise LabReconciliationError("pending LAB-T1 reconciliation evidence failed integrity verification")
    return pending


def signed_to_bytes(evidence: ReconciliationEvidence) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "authority_id": evidence.authority_id,
            "algorithm": evidence.algorithm,
            "contract_id": evidence.contract_id,
            "operation_id": evidence.operation_id,
            "observed_state_version": evidence.observed_state_version,
            "outcome": evidence.outcome.value,
            "issued_at": evidence.issued_at.isoformat(),
            "verified_target_fingerprint": evidence.verified_target_fingerprint,
            "verified_lifecycle_locator": evidence.verified_lifecycle_locator,
            "proof": base64.b64encode(evidence.proof).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def load_signed_evidence(paths: LabReconciliationPaths) -> ReconciliationEvidence:
    try:
        raw = json.loads(_read_secure(paths.signed_file))
        expected = {
            "schema_version",
            "authority_id",
            "algorithm",
            "contract_id",
            "operation_id",
            "observed_state_version",
            "outcome",
            "issued_at",
            "verified_target_fingerprint",
            "verified_lifecycle_locator",
            "proof",
        }
        if set(raw) != expected or raw["schema_version"] != 1:
            raise ValueError
        issued = datetime.fromisoformat(raw["issued_at"])
        proof = base64.b64decode(raw["proof"], validate=True)
        return ReconciliationEvidence(
            authority_id=raw["authority_id"],
            algorithm=raw["algorithm"],
            contract_id=raw["contract_id"],
            operation_id=raw["operation_id"],
            observed_state_version=raw["observed_state_version"],
            outcome=ReconciliationOutcome(raw["outcome"]),
            issued_at=issued,
            proof=proof,
            verified_target_fingerprint=raw["verified_target_fingerprint"],
            verified_lifecycle_locator=raw["verified_lifecycle_locator"],
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        raise LabReconciliationError("signed LAB-T1 reconciliation evidence is malformed") from None


def write_secure_new(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        raise LabReconciliationError("secure evidence output could not be created") from None
    complete = False
    try:
        offset = 0
        while offset < len(value):
            written = os.write(fd, value[offset:])
            if written <= 0:
                raise LabReconciliationError("secure evidence output could not be written")
            offset += written
        os.fsync(fd)
        complete = True
    finally:
        os.close(fd)
        if not complete:
            with suppress(OSError):
                path.unlink()


ContractLoader = Callable[[str], RecoveryContract]
AuditLoader = Callable[[str], tuple[dict[str, object], ...]]


class ReconciliationStore(Protocol):
    def load(self, contract_id: str) -> RecoveryContract: ...

    def audit_events(self, contract_id: str) -> tuple[dict[str, object], ...]: ...

    def resolve_reconciliation(self, contract_id: str, *, evidence: ReconciliationEvidence) -> RecoveryContract: ...


def _require_outcome_for_origin(origin: RecoveryState, outcome: ReconciliationOutcome) -> None:
    allowed = {
        RecoveryState.EXECUTING: {
            ReconciliationOutcome.CONFIRMED_APPLIED,
            ReconciliationOutcome.CONFIRMED_NOT_APPLIED,
        },
        RecoveryState.ROLLING_BACK: {
            ReconciliationOutcome.CONFIRMED_ROLLBACK_APPLIED,
            ReconciliationOutcome.CONFIRMED_ROLLBACK_NOT_APPLIED,
        },
    }
    if outcome not in allowed.get(origin, set()):
        raise LabReconciliationError("reconciliation outcome is incompatible with the persisted uncertainty origin")


def validate_pending_against_store(
    pending: PendingReconciliation, loader: ContractLoader, audit_loader: AuditLoader
) -> RecoveryContract:
    contract = loader(pending.contract_id)
    if (
        contract.state is not RecoveryState.RECONCILIATION
        or contract.operation_id != pending.operation_id
        or contract.state_version != pending.observed_state_version
        or (
            pending.verified_lifecycle_locator is not None
            and pending.verified_lifecycle_locator != contract.lifecycle_locator
        )
    ):
        raise LabReconciliationError("pending evidence no longer matches the persisted operation")
    events = audit_loader(contract.contract_id)
    if not events or events[-1].get("previous_state") != pending.uncertainty_origin.value:
        raise LabReconciliationError("pending evidence does not match the persisted uncertainty origin")
    return contract


def emit_pending_evidence(
    paths: LabReconciliationPaths,
    store: ReconciliationStore,
    *,
    contract_id: str,
    issued_at: datetime,
    verified_target_fingerprint: str | None,
    verified_lifecycle_locator: int | None,
    integrity_key: bytes,
) -> PendingReconciliation:
    """Persist one authenticated unsigned request from authoritative store state."""

    contract = store.load(contract_id)
    events = store.audit_events(contract_id)
    if not events:
        raise LabReconciliationError("persisted reconciliation history is missing")
    try:
        origin = RecoveryState(events[-1]["previous_state"])
    except (KeyError, TypeError, ValueError):
        raise LabReconciliationError("persisted reconciliation origin is malformed") from None
    pending = PendingReconciliation.from_contract(
        contract,
        issued_at=issued_at,
        uncertainty_origin=origin,
        verified_target_fingerprint=verified_target_fingerprint,
        verified_lifecycle_locator=verified_lifecycle_locator,
    )
    validate_pending_against_store(pending, store.load, store.audit_events)
    write_secure_new(paths.pending_file, pending_to_bytes(pending, integrity_key=integrity_key))
    return pending


def resolve_signed_evidence(paths: LabReconciliationPaths, store: ReconciliationStore) -> RecoveryContract:
    """Consume one pre-existing signed artifact through the pinned verifier/store."""

    evidence = load_signed_evidence(paths)
    contract = store.load(evidence.contract_id)
    events = store.audit_events(evidence.contract_id)
    if not events:
        raise LabReconciliationError("persisted reconciliation history is missing")
    try:
        origin = RecoveryState(events[-1]["previous_state"])
    except (KeyError, TypeError, ValueError):
        raise LabReconciliationError("persisted reconciliation origin is malformed") from None
    _require_outcome_for_origin(origin, evidence.outcome)
    if contract.state is not RecoveryState.RECONCILIATION:
        raise LabReconciliationError("operation is not in reconciliation")
    return store.resolve_reconciliation(contract.contract_id, evidence=evidence)
