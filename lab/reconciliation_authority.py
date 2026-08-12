"""LAB-T1-only pinned reconciliation verification and evidence files."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

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
    issued_at: datetime
    verified_target_fingerprint: str | None
    verified_lifecycle_locator: int | None

    @classmethod
    def from_contract(
        cls,
        contract: RecoveryContract,
        *,
        issued_at: datetime,
        verified_target_fingerprint: str | None,
        verified_lifecycle_locator: int | None,
    ) -> "PendingReconciliation":
        if contract.state is not RecoveryState.RECONCILIATION:
            raise LabReconciliationError("operation is not in reconciliation")
        return cls(
            contract.contract_id,
            contract.operation_id,
            contract.state_version,
            issued_at,
            verified_target_fingerprint,
            verified_lifecycle_locator,
        )

    def evidence(self, outcome: ReconciliationOutcome, proof: bytes) -> ReconciliationEvidence:
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


def pending_to_bytes(pending: PendingReconciliation) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "authority_id": LAB_RECONCILIATION_AUTHORITY_ID,
            "algorithm": ACCEPTED_ALGORITHM,
            "contract_id": pending.contract_id,
            "operation_id": pending.operation_id,
            "observed_state_version": pending.observed_state_version,
            "issued_at": pending.issued_at.isoformat(),
            "verified_target_fingerprint": pending.verified_target_fingerprint,
            "verified_lifecycle_locator": pending.verified_lifecycle_locator,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def load_pending(paths: LabReconciliationPaths) -> PendingReconciliation:
    try:
        raw = json.loads(_read_secure(paths.pending_file))
        expected = {
            "schema_version",
            "authority_id",
            "algorithm",
            "contract_id",
            "operation_id",
            "observed_state_version",
            "issued_at",
            "verified_target_fingerprint",
            "verified_lifecycle_locator",
        }
        if set(raw) != expected or raw["schema_version"] != 1:
            raise ValueError
        if raw["authority_id"] != LAB_RECONCILIATION_AUTHORITY_ID or raw["algorithm"] != ACCEPTED_ALGORITHM:
            raise ValueError
        issued = datetime.fromisoformat(raw["issued_at"])
        if issued.tzinfo is None or issued.utcoffset() != timezone.utc.utcoffset(issued):
            raise ValueError
        return PendingReconciliation(
            raw["contract_id"],
            raw["operation_id"],
            raw["observed_state_version"],
            issued,
            raw["verified_target_fingerprint"],
            raw["verified_lifecycle_locator"],
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        raise LabReconciliationError("pending LAB-T1 reconciliation evidence is malformed") from None


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
    try:
        offset = 0
        while offset < len(value):
            written = os.write(fd, value[offset:])
            if written <= 0:
                raise LabReconciliationError("secure evidence output could not be written")
            offset += written
    finally:
        os.close(fd)


ContractLoader = Callable[[str], RecoveryContract]


def validate_pending_against_store(pending: PendingReconciliation, loader: ContractLoader) -> RecoveryContract:
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
    return contract
