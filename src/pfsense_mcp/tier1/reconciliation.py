"""Authenticated reconciliation resolution for inert Tier 1 contracts.

Not constructed by production. `RECONCILIATION` is a manual-only state in
`state_machine.py` with no resolver anywhere in the codebase before this
module -- a contract that enters it has, until now, stayed there
indefinitely. This module defines the one authenticated path that will
resolve it: an operator's signed, structured declaration of the true
real-world outcome, never an automatic inference from HTTP status,
timing, or response presence. See
docs/tier1/specs/reconciliation_authority.md and docs/adr/ADR-013.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol

from .canonical import DigestPurpose, digest_value
from .errors import ConfirmationError
from .state_machine import RecoveryState

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
MAX_RECONCILIATION_PROOF_BYTES = 65_536


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)


class ReconciliationOutcome(str, Enum):
    CONFIRMED_APPLIED = "confirmed_applied"
    CONFIRMED_NOT_APPLIED = "confirmed_not_applied"
    CONFIRMED_ROLLBACK_APPLIED = "confirmed_rollback_applied"
    CONFIRMED_ROLLBACK_NOT_APPLIED = "confirmed_rollback_not_applied"


#: The RecoveryState a resolved contract moves to for each declared
#: outcome. There is no "unknown"/"retry" outcome by design -- an
#: operator who cannot determine the true outcome does not resolve the
#: contract; it remains in RECONCILIATION until they can.
OUTCOME_TARGET_STATE: dict[ReconciliationOutcome, RecoveryState] = {
    ReconciliationOutcome.CONFIRMED_APPLIED: RecoveryState.VERIFIED,
    ReconciliationOutcome.CONFIRMED_NOT_APPLIED: RecoveryState.FAILED,
    ReconciliationOutcome.CONFIRMED_ROLLBACK_APPLIED: RecoveryState.ROLLED_BACK,
    ReconciliationOutcome.CONFIRMED_ROLLBACK_NOT_APPLIED: RecoveryState.ROLLBACK_FAILED,
}


@dataclass(frozen=True)
class ReconciliationEvidence:
    """Opaque proof plus the exact immutable facts an operator attests
    to when resolving a RECONCILIATION contract. Domain-separated from
    ConfirmationEvidence via DigestPurpose.RECONCILIATION (see
    evidence_digest) so a confirmation signature can never be replayed
    as a reconciliation signature or vice versa."""

    authority_id: str
    algorithm: str
    contract_id: str
    operation_id: str
    observed_state_version: int
    outcome: ReconciliationOutcome
    issued_at: datetime
    proof: bytes
    verified_target_fingerprint: str | None = None
    verified_lifecycle_locator: int | None = None

    def __post_init__(self) -> None:
        tokens = (self.authority_id, self.algorithm, self.contract_id, self.operation_id)
        if not all(isinstance(value, str) and _SAFE_TOKEN.fullmatch(value) for value in tokens):
            raise ConfirmationError("Reconciliation evidence metadata is invalid.")
        if (
            not isinstance(self.observed_state_version, int)
            or isinstance(self.observed_state_version, bool)
            or self.observed_state_version < 0
        ):
            raise ConfirmationError("Reconciliation evidence state version is invalid.")
        if not isinstance(self.outcome, ReconciliationOutcome):
            raise ConfirmationError("Reconciliation evidence outcome is invalid.")
        if not isinstance(self.issued_at, datetime) or not _is_utc(self.issued_at):
            raise ConfirmationError("Reconciliation evidence timestamp must be UTC.")
        if not isinstance(self.proof, bytes) or not self.proof or len(self.proof) > MAX_RECONCILIATION_PROOF_BYTES:
            raise ConfirmationError("Reconciliation evidence proof is invalid or oversized.")
        applied = self.outcome is ReconciliationOutcome.CONFIRMED_APPLIED
        valid_fingerprint = isinstance(self.verified_target_fingerprint, str) and bool(
            _HEX_64.fullmatch(self.verified_target_fingerprint)
        )
        if (applied and not valid_fingerprint) or (not applied and self.verified_target_fingerprint is not None):
            raise ConfirmationError(
                "Confirmed-applied reconciliation evidence requires exactly one verified target fingerprint."
            )
        applied_outcome = self.outcome in {
            ReconciliationOutcome.CONFIRMED_APPLIED,
            ReconciliationOutcome.CONFIRMED_ROLLBACK_APPLIED,
        }
        valid_locator = (
            type(self.verified_lifecycle_locator) is int and 0 <= self.verified_lifecycle_locator <= 2_147_483_647
        )
        if (applied_outcome and not valid_locator) or (
            not applied_outcome and self.verified_lifecycle_locator is not None
        ):
            raise ConfirmationError("Applied reconciliation evidence requires exactly one verified lifecycle locator.")

    @property
    def evidence_digest(self) -> str:
        """Value-free audit binding for this resolution event -- computed
        only after verification succeeds, mirroring
        ConfirmationEvidence.evidence_digest's role (not used as a
        signature pre-image; see reconciliation_providers.signing_payload
        for what is actually signed)."""

        proof_digest = hashlib.sha256(self.proof).hexdigest()
        return digest_value(
            DigestPurpose.RECONCILIATION,
            {
                "authority_id": self.authority_id,
                "contract_id": self.contract_id,
                "issued_at": self.issued_at.isoformat(),
                "observed_state_version": self.observed_state_version,
                "operation_id": self.operation_id,
                "outcome": self.outcome.value,
                "proof_digest": proof_digest,
                "verified_target_fingerprint": self.verified_target_fingerprint,
                "verified_lifecycle_locator": self.verified_lifecycle_locator,
            },
        )

    def verify_bindings(
        self, *, contract_id: str, operation_id: str, state_version: int, lifecycle_locator: int
    ) -> None:
        if (
            self.contract_id != contract_id
            or self.operation_id != operation_id
            or self.observed_state_version != state_version
            or (self.verified_lifecycle_locator is not None and self.verified_lifecycle_locator != lifecycle_locator)
        ):
            raise ConfirmationError("Reconciliation evidence does not match the authoritative contract.")


class ReconciliationVerifier(Protocol):
    """Owner-selected authentication provider; no implementation is
    selected here -- see reconciliation_providers.py for the concrete
    Ed25519 provider."""

    def verify(self, evidence: ReconciliationEvidence) -> bool: ...
