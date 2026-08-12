"""Immutable, digest-bound Recovery Contract record."""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from pfsense_mcp.capabilities import Capability

from .canonical import DigestPurpose, digest_value
from .errors import ContractBindingError, ContractValidationError
from .state_machine import RecoveryState

_HEX_64 = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
MAX_PROTECTED_ARTIFACT_BYTES = 1_048_576


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)


@dataclass(frozen=True)
class ProtectedArtifact:
    """Opaque protected data; encryption/decryption belongs to an external provider."""

    key_id: str
    algorithm: str
    ciphertext: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not isinstance(self.algorithm, str):
            raise ContractValidationError("Protected artifact metadata is invalid.")
        if not _IDENTIFIER.fullmatch(self.key_id) or not _IDENTIFIER.fullmatch(self.algorithm):
            raise ContractValidationError("Protected artifact metadata is invalid.")
        if not isinstance(self.ciphertext, bytes) or not self.ciphertext:
            raise ContractValidationError("Protected artifact ciphertext must be non-empty bytes.")
        if len(self.ciphertext) > MAX_PROTECTED_ARTIFACT_BYTES:
            raise ContractValidationError("Protected artifact ciphertext exceeds the safety limit.")


def derive_idempotency_key(
    *,
    capability: Capability,
    endpoint_symbol: str,
    http_method: str,
    target_identity_digest: str,
    target_fingerprint: str,
    intent_digest: str,
    snapshot_digest: str,
    rollback_plan_version: str,
) -> str:
    context = (capability.name, endpoint_symbol, http_method)
    return digest_value(
        DigestPurpose.IDEMPOTENCY,
        {
            "intent_digest": intent_digest,
            "rollback_plan_version": rollback_plan_version,
            "snapshot_digest": snapshot_digest,
            "target_fingerprint": target_fingerprint,
            "target_identity_digest": target_identity_digest,
        },
        context=context,
    )


@dataclass(frozen=True)
class RecoveryContract:
    contract_id: str
    operation_id: str
    idempotency_key: str
    capability: Capability
    endpoint_symbol: str
    http_method: str
    target_identity_digest: str
    target_fingerprint: str
    intent_digest: str
    snapshot_digest: str
    rollback_plan_version: str
    created_at: datetime
    expires_at: datetime
    state: RecoveryState
    state_version: int
    protected_target_identity: ProtectedArtifact
    protected_intent: ProtectedArtifact
    protected_snapshot: ProtectedArtifact
    confirmation_digest: str | None = None
    confirmed_at: datetime | None = None
    verified_target_fingerprint: str | None = None

    def __post_init__(self) -> None:
        identifiers = (self.contract_id, self.operation_id, self.endpoint_symbol, self.rollback_plan_version)
        if not all(isinstance(value, str) and _IDENTIFIER.fullmatch(value) for value in identifiers):
            raise ContractValidationError("Recovery Contract identifier is invalid.")
        if not isinstance(self.capability, Capability) or not self.capability.name.endswith("_WRITE"):
            raise ContractValidationError("Recovery Contract capability must be a WRITE capability.")
        if not isinstance(self.http_method, str) or self.http_method not in _MUTATING_METHODS:
            raise ContractValidationError("Recovery Contract HTTP method is not mutating and allow-listed.")
        digests = (
            self.idempotency_key,
            self.target_identity_digest,
            self.target_fingerprint,
            self.intent_digest,
            self.snapshot_digest,
        )
        if not all(isinstance(value, str) and _HEX_64.fullmatch(value) for value in digests):
            raise ContractValidationError("Recovery Contract digest is invalid.")
        if self.confirmation_digest is not None and (
            not isinstance(self.confirmation_digest, str) or not _HEX_64.fullmatch(self.confirmation_digest)
        ):
            raise ContractValidationError("Recovery Contract confirmation digest is invalid.")
        if self.verified_target_fingerprint is not None and (
            not isinstance(self.verified_target_fingerprint, str)
            or not _HEX_64.fullmatch(self.verified_target_fingerprint)
        ):
            raise ContractValidationError("Verified target fingerprint is invalid.")
        forbids_verified_fingerprint = self.state in {
            RecoveryState.PREPARING,
            RecoveryState.PREPARED,
            RecoveryState.EXECUTING,
        }
        requires_verified_fingerprint = self.state in {RecoveryState.VERIFIED, RecoveryState.ROLLING_BACK}
        if (forbids_verified_fingerprint and self.verified_target_fingerprint is not None) or (
            requires_verified_fingerprint and self.verified_target_fingerprint is None
        ):
            raise ContractValidationError("Recovery Contract state and verified target fingerprint are inconsistent.")
        if not isinstance(self.created_at, datetime) or not isinstance(self.expires_at, datetime):
            raise ContractValidationError("Recovery Contract timestamps must be UTC.")
        if not _is_utc(self.created_at) or not _is_utc(self.expires_at):
            raise ContractValidationError("Recovery Contract timestamps must be UTC.")
        if self.expires_at <= self.created_at:
            raise ContractValidationError("Recovery Contract expiry must follow creation.")
        if not isinstance(self.state, RecoveryState):
            raise ContractValidationError("Recovery Contract state is invalid.")
        if type(self.state_version) is not int or self.state_version < 0:
            raise ContractValidationError("Recovery Contract state version is invalid.")
        if (self.confirmation_digest is None) != (self.confirmed_at is None):
            raise ContractValidationError("Confirmation digest and timestamp must be set together.")
        if self.confirmed_at is not None and (
            not _is_utc(self.confirmed_at) or not self.created_at <= self.confirmed_at < self.expires_at
        ):
            raise ContractValidationError("Recovery Contract confirmation timestamp is outside its validity window.")
        expected_idempotency_key = derive_idempotency_key(
            capability=self.capability,
            endpoint_symbol=self.endpoint_symbol,
            http_method=self.http_method,
            target_identity_digest=self.target_identity_digest,
            target_fingerprint=self.target_fingerprint,
            intent_digest=self.intent_digest,
            snapshot_digest=self.snapshot_digest,
            rollback_plan_version=self.rollback_plan_version,
        )
        if not hmac.compare_digest(self.idempotency_key, expected_idempotency_key):
            raise ContractValidationError("Recovery Contract idempotency binding is invalid.")

    @property
    def is_confirmed(self) -> bool:
        return self.confirmation_digest is not None

    def is_expired(self, *, now: datetime | None = None) -> bool:
        current = now if now is not None else datetime.now(timezone.utc)
        if not _is_utc(current):
            raise ContractValidationError("Recovery Contract comparison time must be UTC.")
        return current >= self.expires_at

    def with_confirmation(
        self, *, authority_id: str, evidence_digest: str, confirmed_at: datetime
    ) -> "RecoveryContract":
        if self.state != RecoveryState.PREPARED or self.is_confirmed:
            raise ContractBindingError("Recovery Contract cannot accept this confirmation.")
        if not isinstance(authority_id, str) or not _IDENTIFIER.fullmatch(authority_id):
            raise ContractValidationError("Confirmation authority identifier is invalid.")
        if not isinstance(evidence_digest, str) or not _HEX_64.fullmatch(evidence_digest):
            raise ContractValidationError("Confirmation evidence digest is invalid.")
        digest = digest_value(
            DigestPurpose.CONFIRMATION,
            {
                "authority_id": authority_id,
                "contract_id": self.contract_id,
                "evidence_digest": evidence_digest,
                "expires_at": self.expires_at.isoformat(),
                "intent_digest": self.intent_digest,
                "operation_id": self.operation_id,
                "target_fingerprint": self.target_fingerprint,
                "target_identity_digest": self.target_identity_digest,
            },
        )
        return replace(
            self,
            confirmation_digest=digest,
            confirmed_at=confirmed_at,
            state_version=self.state_version + 1,
        )

    def verify_bindings(
        self,
        *,
        capability: Capability,
        endpoint_symbol: str,
        http_method: str,
        target_identity: object,
        target_precondition: object,
        normalized_intent: object,
    ) -> None:
        context = (self.capability.name, self.endpoint_symbol, self.http_method)
        supplied = (
            capability,
            endpoint_symbol,
            http_method,
            digest_value(DigestPurpose.TARGET_IDENTITY, target_identity, context=(self.capability.name,)),
            digest_value(DigestPurpose.TARGET_FINGERPRINT, target_precondition, context=context),
            digest_value(DigestPurpose.INTENT, normalized_intent, context=context),
        )
        expected = (
            self.capability,
            self.endpoint_symbol,
            self.http_method,
            self.target_identity_digest,
            self.target_fingerprint,
            self.intent_digest,
        )
        if supplied != expected:
            raise ContractBindingError("Execution request does not match the authoritative Recovery Contract.")
