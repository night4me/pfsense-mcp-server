"""Immutable, digest-bound Recovery Contract record."""

from __future__ import annotations

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


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)


@dataclass(frozen=True)
class ProtectedArtifact:
    """Opaque protected data; encryption/decryption belongs to an external provider."""

    key_id: str
    algorithm: str
    ciphertext: bytes

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.key_id) or not _IDENTIFIER.fullmatch(self.algorithm):
            raise ContractValidationError("Protected artifact metadata is invalid.")
        if not self.ciphertext:
            raise ContractValidationError("Protected artifact ciphertext must not be empty.")


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

    def __post_init__(self) -> None:
        identifiers = (self.contract_id, self.operation_id, self.endpoint_symbol, self.rollback_plan_version)
        if not all(_IDENTIFIER.fullmatch(value) for value in identifiers):
            raise ContractValidationError("Recovery Contract identifier is invalid.")
        if not self.capability.name.endswith("_WRITE"):
            raise ContractValidationError("Recovery Contract capability must be a WRITE capability.")
        if self.http_method not in _MUTATING_METHODS:
            raise ContractValidationError("Recovery Contract HTTP method is not mutating and allow-listed.")
        digests = (
            self.idempotency_key,
            self.target_identity_digest,
            self.target_fingerprint,
            self.intent_digest,
            self.snapshot_digest,
        )
        if not all(_HEX_64.fullmatch(value) for value in digests):
            raise ContractValidationError("Recovery Contract digest is invalid.")
        if self.confirmation_digest is not None and not _HEX_64.fullmatch(self.confirmation_digest):
            raise ContractValidationError("Recovery Contract confirmation digest is invalid.")
        if not _is_utc(self.created_at) or not _is_utc(self.expires_at):
            raise ContractValidationError("Recovery Contract timestamps must be UTC.")
        if self.expires_at <= self.created_at:
            raise ContractValidationError("Recovery Contract expiry must follow creation.")
        if self.state_version < 0:
            raise ContractValidationError("Recovery Contract state version is invalid.")
        if (self.confirmation_digest is None) != (self.confirmed_at is None):
            raise ContractValidationError("Confirmation digest and timestamp must be set together.")
        if self.confirmed_at is not None:
            if not _is_utc(self.confirmed_at) or not self.created_at <= self.confirmed_at < self.expires_at:
                raise ContractValidationError(
                    "Recovery Contract confirmation timestamp is outside its validity window."
                )

    @property
    def is_confirmed(self) -> bool:
        return self.confirmation_digest is not None

    def is_expired(self, *, now: datetime | None = None) -> bool:
        current = now if now is not None else datetime.now(timezone.utc)
        if not _is_utc(current):
            raise ContractValidationError("Recovery Contract comparison time must be UTC.")
        return current >= self.expires_at

    def with_confirmation(self, *, actor_id: str, confirmed_at: datetime) -> "RecoveryContract":
        if self.state != RecoveryState.PREPARED or self.is_confirmed:
            raise ContractBindingError("Recovery Contract cannot accept this confirmation.")
        if not _IDENTIFIER.fullmatch(actor_id):
            raise ContractValidationError("Confirmation actor identifier is invalid.")
        digest = digest_value(
            DigestPurpose.CONFIRMATION,
            {
                "actor_id": actor_id,
                "contract_id": self.contract_id,
                "expires_at": self.expires_at.isoformat(),
                "intent_digest": self.intent_digest,
                "operation_id": self.operation_id,
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
        normalized_intent: object,
    ) -> None:
        context = (self.capability.name, self.endpoint_symbol, self.http_method)
        supplied = (
            capability,
            endpoint_symbol,
            http_method,
            digest_value(DigestPurpose.TARGET_IDENTITY, target_identity, context=(self.capability.name,)),
            digest_value(DigestPurpose.INTENT, normalized_intent, context=context),
        )
        expected = (
            self.capability,
            self.endpoint_symbol,
            self.http_method,
            self.target_identity_digest,
            self.intent_digest,
        )
        if supplied != expected:
            raise ContractBindingError("Execution request does not match the authoritative Recovery Contract.")
