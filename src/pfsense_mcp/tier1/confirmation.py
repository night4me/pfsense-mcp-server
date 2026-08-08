"""Provider-neutral owner confirmation evidence for inert Tier 1 contracts."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from .canonical import DigestPurpose, digest_value
from .contract import RecoveryContract
from .errors import ConfirmationError

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
MAX_CONFIRMATION_PROOF_BYTES = 65_536


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)


@dataclass(frozen=True)
class ConfirmationEvidence:
    """Opaque proof plus the exact immutable facts an authority attests."""

    authority_id: str
    algorithm: str
    nonce: str
    contract_id: str
    operation_id: str
    target_identity_digest: str
    target_fingerprint: str
    intent_digest: str
    expires_at: datetime
    issued_at: datetime
    proof: bytes

    def __post_init__(self) -> None:
        tokens = (self.authority_id, self.algorithm, self.nonce, self.contract_id, self.operation_id)
        if not all(isinstance(value, str) and _SAFE_TOKEN.fullmatch(value) for value in tokens):
            raise ConfirmationError("Confirmation evidence metadata is invalid.")
        digests = (self.target_identity_digest, self.target_fingerprint, self.intent_digest)
        if not all(isinstance(value, str) and _HEX_64.fullmatch(value) for value in digests):
            raise ConfirmationError("Confirmation evidence digest is invalid.")
        if not isinstance(self.expires_at, datetime) or not isinstance(self.issued_at, datetime):
            raise ConfirmationError("Confirmation evidence timestamps must be UTC.")
        if not _is_utc(self.expires_at) or not _is_utc(self.issued_at) or self.issued_at >= self.expires_at:
            raise ConfirmationError("Confirmation evidence validity window is invalid.")
        if not isinstance(self.proof, bytes) or not self.proof or len(self.proof) > MAX_CONFIRMATION_PROOF_BYTES:
            raise ConfirmationError("Confirmation evidence proof is invalid or oversized.")

    @property
    def proof_digest(self) -> str:
        return hashlib.sha256(self.proof).hexdigest()

    @property
    def evidence_digest(self) -> str:
        return digest_value(
            DigestPurpose.CONFIRMATION,
            {
                "algorithm": self.algorithm,
                "authority_id": self.authority_id,
                "contract_id": self.contract_id,
                "expires_at": self.expires_at.isoformat(),
                "intent_digest": self.intent_digest,
                "nonce": self.nonce,
                "operation_id": self.operation_id,
                "proof_digest": self.proof_digest,
                "target_fingerprint": self.target_fingerprint,
                "target_identity_digest": self.target_identity_digest,
            },
        )

    def verify_bindings(self, contract: RecoveryContract) -> None:
        supplied = (
            self.contract_id,
            self.operation_id,
            self.target_identity_digest,
            self.target_fingerprint,
            self.intent_digest,
            self.expires_at,
        )
        expected = (
            contract.contract_id,
            contract.operation_id,
            contract.target_identity_digest,
            contract.target_fingerprint,
            contract.intent_digest,
            contract.expires_at,
        )
        matches = (
            hmac.compare_digest(left, right) if isinstance(left, str) and isinstance(right, str) else left == right
            for left, right in zip(supplied, expected, strict=True)
        )
        if not all(matches):
            raise ConfirmationError("Confirmation evidence does not match the authoritative contract.")


class ConfirmationVerifier(Protocol):
    """Owner-selected authentication provider; no implementation is selected here."""

    def verify(self, evidence: ConfirmationEvidence) -> bool: ...
