"""Concrete confirmation authority: detached Ed25519 signatures verified
against a pinned, owner-configured public key set.

Not constructed by production. Satisfies the `ConfirmationVerifier`
Protocol already defined and enforced in `confirmation.py`/`store.py`.
The private signing key never appears anywhere in this module or this
package -- only public keys are ever loaded. See
docs/tier1/specs/confirmation_authority.md and docs/adr/ADR-012 for the
full specification and the signing-side workflow this verifier pairs
with (built separately, outside `pfsense_mcp`, per that spec's Non-goals).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json
from .confirmation import ConfirmationEvidence
from .errors import ConfirmationError

_AUTHORITY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_PUBLIC_KEY_BYTES = 32

#: The only algorithm identifier this verifier accepts. A downgrade
#: attempt (claiming a different/weaker algorithm) is refused, not
#: interpreted.
ACCEPTED_ALGORITHM = "ed25519-v1"


def signing_payload(evidence: ConfirmationEvidence) -> bytes:
    """The exact bytes an owner's signature must cover.

    Deliberately NOT `evidence.evidence_digest`: that property's own
    construction includes `proof_digest` (a hash of `evidence.proof`
    itself), which makes it circular as a signature pre-image -- the
    signature is what becomes `proof`, so the message to sign cannot
    depend on the signature already existing. This function instead
    canonicalizes exactly the attested facts (every `ConfirmationEvidence`
    field except `proof`), which are all known before signing and are
    exactly what an owner is attesting to."""

    return canonical_json(
        {
            "algorithm": evidence.algorithm,
            "authority_id": evidence.authority_id,
            "contract_id": evidence.contract_id,
            "expires_at": evidence.expires_at.isoformat(),
            "intent_digest": evidence.intent_digest,
            "issued_at": evidence.issued_at.isoformat(),
            "nonce": evidence.nonce,
            "operation_id": evidence.operation_id,
            "target_fingerprint": evidence.target_fingerprint,
            "target_identity_digest": evidence.target_identity_digest,
        }
    )


@dataclass(frozen=True)
class PinnedAuthority:
    authority_id: str
    public_key: bytes
    active: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.authority_id, str) or not _AUTHORITY_ID.fullmatch(self.authority_id):
            raise ConfirmationError("Pinned authority identifier is invalid.")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != _PUBLIC_KEY_BYTES:
            raise ConfirmationError("Pinned authority public key must be exactly 32 bytes.")


class Ed25519ConfirmationVerifier:
    """Satisfies `pfsense_mcp.tier1.confirmation.ConfirmationVerifier`.
    Every failure path returns `False`; this method never raises for
    ordinary evidence (only construction-time misconfiguration raises)."""

    def __init__(self, authorities: tuple[PinnedAuthority, ...]) -> None:
        if not isinstance(authorities, tuple) or not authorities:
            raise ConfirmationError("At least one pinned confirmation authority is required.")
        ids = [authority.authority_id for authority in authorities]
        if len(ids) != len(set(ids)):
            raise ConfirmationError("Pinned confirmation authorities must have unique identifiers.")
        self._authorities = {authority.authority_id: authority for authority in authorities}

    def verify(self, evidence: ConfirmationEvidence) -> bool:
        if evidence.algorithm != ACCEPTED_ALGORITHM:
            return False
        authority = self._authorities.get(evidence.authority_id)
        if authority is None or not authority.active:
            return False
        try:
            public_key = Ed25519PublicKey.from_public_bytes(authority.public_key)
            public_key.verify(evidence.proof, signing_payload(evidence))
        except (InvalidSignature, ValueError):
            return False
        return True
