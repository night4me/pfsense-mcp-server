"""Concrete confirmation authority: detached Ed25519 signatures verified
against a pinned, owner-configured public key set.

Not constructed by production. Satisfies the `ConfirmationVerifier`
Protocol already defined and enforced in `confirmation.py`/`store.py`.
See docs/tier1/specs/confirmation_authority.md and docs/adr/ADR-012 for
the full specification and the signing-side workflow this verifier pairs
with (built separately, outside `pfsense_mcp`, per that spec's Non-goals).
"""

from __future__ import annotations

from .canonical import canonical_json
from .confirmation import ConfirmationEvidence
from .ed25519_authority import PinnedAuthority, PinnedAuthoritySet

__all__ = ["ACCEPTED_ALGORITHM", "Ed25519ConfirmationVerifier", "PinnedAuthority", "signing_payload"]

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


class Ed25519ConfirmationVerifier:
    """Satisfies `pfsense_mcp.tier1.confirmation.ConfirmationVerifier`.
    Every failure path returns `False`; this method never raises for
    ordinary evidence (only construction-time misconfiguration raises)."""

    def __init__(self, authorities: tuple[PinnedAuthority, ...]) -> None:
        self._authorities = PinnedAuthoritySet(authorities)

    def verify(self, evidence: ConfirmationEvidence) -> bool:
        if evidence.algorithm != ACCEPTED_ALGORITHM:
            return False
        return self._authorities.verify_signature(
            authority_id=evidence.authority_id,
            message=signing_payload(evidence),
            signature=evidence.proof,
        )
