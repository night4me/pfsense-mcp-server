"""Concrete reconciliation authority: detached Ed25519 signatures over a
structured, typed resolution outcome.

Not constructed by production. Reuses `ed25519_authority.py`'s shared
pinned-authority mechanics (per ADR-013) with a distinct signing payload
and a distinct accepted-algorithm string, so a confirmation signature can
never be verified as a reconciliation signature or vice versa, even under
the same pinned key material. See
docs/tier1/specs/reconciliation_authority.md and docs/adr/ADR-013.
"""

from __future__ import annotations

from .canonical import canonical_json
from .ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from .reconciliation import ReconciliationEvidence

__all__ = ["ACCEPTED_ALGORITHM", "Ed25519ReconciliationVerifier", "PinnedAuthority", "signing_payload"]

#: Distinct from confirmation_providers.ACCEPTED_ALGORITHM by design --
#: this is part of the domain separation between the two authorities.
ACCEPTED_ALGORITHM = "ed25519-reconciliation-v1"


def signing_payload(evidence: ReconciliationEvidence) -> bytes:
    """The exact bytes an operator's signature must cover. Deliberately
    not `evidence.evidence_digest` -- same circularity reason as
    `confirmation_providers.signing_payload` (that property hashes
    `evidence.proof`, which does not exist yet at signing time)."""

    return canonical_json(
        {
            "algorithm": evidence.algorithm,
            "authority_id": evidence.authority_id,
            "contract_id": evidence.contract_id,
            "issued_at": evidence.issued_at.isoformat(),
            "observed_state_version": evidence.observed_state_version,
            "operation_id": evidence.operation_id,
            "outcome": evidence.outcome.value,
        }
    )


class Ed25519ReconciliationVerifier:
    """Satisfies `pfsense_mcp.tier1.reconciliation.ReconciliationVerifier`.
    Every failure path returns `False`; never raises for ordinary
    evidence (only construction-time misconfiguration raises)."""

    def __init__(self, authorities: tuple[PinnedAuthority, ...]) -> None:
        self._authorities = PinnedAuthoritySet(authorities)

    def verify(self, evidence: ReconciliationEvidence) -> bool:
        if evidence.algorithm != ACCEPTED_ALGORITHM:
            return False
        return self._authorities.verify_signature(
            authority_id=evidence.authority_id,
            message=signing_payload(evidence),
            signature=evidence.proof,
        )
