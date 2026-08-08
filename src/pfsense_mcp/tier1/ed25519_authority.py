"""Shared Ed25519 pinned-authority verification.

Used by both `confirmation_providers.py` and `reconciliation_providers.py`
-- per ADR-013, both domains reuse the same signing mechanism but remain
distinct `Protocol` implementations with distinct digest-purpose domain
separation (`DigestPurpose.CONFIRMATION` vs. `DigestPurpose.RECONCILIATION`,
and distinct `ConfirmationEvidence`/`ReconciliationEvidence` shapes). This
module factors out only the common "verify a signature against one of a
pinned set of public keys" mechanics, not any domain-specific evidence
shape or digest purpose -- extracted after writing that exact logic twice
nearly identically, not designed speculatively in advance.

Not constructed by production. The private signing key never appears
anywhere in this module or this package -- only public keys are ever
loaded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import Tier1Error

_AUTHORITY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_PUBLIC_KEY_BYTES = 32


@dataclass(frozen=True)
class PinnedAuthority:
    authority_id: str
    public_key: bytes
    active: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.authority_id, str) or not _AUTHORITY_ID.fullmatch(self.authority_id):
            raise Tier1Error("Pinned authority identifier is invalid.")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != _PUBLIC_KEY_BYTES:
            raise Tier1Error("Pinned authority public key must be exactly 32 bytes.")


class PinnedAuthoritySet:
    """A validated, immutable set of `PinnedAuthority` entries, keyed by
    `authority_id`, with signature verification against whichever entry
    an evidence object names."""

    def __init__(self, authorities: tuple[PinnedAuthority, ...]) -> None:
        if not isinstance(authorities, tuple) or not authorities:
            raise Tier1Error("At least one pinned authority is required.")
        ids = [authority.authority_id for authority in authorities]
        if len(ids) != len(set(ids)):
            raise Tier1Error("Pinned authorities must have unique identifiers.")
        self._authorities = {authority.authority_id: authority for authority in authorities}

    def verify_signature(self, *, authority_id: str, message: bytes, signature: bytes) -> bool:
        """Never raises. Returns False for an unknown or inactive
        authority_id, a malformed signature, or a signature that does
        not verify against the pinned key -- the caller cannot
        distinguish which, by design (no detail beyond True/False)."""

        authority = self._authorities.get(authority_id)
        if authority is None or not authority.active:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(authority.public_key).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True
