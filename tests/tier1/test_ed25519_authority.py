from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.errors import Tier1Error


def _keypair():
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return private_key, public_bytes


def test_verify_signature_accepts_a_valid_signature():
    private_key, public_bytes = _keypair()
    authorities = PinnedAuthoritySet((PinnedAuthority(authority_id="owner-a", public_key=public_bytes),))

    signature = private_key.sign(b"message")
    assert authorities.verify_signature(authority_id="owner-a", message=b"message", signature=signature) is True


def test_verify_signature_rejects_unknown_authority():
    _, public_bytes = _keypair()
    authorities = PinnedAuthoritySet((PinnedAuthority(authority_id="owner-a", public_key=public_bytes),))

    assert authorities.verify_signature(authority_id="owner-b", message=b"x", signature=b"y" * 64) is False


def test_verify_signature_rejects_inactive_authority():
    private_key, public_bytes = _keypair()
    authorities = PinnedAuthoritySet((PinnedAuthority(authority_id="owner-a", public_key=public_bytes, active=False),))

    signature = private_key.sign(b"message")
    assert authorities.verify_signature(authority_id="owner-a", message=b"message", signature=signature) is False


def test_verify_signature_rejects_wrong_key():
    private_key, _ = _keypair()
    _, other_public_bytes = _keypair()
    authorities = PinnedAuthoritySet((PinnedAuthority(authority_id="owner-a", public_key=other_public_bytes),))

    signature = private_key.sign(b"message")
    assert authorities.verify_signature(authority_id="owner-a", message=b"message", signature=signature) is False


def test_verify_signature_never_raises_on_malformed_signature():
    _, public_bytes = _keypair()
    authorities = PinnedAuthoritySet((PinnedAuthority(authority_id="owner-a", public_key=public_bytes),))

    assert authorities.verify_signature(authority_id="owner-a", message=b"message", signature=b"short") is False
    assert authorities.verify_signature(authority_id="owner-a", message=b"message", signature=b"") is False


def test_two_distinct_authorities_are_independently_addressable():
    private_a, public_a = _keypair()
    _private_b, public_b = _keypair()
    authorities = PinnedAuthoritySet(
        (
            PinnedAuthority(authority_id="owner-a", public_key=public_a),
            PinnedAuthority(authority_id="owner-b", public_key=public_b),
        )
    )

    signature_a = private_a.sign(b"message")
    assert authorities.verify_signature(authority_id="owner-a", message=b"message", signature=signature_a) is True
    # owner-a's signature must not verify against owner-b's slot.
    assert authorities.verify_signature(authority_id="owner-b", message=b"message", signature=signature_a) is False


def test_empty_authority_set_refuses_construction():
    with pytest.raises(Tier1Error):
        PinnedAuthoritySet(())


def test_duplicate_authority_id_refuses_construction():
    _, public_bytes = _keypair()
    with pytest.raises(Tier1Error):
        PinnedAuthoritySet(
            (
                PinnedAuthority(authority_id="dup", public_key=public_bytes),
                PinnedAuthority(authority_id="dup", public_key=public_bytes),
            )
        )


def test_pinned_authority_rejects_wrong_key_length():
    with pytest.raises(Tier1Error):
        PinnedAuthority(authority_id="owner-a", public_key=b"too-short")


def test_pinned_authority_rejects_invalid_identifier():
    _, public_bytes = _keypair()
    with pytest.raises(Tier1Error):
        PinnedAuthority(authority_id="not an identifier", public_key=public_bytes)
