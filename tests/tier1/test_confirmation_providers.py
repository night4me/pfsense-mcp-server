from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.confirmation_providers import (
    ACCEPTED_ALGORITHM,
    Ed25519ConfirmationVerifier,
    PinnedAuthority,
    signing_payload,
)
from pfsense_mcp.tier1.errors import ConfirmationError


def _keypair():
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return private_key, public_bytes


def _evidence(contract, *, private_key, authority_id="synthetic-owner", algorithm=ACCEPTED_ALGORITHM):
    unsigned = ConfirmationEvidence(
        authority_id=authority_id,
        algorithm=algorithm,
        nonce="nonce-001",
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        target_identity_digest=contract.target_identity_digest,
        target_fingerprint=contract.target_fingerprint,
        intent_digest=contract.intent_digest,
        expires_at=contract.expires_at,
        issued_at=contract.created_at,
        proof=b"placeholder-32-bytes-minimum-len",
    )
    signature = private_key.sign(signing_payload(unsigned))
    return ConfirmationEvidence(
        authority_id=unsigned.authority_id,
        algorithm=unsigned.algorithm,
        nonce=unsigned.nonce,
        contract_id=unsigned.contract_id,
        operation_id=unsigned.operation_id,
        target_identity_digest=unsigned.target_identity_digest,
        target_fingerprint=unsigned.target_fingerprint,
        intent_digest=unsigned.intent_digest,
        expires_at=unsigned.expires_at,
        issued_at=unsigned.issued_at,
        proof=signature,
    )


def test_valid_signature_from_active_authority_is_accepted(contract_factory):
    private_key, public_bytes = _keypair()
    verifier = Ed25519ConfirmationVerifier((PinnedAuthority(authority_id="synthetic-owner", public_key=public_bytes),))

    evidence = _evidence(contract_factory(), private_key=private_key)
    assert verifier.verify(evidence) is True


def test_signature_from_unknown_authority_is_refused(contract_factory):
    private_key, public_bytes = _keypair()
    verifier = Ed25519ConfirmationVerifier((PinnedAuthority(authority_id="synthetic-owner", public_key=public_bytes),))

    evidence = _evidence(contract_factory(), private_key=private_key, authority_id="unknown-owner")
    assert verifier.verify(evidence) is False


def test_signature_from_retired_authority_is_refused(contract_factory):
    private_key, public_bytes = _keypair()
    verifier = Ed25519ConfirmationVerifier(
        (PinnedAuthority(authority_id="synthetic-owner", public_key=public_bytes, active=False),)
    )

    evidence = _evidence(contract_factory(), private_key=private_key)
    assert verifier.verify(evidence) is False


def test_signature_over_different_digest_is_refused(contract_factory):
    private_key, public_bytes = _keypair()
    verifier = Ed25519ConfirmationVerifier((PinnedAuthority(authority_id="synthetic-owner", public_key=public_bytes),))

    contract = contract_factory()
    evidence = _evidence(contract, private_key=private_key)
    forged_signature = private_key.sign(b"some-other-message")
    tampered = ConfirmationEvidence(
        authority_id=evidence.authority_id,
        algorithm=evidence.algorithm,
        nonce=evidence.nonce,
        contract_id=evidence.contract_id,
        operation_id=evidence.operation_id,
        target_identity_digest=evidence.target_identity_digest,
        target_fingerprint=evidence.target_fingerprint,
        intent_digest=evidence.intent_digest,
        expires_at=evidence.expires_at,
        issued_at=evidence.issued_at,
        proof=forged_signature,
    )
    assert verifier.verify(tampered) is False


def test_malformed_proof_bytes_are_refused_not_raised(contract_factory):
    private_key, public_bytes = _keypair()
    verifier = Ed25519ConfirmationVerifier((PinnedAuthority(authority_id="synthetic-owner", public_key=public_bytes),))

    evidence = _evidence(contract_factory(), private_key=private_key)
    malformed = ConfirmationEvidence(
        authority_id=evidence.authority_id,
        algorithm=evidence.algorithm,
        nonce=evidence.nonce,
        contract_id=evidence.contract_id,
        operation_id=evidence.operation_id,
        target_identity_digest=evidence.target_identity_digest,
        target_fingerprint=evidence.target_fingerprint,
        intent_digest=evidence.intent_digest,
        expires_at=evidence.expires_at,
        issued_at=evidence.issued_at,
        proof=b"not-a-valid-ed25519-signature-at-all",
    )
    assert verifier.verify(malformed) is False


def test_algorithm_downgrade_is_refused(contract_factory):
    private_key, public_bytes = _keypair()
    verifier = Ed25519ConfirmationVerifier((PinnedAuthority(authority_id="synthetic-owner", public_key=public_bytes),))

    evidence = _evidence(contract_factory(), private_key=private_key, algorithm="ed25519-v0-legacy")
    assert verifier.verify(evidence) is False


def test_empty_authority_table_refuses_construction():
    with pytest.raises(ConfirmationError):
        Ed25519ConfirmationVerifier(())


def test_duplicate_authority_id_refuses_construction():
    _, public_bytes = _keypair()
    with pytest.raises(ConfirmationError):
        Ed25519ConfirmationVerifier(
            (
                PinnedAuthority(authority_id="dup", public_key=public_bytes),
                PinnedAuthority(authority_id="dup", public_key=public_bytes),
            )
        )


def test_pinned_authority_rejects_wrong_key_length():
    with pytest.raises(ConfirmationError):
        PinnedAuthority(authority_id="synthetic-owner", public_key=b"too-short")
