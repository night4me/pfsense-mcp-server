from __future__ import annotations

from dataclasses import replace as dc_replace
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.confirmation_providers import signing_payload as confirmation_signing_payload
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority
from pfsense_mcp.tier1.reconciliation import ReconciliationEvidence, ReconciliationOutcome
from pfsense_mcp.tier1.reconciliation_providers import (
    ACCEPTED_ALGORITHM,
    Ed25519ReconciliationVerifier,
    signing_payload,
)


def _keypair():
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return private_key, public_bytes


def _evidence(private_key, *, algorithm=ACCEPTED_ALGORITHM, outcome=ReconciliationOutcome.CONFIRMED_APPLIED):
    unsigned = ReconciliationEvidence(
        authority_id="synthetic-owner",
        algorithm=algorithm,
        contract_id="contract-001",
        operation_id="operation-001",
        observed_state_version=3,
        outcome=outcome,
        issued_at=datetime.now(timezone.utc),
        proof=b"placeholder-proof-bytes",
    )
    signature = private_key.sign(signing_payload(unsigned))
    return ReconciliationEvidence(
        authority_id=unsigned.authority_id,
        algorithm=unsigned.algorithm,
        contract_id=unsigned.contract_id,
        operation_id=unsigned.operation_id,
        observed_state_version=unsigned.observed_state_version,
        outcome=unsigned.outcome,
        issued_at=unsigned.issued_at,
        proof=signature,
    )


def test_valid_reconciliation_signature_is_accepted():
    private_key, public_bytes = _keypair()
    verifier = Ed25519ReconciliationVerifier(
        (PinnedAuthority(authority_id="synthetic-owner", public_key=public_bytes),)
    )

    assert verifier.verify(_evidence(private_key)) is True


def test_algorithm_downgrade_is_refused():
    private_key, public_bytes = _keypair()
    verifier = Ed25519ReconciliationVerifier(
        (PinnedAuthority(authority_id="synthetic-owner", public_key=public_bytes),)
    )

    evidence = _evidence(private_key, algorithm="ed25519-v1")  # confirmation's algorithm, not reconciliation's
    assert verifier.verify(evidence) is False


def test_confirmation_signature_cannot_be_replayed_as_reconciliation():
    """Cross-domain replay check: a signature computed over the
    confirmation-domain payload shape must not verify as reconciliation
    evidence, even reusing the same key, contract_id, and operation_id."""

    private_key, public_bytes = _keypair()
    verifier = Ed25519ReconciliationVerifier(
        (PinnedAuthority(authority_id="synthetic-owner", public_key=public_bytes),)
    )

    now = datetime.now(timezone.utc)
    confirmation_shaped = ConfirmationEvidence(
        authority_id="synthetic-owner",
        algorithm="ed25519-v1",
        nonce="nonce-001",
        contract_id="contract-001",
        operation_id="operation-001",
        target_identity_digest="a" * 64,
        target_fingerprint="b" * 64,
        intent_digest="c" * 64,
        expires_at=now.replace(year=now.year + 1),
        issued_at=now,
        proof=b"placeholder",
    )
    wrong_signature = private_key.sign(confirmation_signing_payload(confirmation_shaped))

    reconciliation_evidence = _evidence(private_key)
    tampered = dc_replace(reconciliation_evidence, proof=wrong_signature)
    assert verifier.verify(tampered) is False


@pytest.mark.parametrize(
    "outcome",
    [
        ReconciliationOutcome.CONFIRMED_APPLIED,
        ReconciliationOutcome.CONFIRMED_NOT_APPLIED,
        ReconciliationOutcome.CONFIRMED_ROLLBACK_APPLIED,
        ReconciliationOutcome.CONFIRMED_ROLLBACK_NOT_APPLIED,
    ],
)
def test_all_outcomes_produce_verifiable_evidence(outcome):
    private_key, public_bytes = _keypair()
    verifier = Ed25519ReconciliationVerifier(
        (PinnedAuthority(authority_id="synthetic-owner", public_key=public_bytes),)
    )

    assert verifier.verify(_evidence(private_key, outcome=outcome)) is True
