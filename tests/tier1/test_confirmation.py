from dataclasses import replace

import pytest

from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.errors import ConfirmationError


def _evidence(contract) -> ConfirmationEvidence:
    return ConfirmationEvidence(
        authority_id="synthetic-owner",
        algorithm="detached-signature-test",
        nonce="nonce-001",
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        target_identity_digest=contract.target_identity_digest,
        target_fingerprint=contract.target_fingerprint,
        intent_digest=contract.intent_digest,
        expires_at=contract.expires_at,
        issued_at=contract.created_at,
        proof=b"synthetic-proof",
    )


def test_confirmation_evidence_is_digest_bound_and_value_free(contract_factory):
    evidence = _evidence(contract_factory())
    assert len(evidence.evidence_digest) == 64
    assert len(evidence.proof_digest) == 64
    assert b"synthetic-proof" not in evidence.evidence_digest.encode()


@pytest.mark.parametrize(
    "changes",
    [
        {"contract_id": "other-contract"},
        {"operation_id": "other-operation"},
        {"target_identity_digest": "f" * 64},
        {"target_fingerprint": "f" * 64},
        {"intent_digest": "f" * 64},
    ],
)
def test_confirmation_substitution_is_refused(contract_factory, changes):
    contract = contract_factory()
    with pytest.raises(ConfirmationError, match="does not match"):
        replace(_evidence(contract), **changes).verify_bindings(contract)


@pytest.mark.parametrize(
    "changes",
    [
        {"authority_id": "owner\nforged"},
        {"nonce": ""},
        {"proof": b""},
        {"proof": b"x" * 65_537},
    ],
)
def test_confirmation_evidence_rejects_unsafe_metadata_or_proof(contract_factory, changes):
    with pytest.raises(ConfirmationError):
        replace(_evidence(contract_factory()), **changes)
