from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pfsense_mcp.tier1.errors import ConfirmationError
from pfsense_mcp.tier1.reconciliation import (
    OUTCOME_TARGET_STATE,
    ReconciliationEvidence,
    ReconciliationOutcome,
)
from pfsense_mcp.tier1.state_machine import RecoveryState


def _evidence(**overrides):
    fields = {
        "authority_id": "synthetic-owner",
        "algorithm": "ed25519-reconciliation-v2",
        "contract_id": "contract-001",
        "operation_id": "operation-001",
        "observed_state_version": 3,
        "outcome": ReconciliationOutcome.CONFIRMED_APPLIED,
        "issued_at": datetime.now(timezone.utc),
        "proof": b"synthetic-proof",
        "verified_target_fingerprint": "a" * 64,
        "verified_lifecycle_locator": 7,
    }
    fields.update(overrides)
    return ReconciliationEvidence(**fields)


def test_valid_evidence_constructs():
    evidence = _evidence()
    assert evidence.outcome == ReconciliationOutcome.CONFIRMED_APPLIED


def test_confirmed_applied_requires_verified_target_fingerprint():
    with pytest.raises(ConfirmationError, match="verified target fingerprint"):
        _evidence(verified_target_fingerprint=None)


@pytest.mark.parametrize("fingerprint", ["d" * 64, "malformed", 7])
def test_non_applied_outcome_rejects_any_verified_target_fingerprint(fingerprint):
    with pytest.raises(ConfirmationError, match="verified target fingerprint"):
        _evidence(
            outcome=ReconciliationOutcome.CONFIRMED_NOT_APPLIED,
            verified_target_fingerprint=fingerprint,
            verified_lifecycle_locator=None,
        )


def test_applied_outcomes_require_verified_lifecycle_locator():
    with pytest.raises(ConfirmationError, match="verified lifecycle locator"):
        _evidence(verified_lifecycle_locator=None)
    rollback = _evidence(
        outcome=ReconciliationOutcome.CONFIRMED_ROLLBACK_APPLIED,
        verified_target_fingerprint=None,
    )
    assert rollback.verified_lifecycle_locator == 7


@pytest.mark.parametrize("locator", [7, "7", True, -1, 2_147_483_648])
def test_non_applied_outcomes_reject_any_verified_lifecycle_locator(locator):
    with pytest.raises(ConfirmationError, match="verified lifecycle locator"):
        _evidence(
            outcome=ReconciliationOutcome.CONFIRMED_NOT_APPLIED,
            verified_target_fingerprint=None,
            verified_lifecycle_locator=locator,
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"authority_id": ""},
        {"contract_id": "not valid"},
        {"observed_state_version": -1},
        {"issued_at": datetime.now()},  # naive, not UTC
        {"proof": b""},
        {"proof": b"x" * 65_537},
    ],
)
def test_invalid_fields_are_rejected(overrides):
    with pytest.raises(ConfirmationError):
        _evidence(**overrides)


def test_verify_bindings_accepts_matching_contract():
    evidence = _evidence()
    evidence.verify_bindings(
        contract_id="contract-001", operation_id="operation-001", state_version=3, lifecycle_locator=7
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"contract_id": "contract-002", "operation_id": "operation-001", "state_version": 3, "lifecycle_locator": 7},
        {"contract_id": "contract-001", "operation_id": "operation-002", "state_version": 3, "lifecycle_locator": 7},
        {"contract_id": "contract-001", "operation_id": "operation-001", "state_version": 4, "lifecycle_locator": 7},
        {"contract_id": "contract-001", "operation_id": "operation-001", "state_version": 3, "lifecycle_locator": 9},
    ],
)
def test_verify_bindings_rejects_any_mismatch(kwargs):
    evidence = _evidence()
    with pytest.raises(ConfirmationError, match="does not match"):
        evidence.verify_bindings(**kwargs)


def test_all_four_outcomes_map_to_distinct_terminal_states():
    assert OUTCOME_TARGET_STATE[ReconciliationOutcome.CONFIRMED_APPLIED] == RecoveryState.VERIFIED
    assert OUTCOME_TARGET_STATE[ReconciliationOutcome.CONFIRMED_NOT_APPLIED] == RecoveryState.FAILED
    assert OUTCOME_TARGET_STATE[ReconciliationOutcome.CONFIRMED_ROLLBACK_APPLIED] == RecoveryState.ROLLED_BACK
    assert OUTCOME_TARGET_STATE[ReconciliationOutcome.CONFIRMED_ROLLBACK_NOT_APPLIED] == RecoveryState.ROLLBACK_FAILED
    assert len(set(OUTCOME_TARGET_STATE.values())) == 4


def test_evidence_digest_is_stable_and_reflects_proof_identity():
    """evidence_digest deliberately includes a hash of the proof bytes
    (proof_digest) -- this is exactly why it is unsuitable as a signature
    pre-image (see reconciliation_providers.signing_payload's docstring)
    and is instead reserved for post-verification audit binding. This
    test only confirms the digest is a stable, deterministic function of
    its inputs including proof identity -- never the raw proof bytes
    themselves in cleartext."""

    issued_at = datetime.now(timezone.utc)
    first = _evidence(proof=b"proof-a", issued_at=issued_at)
    second = _evidence(proof=b"proof-a", issued_at=issued_at)
    third = _evidence(proof=b"proof-b", issued_at=issued_at)

    assert first.evidence_digest == second.evidence_digest
    assert first.evidence_digest != third.evidence_digest
    assert b"proof-a" not in first.evidence_digest.encode()
