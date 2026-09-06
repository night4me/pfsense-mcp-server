"""Unit tests for `pfsense_mcp.tier1.sealed_write_approval` --
`SealedWriteApprovalPayload`/`SealedWriteApproval` construction
validation, canonical signing-payload determinism, Ed25519 sign/verify,
tamper detection, `to_bytes`/`from_bytes` round-tripping, and the
combined `verify_sealed_write_approval()` binding checks (cross-contract/
cross-version/cross-target/cross-class replay, expiry). Mirrors
`tests/tier1/test_anchor_evidence_export.py`'s established style -- the
module this one deliberately mirrors.

All keys here are synthetic and ephemeral. This module never provisions
a real STANDARD approval authority key or a real local signer identity
(see the module's own docstring); neither does this test file.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.sealed_write_approval import (
    SEALED_WRITE_APPROVAL_SCHEMA_VERSION,
    STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID,
    SealedWriteApproval,
    SealedWriteApprovalError,
    SealedWriteApprovalPayload,
    build_sealed_write_approval_payload,
    sealed_write_approval_from_bytes,
    sealed_write_approval_payload_of,
    sealed_write_approval_signing_payload,
    sealed_write_approval_to_bytes,
    sign_sealed_write_approval,
    verify_sealed_write_approval,
    verify_sealed_write_approval_signature,
)
from pfsense_mcp.tier1.write_security_class import WriteSecurityClass

_CONTRACT_ID = "ntppref-abc123"
_STATE_VERSION = 1
_SECURITY_CLASS = WriteSecurityClass.STANDARD_SEALED_WRITE
_INTENT_DIGEST = "a" * 64
_TARGET_DIGEST = "b" * 64
_ISSUED_AT = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
_EXPIRES_AT = _ISSUED_AT + timedelta(minutes=5)


def _payload(**overrides: object) -> SealedWriteApprovalPayload:
    fields = {
        "contract_id": _CONTRACT_ID,
        "state_version": _STATE_VERSION,
        "security_class": _SECURITY_CLASS,
        "execution_intent_digest": _INTENT_DIGEST,
        "target_identity_digest": _TARGET_DIGEST,
        "issued_at": _ISSUED_AT,
        "expires_at": _EXPIRES_AT,
    }
    fields.update(overrides)
    return build_sealed_write_approval_payload(**fields)  # type: ignore[arg-type]


def _authority_and_key(authority_id: str = STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    authority = PinnedAuthority(authority_id=authority_id, public_key=public_key)
    return PinnedAuthoritySet((authority,)), private_key


def _signed(**overrides: object) -> tuple[SealedWriteApproval, PinnedAuthoritySet]:
    authorities, private_key = _authority_and_key()
    approval = sign_sealed_write_approval(
        _payload(**overrides), authority_id=STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID, private_key=private_key
    )
    return approval, authorities


# ---------------------------------------------------------------------------
# 1. Payload construction validation
# ---------------------------------------------------------------------------


def test_valid_payload_constructs():
    payload = _payload()
    assert payload.schema_version == SEALED_WRITE_APPROVAL_SCHEMA_VERSION


@pytest.mark.parametrize("bad_contract_id", ["", "has a space", "has/a/slash", "x" * 200])
def test_invalid_contract_id_is_rejected(bad_contract_id):
    with pytest.raises(SealedWriteApprovalError):
        _payload(contract_id=bad_contract_id)


@pytest.mark.parametrize("bad_state_version", [-1, "1", 1.0, True])
def test_invalid_state_version_is_rejected(bad_state_version):
    with pytest.raises(SealedWriteApprovalError):
        _payload(state_version=bad_state_version)


@pytest.mark.parametrize("bad_class", ["standard_sealed_write", 1, None, object()])
def test_non_enum_security_class_is_rejected(bad_class):
    with pytest.raises(SealedWriteApprovalError):
        _payload(security_class=bad_class)


@pytest.mark.parametrize("bad_digest", ["", "not-hex" * 10, "a" * 63, "a" * 65, "A" * 64])
def test_invalid_execution_intent_digest_is_rejected(bad_digest):
    with pytest.raises(SealedWriteApprovalError):
        _payload(execution_intent_digest=bad_digest)


@pytest.mark.parametrize("bad_digest", ["", "not-hex" * 10, "b" * 63, "b" * 65, "B" * 64])
def test_invalid_target_identity_digest_is_rejected(bad_digest):
    with pytest.raises(SealedWriteApprovalError):
        _payload(target_identity_digest=bad_digest)


def test_naive_issued_at_is_rejected():
    with pytest.raises(SealedWriteApprovalError):
        _payload(issued_at=datetime(2026, 9, 6, 12, 0, 0))


def test_naive_expires_at_is_rejected():
    with pytest.raises(SealedWriteApprovalError):
        _payload(expires_at=datetime(2026, 9, 6, 12, 5, 0))


def test_non_utc_offset_is_rejected():
    with pytest.raises(SealedWriteApprovalError):
        _payload(issued_at=_ISSUED_AT.astimezone(timezone(timedelta(hours=2))))


def test_expires_at_must_be_strictly_after_issued_at():
    with pytest.raises(SealedWriteApprovalError):
        _payload(expires_at=_ISSUED_AT)
    with pytest.raises(SealedWriteApprovalError):
        _payload(expires_at=_ISSUED_AT - timedelta(seconds=1))


def test_wrong_schema_version_is_rejected():
    with pytest.raises(SealedWriteApprovalError):
        SealedWriteApprovalPayload(
            schema_version=SEALED_WRITE_APPROVAL_SCHEMA_VERSION + 1,
            contract_id=_CONTRACT_ID,
            state_version=_STATE_VERSION,
            security_class=_SECURITY_CLASS,
            execution_intent_digest=_INTENT_DIGEST,
            target_identity_digest=_TARGET_DIGEST,
            issued_at=_ISSUED_AT,
            expires_at=_EXPIRES_AT,
        )


def test_bool_schema_version_is_rejected_not_coerced_to_int():
    with pytest.raises(SealedWriteApprovalError):
        SealedWriteApprovalPayload(
            schema_version=True,
            contract_id=_CONTRACT_ID,
            state_version=_STATE_VERSION,
            security_class=_SECURITY_CLASS,
            execution_intent_digest=_INTENT_DIGEST,
            target_identity_digest=_TARGET_DIGEST,
            issued_at=_ISSUED_AT,
            expires_at=_EXPIRES_AT,
        )


# ---------------------------------------------------------------------------
# 2. Signing payload determinism / domain separation
# ---------------------------------------------------------------------------


def test_signing_payload_is_deterministic():
    payload = _payload()
    assert sealed_write_approval_signing_payload(payload) == sealed_write_approval_signing_payload(payload)


def test_signing_payload_differs_for_a_different_contract_id():
    a = sealed_write_approval_signing_payload(_payload())
    b = sealed_write_approval_signing_payload(_payload(contract_id="ntppref-different"))
    assert a != b


def test_signing_payload_differs_for_a_different_state_version():
    a = sealed_write_approval_signing_payload(_payload())
    b = sealed_write_approval_signing_payload(_payload(state_version=_STATE_VERSION + 1))
    assert a != b


def test_signing_payload_differs_for_a_different_security_class():
    a = sealed_write_approval_signing_payload(_payload())
    b = sealed_write_approval_signing_payload(_payload(security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1))
    assert a != b


def test_signing_payload_differs_for_a_different_intent_digest():
    a = sealed_write_approval_signing_payload(_payload())
    b = sealed_write_approval_signing_payload(_payload(execution_intent_digest="c" * 64))
    assert a != b


def test_signing_payload_differs_for_a_different_target_digest():
    a = sealed_write_approval_signing_payload(_payload())
    b = sealed_write_approval_signing_payload(_payload(target_identity_digest="d" * 64))
    assert a != b


def test_signing_payload_includes_a_domain_separator():
    body = sealed_write_approval_signing_payload(_payload())
    assert b"pfsense-mcp-standard-sealed-write-approval-v1" in body


# ---------------------------------------------------------------------------
# 3. Sign / verify (signature-only)
# ---------------------------------------------------------------------------


def test_sign_and_verify_round_trip():
    approval, authorities = _signed()
    assert verify_sealed_write_approval_signature(approval, authorities) is True


def test_wrong_key_signature_does_not_verify():
    authorities, _ = _authority_and_key()
    _, other_key = _authority_and_key()
    approval = sign_sealed_write_approval(
        _payload(), authority_id=STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID, private_key=other_key
    )
    assert verify_sealed_write_approval_signature(approval, authorities) is False


def test_unknown_authority_id_does_not_verify():
    authorities, private_key = _authority_and_key()
    approval = sign_sealed_write_approval(_payload(), authority_id="a-different-authority", private_key=private_key)
    assert verify_sealed_write_approval_signature(approval, authorities) is False


def test_changing_any_signed_field_invalidates_the_signature():
    approval, authorities = _signed()
    tampered = SealedWriteApproval(
        schema_version=approval.schema_version,
        contract_id=approval.contract_id,
        state_version=approval.state_version + 1,
        security_class=approval.security_class,
        execution_intent_digest=approval.execution_intent_digest,
        target_identity_digest=approval.target_identity_digest,
        issued_at=approval.issued_at,
        expires_at=approval.expires_at,
        authority_id=approval.authority_id,
        proof=approval.proof,
    )
    assert verify_sealed_write_approval_signature(tampered, authorities) is False


def test_malformed_proof_length_is_rejected_at_construction():
    with pytest.raises(SealedWriteApprovalError, match="64-byte"):
        SealedWriteApproval(
            schema_version=SEALED_WRITE_APPROVAL_SCHEMA_VERSION,
            contract_id=_CONTRACT_ID,
            state_version=_STATE_VERSION,
            security_class=_SECURITY_CLASS,
            execution_intent_digest=_INTENT_DIGEST,
            target_identity_digest=_TARGET_DIGEST,
            issued_at=_ISSUED_AT,
            expires_at=_EXPIRES_AT,
            authority_id=STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID,
            proof=b"too-short",
        )


def test_empty_proof_is_rejected_at_construction():
    with pytest.raises(SealedWriteApprovalError, match="64-byte"):
        SealedWriteApproval(
            schema_version=SEALED_WRITE_APPROVAL_SCHEMA_VERSION,
            contract_id=_CONTRACT_ID,
            state_version=_STATE_VERSION,
            security_class=_SECURITY_CLASS,
            execution_intent_digest=_INTENT_DIGEST,
            target_identity_digest=_TARGET_DIGEST,
            issued_at=_ISSUED_AT,
            expires_at=_EXPIRES_AT,
            authority_id=STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID,
            proof=b"",
        )


def test_verify_signature_returns_false_not_raise_for_a_non_approval_object():
    authorities, _ = _authority_and_key()
    assert verify_sealed_write_approval_signature(object(), authorities) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 4. verify_sealed_write_approval() -- combined binding checks
# ---------------------------------------------------------------------------


def _verify(approval, authorities, *, now=None, **overrides):
    fields = {
        "contract_id": _CONTRACT_ID,
        "state_version": _STATE_VERSION,
        "security_class": _SECURITY_CLASS,
        "execution_intent_digest": _INTENT_DIGEST,
        "target_identity_digest": _TARGET_DIGEST,
    }
    fields.update(overrides)
    return verify_sealed_write_approval(
        approval, authorities=authorities, now=now or (_ISSUED_AT + timedelta(minutes=1)), **fields
    )


def test_valid_approval_verifies_against_matching_fields():
    approval, authorities = _signed()
    assert _verify(approval, authorities) is True


def test_cross_contract_replay_is_refused():
    approval, authorities = _signed()
    assert _verify(approval, authorities, contract_id="ntppref-a-different-contract") is False


def test_cross_version_replay_is_refused():
    approval, authorities = _signed()
    assert _verify(approval, authorities, state_version=_STATE_VERSION + 1) is False


def test_cross_class_replay_is_refused():
    approval, authorities = _signed()
    assert _verify(approval, authorities, security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1) is False


def test_cross_intent_digest_replay_is_refused():
    approval, authorities = _signed()
    assert _verify(approval, authorities, execution_intent_digest="c" * 64) is False


def test_cross_target_replay_is_refused():
    approval, authorities = _signed()
    assert _verify(approval, authorities, target_identity_digest="d" * 64) is False


def test_cross_domain_authority_replay_is_refused():
    """An approval signed by a HIGH_ASSURANCE-style authority id (wrong
    authority for this domain) must never verify, even with every other
    field matching exactly."""

    _, private_key = _authority_and_key(authority_id="some-other-authority-v1")
    approval = sign_sealed_write_approval(_payload(), authority_id="some-other-authority-v1", private_key=private_key)
    # Verifier only trusts the real STANDARD authority id.
    real_authorities, _ = _authority_and_key()
    assert _verify(approval, real_authorities) is False


def test_expired_approval_is_refused():
    approval, authorities = _signed()
    assert _verify(approval, authorities, now=_EXPIRES_AT) is False
    assert _verify(approval, authorities, now=_EXPIRES_AT + timedelta(seconds=1)) is False


def test_not_yet_issued_approval_is_refused():
    approval, authorities = _signed()
    assert _verify(approval, authorities, now=_ISSUED_AT - timedelta(seconds=1)) is False


def test_naive_now_is_refused_not_raised():
    approval, authorities = _signed()
    assert _verify(approval, authorities, now=datetime(2026, 9, 6, 12, 1, 0)) is False


def test_non_approval_object_is_refused_not_raised():
    authorities, _ = _authority_and_key()
    assert (
        verify_sealed_write_approval(
            object(),  # type: ignore[arg-type]
            authorities=authorities,
            now=_ISSUED_AT + timedelta(minutes=1),
            contract_id=_CONTRACT_ID,
            state_version=_STATE_VERSION,
            security_class=_SECURITY_CLASS,
            execution_intent_digest=_INTENT_DIGEST,
            target_identity_digest=_TARGET_DIGEST,
        )
        is False
    )


def test_bad_signature_with_otherwise_matching_fields_is_refused():
    authorities, _ = _authority_and_key()
    _, other_key = _authority_and_key()
    approval = sign_sealed_write_approval(
        _payload(), authority_id=STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID, private_key=other_key
    )
    assert _verify(approval, authorities) is False


# ---------------------------------------------------------------------------
# 5. Serialization round-trip / untrusted-bytes parsing
# ---------------------------------------------------------------------------


def test_to_bytes_from_bytes_round_trips_and_still_verifies():
    approval, authorities = _signed()

    raw = sealed_write_approval_to_bytes(approval)
    parsed = sealed_write_approval_from_bytes(raw)

    assert parsed == approval
    assert verify_sealed_write_approval_signature(parsed, authorities) is True


def test_from_bytes_rejects_invalid_json():
    with pytest.raises(SealedWriteApprovalError, match="not valid JSON"):
        sealed_write_approval_from_bytes(b"not json at all {{{")


def test_from_bytes_rejects_a_json_array():
    with pytest.raises(SealedWriteApprovalError, match="not a JSON object"):
        sealed_write_approval_from_bytes(b"[1, 2, 3]")


def test_from_bytes_rejects_an_unexpected_field_set():
    approval, _ = _signed()
    raw = sealed_write_approval_to_bytes(approval)
    body = json.loads(raw)
    body["unexpected_extra_field"] = "x"
    with pytest.raises(SealedWriteApprovalError, match="unexpected field set"):
        sealed_write_approval_from_bytes(json.dumps(body).encode("utf-8"))


def test_from_bytes_rejects_a_missing_field():
    approval, _ = _signed()
    raw = sealed_write_approval_to_bytes(approval)
    body = json.loads(raw)
    del body["state_version"]
    with pytest.raises(SealedWriteApprovalError, match="unexpected field set"):
        sealed_write_approval_from_bytes(json.dumps(body).encode("utf-8"))


def test_from_bytes_rejects_a_malformed_proof_hex():
    approval, _ = _signed()
    raw = sealed_write_approval_to_bytes(approval)
    body = json.loads(raw)
    body["proof_hex"] = "not-hex-zz"
    with pytest.raises(SealedWriteApprovalError, match="malformed field"):
        sealed_write_approval_from_bytes(json.dumps(body).encode("utf-8"))


def test_from_bytes_rejects_an_unknown_security_class_literal():
    approval, _ = _signed()
    raw = sealed_write_approval_to_bytes(approval)
    body = json.loads(raw)
    body["security_class"] = "not_a_real_class"
    with pytest.raises(SealedWriteApprovalError, match="malformed field"):
        sealed_write_approval_from_bytes(json.dumps(body).encode("utf-8"))


def test_from_bytes_does_not_itself_check_signature_validity():
    """`from_bytes` parses; it never verifies. A byte-tampered-but-still
    self-consistent artifact parses successfully but fails the separate
    `verify_sealed_write_approval_signature()` step -- proof that
    "parses" and "is trustworthy" are never conflated, per this module's
    own docstring."""

    approval, authorities = _signed()
    raw = sealed_write_approval_to_bytes(approval)
    body = json.loads(raw)
    body["state_version"] = _STATE_VERSION + 1
    parsed = sealed_write_approval_from_bytes(json.dumps(body).encode("utf-8"))

    assert parsed.state_version == _STATE_VERSION + 1  # parsed without error
    assert verify_sealed_write_approval_signature(parsed, authorities) is False  # but untrustworthy


def test_payload_of_reconstructs_the_signed_payload_exactly():
    payload = _payload()
    _, private_key = _authority_and_key()
    approval = sign_sealed_write_approval(
        payload, authority_id=STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID, private_key=private_key
    )
    assert sealed_write_approval_payload_of(approval) == payload
