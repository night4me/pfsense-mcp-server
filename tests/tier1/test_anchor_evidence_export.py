"""Unit tests for `pfsense_mcp.tier1.anchor_evidence_export` --
`AnchorEvidenceExportPayload`/`AnchorEvidenceExport` construction
validation, canonical signing-payload determinism, Ed25519 sign/verify,
tamper detection, and `to_bytes`/`from_bytes` round-tripping. Mirrors
`tests/test_security_authorization.py`'s established style for
`PlanAuthorizationV2` -- the shape this module deliberately mirrors.

All keys here are synthetic and ephemeral. This module never provisions
a real posture-evidence authority key (see the module's own docstring);
neither does this test file.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.tier1.anchor_evidence_export import (
    ANCHOR_EVIDENCE_EXPORT_SCHEMA_VERSION,
    AnchorEvidenceExport,
    AnchorEvidenceExportError,
    AnchorEvidenceExportPayload,
    anchor_evidence_export_from_bytes,
    anchor_evidence_export_payload_of,
    anchor_evidence_export_signing_payload,
    anchor_evidence_export_to_bytes,
    build_anchor_evidence_export_payload,
    sign_anchor_evidence_export,
    verify_anchor_evidence_export_signature,
)
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet

_STORE_ID = "tier1-production-write-batch1-store"
_HANDLE = "0x01500000"
_BASELINE = 4
_PROVISIONED_AT = "2026-08-10T15:10:16.416050+00:00"
_ISSUED_AT = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
_EXPIRES_AT = _ISSUED_AT + timedelta(minutes=5)


def _payload(**overrides: object) -> AnchorEvidenceExportPayload:
    fields = {
        "store_id": _STORE_ID,
        "handle": _HANDLE,
        "baseline": _BASELINE,
        "provisioned_at": _PROVISIONED_AT,
        "issued_at": _ISSUED_AT,
        "expires_at": _EXPIRES_AT,
    }
    fields.update(overrides)
    return build_anchor_evidence_export_payload(**fields)  # type: ignore[arg-type]


def _authority_and_key() -> tuple[PinnedAuthoritySet, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    authority = PinnedAuthority(authority_id="test-authority", public_key=public_key)
    return PinnedAuthoritySet((authority,)), private_key


# ---------------------------------------------------------------------------
# 1. Payload construction validation
# ---------------------------------------------------------------------------


def test_valid_payload_constructs():
    payload = _payload()
    assert payload.schema_version == ANCHOR_EVIDENCE_EXPORT_SCHEMA_VERSION


@pytest.mark.parametrize("bad_store_id", ["", "has a space", "has/a/slash", "x" * 200])
def test_invalid_store_id_is_rejected(bad_store_id):
    with pytest.raises(AnchorEvidenceExportError):
        _payload(store_id=bad_store_id)


@pytest.mark.parametrize("bad_handle", ["0x1500000", "0X01500000", "not-a-handle", "0x01500000extra", ""])
def test_invalid_handle_is_rejected(bad_handle):
    with pytest.raises(AnchorEvidenceExportError):
        _payload(handle=bad_handle)


@pytest.mark.parametrize("bad_baseline", [-1, "4", 4.0, True])
def test_invalid_baseline_is_rejected(bad_baseline):
    with pytest.raises(AnchorEvidenceExportError):
        _payload(baseline=bad_baseline)


def test_empty_provisioned_at_is_rejected():
    with pytest.raises(AnchorEvidenceExportError):
        _payload(provisioned_at="")


def test_naive_issued_at_is_rejected():
    with pytest.raises(AnchorEvidenceExportError):
        _payload(issued_at=datetime(2026, 9, 5, 12, 0, 0))


def test_naive_expires_at_is_rejected():
    with pytest.raises(AnchorEvidenceExportError):
        _payload(expires_at=datetime(2026, 9, 5, 12, 5, 0))


def test_non_utc_offset_is_rejected():
    from datetime import timezone as tz

    with pytest.raises(AnchorEvidenceExportError):
        _payload(issued_at=_ISSUED_AT.astimezone(tz(timedelta(hours=2))))


def test_expires_at_must_be_strictly_after_issued_at():
    with pytest.raises(AnchorEvidenceExportError):
        _payload(expires_at=_ISSUED_AT)
    with pytest.raises(AnchorEvidenceExportError):
        _payload(expires_at=_ISSUED_AT - timedelta(seconds=1))


def test_wrong_schema_version_is_rejected():
    with pytest.raises(AnchorEvidenceExportError):
        AnchorEvidenceExportPayload(
            schema_version=ANCHOR_EVIDENCE_EXPORT_SCHEMA_VERSION + 1,
            store_id=_STORE_ID,
            handle=_HANDLE,
            baseline=_BASELINE,
            provisioned_at=_PROVISIONED_AT,
            issued_at=_ISSUED_AT,
            expires_at=_EXPIRES_AT,
        )


def test_bool_schema_version_is_rejected_not_coerced_to_int():
    with pytest.raises(AnchorEvidenceExportError):
        AnchorEvidenceExportPayload(
            schema_version=True,
            store_id=_STORE_ID,
            handle=_HANDLE,
            baseline=_BASELINE,
            provisioned_at=_PROVISIONED_AT,
            issued_at=_ISSUED_AT,
            expires_at=_EXPIRES_AT,
        )


# ---------------------------------------------------------------------------
# 2. Signing payload determinism / domain separation
# ---------------------------------------------------------------------------


def test_signing_payload_is_deterministic():
    payload = _payload()
    assert anchor_evidence_export_signing_payload(payload) == anchor_evidence_export_signing_payload(payload)


def test_signing_payload_differs_for_a_different_baseline():
    a = anchor_evidence_export_signing_payload(_payload())
    b = anchor_evidence_export_signing_payload(_payload(baseline=_BASELINE + 1))
    assert a != b


def test_signing_payload_includes_a_domain_separator():
    body = anchor_evidence_export_signing_payload(_payload())
    assert b"pfsense-mcp-anchor-evidence-export-v1" in body


# ---------------------------------------------------------------------------
# 3. Sign / verify
# ---------------------------------------------------------------------------


def test_sign_and_verify_round_trip():
    authorities, private_key = _authority_and_key()
    export = sign_anchor_evidence_export(_payload(), authority_id="test-authority", private_key=private_key)
    assert verify_anchor_evidence_export_signature(export, authorities) is True


def test_wrong_key_signature_does_not_verify():
    authorities, _ = _authority_and_key()
    _, other_key = _authority_and_key()
    export = sign_anchor_evidence_export(_payload(), authority_id="test-authority", private_key=other_key)
    assert verify_anchor_evidence_export_signature(export, authorities) is False


def test_unknown_authority_id_does_not_verify():
    authorities, private_key = _authority_and_key()
    export = sign_anchor_evidence_export(_payload(), authority_id="a-different-authority", private_key=private_key)
    assert verify_anchor_evidence_export_signature(export, authorities) is False


def test_changing_any_signed_field_invalidates_the_signature():
    authorities, private_key = _authority_and_key()
    export = sign_anchor_evidence_export(_payload(), authority_id="test-authority", private_key=private_key)
    tampered = AnchorEvidenceExport(
        schema_version=export.schema_version,
        store_id=export.store_id,
        handle=export.handle,
        baseline=export.baseline + 1,
        provisioned_at=export.provisioned_at,
        issued_at=export.issued_at,
        expires_at=export.expires_at,
        authority_id=export.authority_id,
        proof=export.proof,
    )
    assert verify_anchor_evidence_export_signature(tampered, authorities) is False


def test_malformed_proof_length_is_rejected_at_construction():
    with pytest.raises(AnchorEvidenceExportError, match="64-byte"):
        AnchorEvidenceExport(
            schema_version=ANCHOR_EVIDENCE_EXPORT_SCHEMA_VERSION,
            store_id=_STORE_ID,
            handle=_HANDLE,
            baseline=_BASELINE,
            provisioned_at=_PROVISIONED_AT,
            issued_at=_ISSUED_AT,
            expires_at=_EXPIRES_AT,
            authority_id="test-authority",
            proof=b"too-short",
        )


def test_empty_proof_is_rejected_at_construction():
    with pytest.raises(AnchorEvidenceExportError, match="64-byte"):
        AnchorEvidenceExport(
            schema_version=ANCHOR_EVIDENCE_EXPORT_SCHEMA_VERSION,
            store_id=_STORE_ID,
            handle=_HANDLE,
            baseline=_BASELINE,
            provisioned_at=_PROVISIONED_AT,
            issued_at=_ISSUED_AT,
            expires_at=_EXPIRES_AT,
            authority_id="test-authority",
            proof=b"",
        )


def test_verify_returns_false_not_raise_for_a_non_export_object():
    authorities, _ = _authority_and_key()
    assert verify_anchor_evidence_export_signature(object(), authorities) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 4. Serialization round-trip / untrusted-bytes parsing
# ---------------------------------------------------------------------------


def test_to_bytes_from_bytes_round_trips_and_still_verifies():
    authorities, private_key = _authority_and_key()
    export = sign_anchor_evidence_export(_payload(), authority_id="test-authority", private_key=private_key)

    raw = anchor_evidence_export_to_bytes(export)
    parsed = anchor_evidence_export_from_bytes(raw)

    assert parsed == export
    assert verify_anchor_evidence_export_signature(parsed, authorities) is True


def test_from_bytes_rejects_invalid_json():
    with pytest.raises(AnchorEvidenceExportError, match="not valid JSON"):
        anchor_evidence_export_from_bytes(b"not json at all {{{")


def test_from_bytes_rejects_a_json_array():
    with pytest.raises(AnchorEvidenceExportError, match="not a JSON object"):
        anchor_evidence_export_from_bytes(b"[1, 2, 3]")


def test_from_bytes_rejects_an_unexpected_field_set():
    _, private_key = _authority_and_key()
    export = sign_anchor_evidence_export(_payload(), authority_id="test-authority", private_key=private_key)
    raw = anchor_evidence_export_to_bytes(export)
    import json

    body = json.loads(raw)
    body["unexpected_extra_field"] = "x"
    with pytest.raises(AnchorEvidenceExportError, match="unexpected field set"):
        anchor_evidence_export_from_bytes(json.dumps(body).encode("utf-8"))


def test_from_bytes_rejects_a_missing_field():
    _, private_key = _authority_and_key()
    export = sign_anchor_evidence_export(_payload(), authority_id="test-authority", private_key=private_key)
    raw = anchor_evidence_export_to_bytes(export)
    import json

    body = json.loads(raw)
    del body["baseline"]
    with pytest.raises(AnchorEvidenceExportError, match="unexpected field set"):
        anchor_evidence_export_from_bytes(json.dumps(body).encode("utf-8"))


def test_from_bytes_rejects_a_malformed_proof_hex():
    _, private_key = _authority_and_key()
    export = sign_anchor_evidence_export(_payload(), authority_id="test-authority", private_key=private_key)
    raw = anchor_evidence_export_to_bytes(export)
    import json

    body = json.loads(raw)
    body["proof_hex"] = "not-hex-zz"
    with pytest.raises(AnchorEvidenceExportError, match="malformed field"):
        anchor_evidence_export_from_bytes(json.dumps(body).encode("utf-8"))


def test_from_bytes_does_not_itself_check_signature_validity():
    """`from_bytes` parses; it never verifies. A byte-tampered-but-still
    self-consistent artifact parses successfully but fails the separate
    `verify_anchor_evidence_export_signature()` step -- proof that
    "parses" and "is trustworthy" are never conflated, per this
    module's own docstring."""

    authorities, private_key = _authority_and_key()
    export = sign_anchor_evidence_export(_payload(), authority_id="test-authority", private_key=private_key)
    raw = anchor_evidence_export_to_bytes(export)
    import json

    body = json.loads(raw)
    body["baseline"] = _BASELINE + 1
    parsed = anchor_evidence_export_from_bytes(json.dumps(body).encode("utf-8"))

    assert parsed.baseline == _BASELINE + 1  # parsed without error
    assert verify_anchor_evidence_export_signature(parsed, authorities) is False  # but untrustworthy


def test_payload_of_reconstructs_the_signed_payload_exactly():
    payload = _payload()
    _, private_key = _authority_and_key()
    export = sign_anchor_evidence_export(payload, authority_id="test-authority", private_key=private_key)
    assert anchor_evidence_export_payload_of(export) == payload
