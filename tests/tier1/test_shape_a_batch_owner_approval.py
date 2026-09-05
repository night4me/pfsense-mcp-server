"""Tests for the 2026-09-05 `ShapeABatchOwnerApproval` addition -- the
signed artifact that cryptographically binds one owner-reviewed
`ShapeABatchManifest` to the exact `PlanAuthorizationV2.authorization_id`
set the signer produces for it, closing the gap the owner's review of
commit 068a25a identified (a batch manifest digest that was "display/
audit only", with no cryptographic proof any individual authorization
belonged to a specific approved batch).

This file covers the module's own pure schema/sign/verify/serialization
logic in isolation. The end-to-end proof that a real, signed
`PlanAuthorizationV2` produced by the batch CLI actually satisfies
`verify_plan_authorization_v2_batch_membership()` against its own batch's
approval -- and fails against a different batch's -- lives in
`signing/tests/test_write_batch1_signing_batch.py`, which already has the
full realistic fixture (export-based discovery, real preview/authority/
key files) this needs; duplicating that infrastructure here would not add
coverage, only maintenance cost.

All keys/evidence here are synthetic and ephemeral.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.security_posture_types import AnchorAssurance, CapabilityPosture
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.shape_a_artifact_exchange import ShapeAAuthorizationPreview
from pfsense_mcp.tier1.shape_a_batch_manifest import build_shape_a_batch_manifest, compute_shape_a_batch_manifest_digest
from signing.shape_a_batch_owner_approval import (
    SHAPE_A_BATCH_OWNER_APPROVAL_SCHEMA_VERSION,
    ShapeABatchOwnerApprovalError,
    build_shape_a_batch_owner_approval_payload,
    shape_a_batch_owner_approval_from_bytes,
    shape_a_batch_owner_approval_to_bytes,
    sign_shape_a_batch_owner_approval,
    verify_shape_a_batch_owner_approval_signature,
)

_PLAN_DIGEST = "a" * 64
_STEP_ID = "milestone-9-write-activation"
_POSTURE = CapabilityPosture.WRITE_PROTECTED
_ASSURANCE = AnchorAssurance.HARDWARE_WITNESS
_NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
_EXPIRES = _NOW + timedelta(hours=1)

_TWO_SYMBOLS = ("LOG_RETENTION_SETTINGS", "SYSTEM_TIMEZONE")


def _preview(capability_symbol: str, *, execution_intent_digest: str) -> ShapeAAuthorizationPreview:
    return ShapeAAuthorizationPreview(
        capability_symbol=capability_symbol,
        semantic_fields=(("field", "value"),),
        execution_intent_digest=execution_intent_digest,
        requested_plan_digest=_PLAN_DIGEST,
        requested_step_id=_STEP_ID,
        target_capability_posture=_POSTURE,
        target_anchor_assurance=_ASSURANCE,
        generated_at=_NOW,
    )


def _manifest_and_ids():
    digests = {"LOG_RETENTION_SETTINGS": "b" * 64, "SYSTEM_TIMEZONE": "c" * 64}
    previews = tuple(_preview(symbol, execution_intent_digest=digests[symbol]) for symbol in _TWO_SYMBOLS)
    manifest = build_shape_a_batch_manifest(previews, batch_id="batch-1")
    authorization_ids = {"LOG_RETENTION_SETTINGS": "authz-aaaa", "SYSTEM_TIMEZONE": "authz-bbbb"}
    return manifest, authorization_ids


def _authority() -> tuple[Ed25519PrivateKey, PinnedAuthority]:
    private_key = Ed25519PrivateKey.generate()
    authority = PinnedAuthority(
        authority_id="test-authorization-authority", public_key=private_key.public_key().public_bytes_raw()
    )
    return private_key, authority


def test_build_payload_refuses_missing_authorization_id():
    manifest, _authorization_ids = _manifest_and_ids()
    with pytest.raises(ShapeABatchOwnerApprovalError, match="exactly one entry"):
        build_shape_a_batch_owner_approval_payload(
            manifest,
            batch_id="batch-1",
            authorization_ids={"SYSTEM_TIMEZONE": "authz-bbbb"},
            issued_at=_NOW,
            expires_at=_EXPIRES,
        )


def test_build_payload_refuses_extra_authorization_id():
    manifest, authorization_ids = _manifest_and_ids()
    authorization_ids = {**authorization_ids, "EXTRA_CAPABILITY": "authz-cccc"}
    with pytest.raises(ShapeABatchOwnerApprovalError, match="exactly one entry"):
        build_shape_a_batch_owner_approval_payload(
            manifest, batch_id="batch-1", authorization_ids=authorization_ids, issued_at=_NOW, expires_at=_EXPIRES
        )


def test_build_payload_binds_manifest_digest_independently():
    """`manifest_digest` in the payload must be independently recomputed
    from the manifest, matching `compute_shape_a_batch_manifest_digest()`
    -- proving a caller cannot forge approval for content never actually
    built via `build_shape_a_batch_manifest()`. Uses the module-level
    import above, not a function-local re-import -- see the confirmation-
    side mirror of this test for why a local re-import here would be
    flaky under xdist (a same-worker isolation test elsewhere can
    delete/reload this module from `sys.modules` between collection and
    execution, which would otherwise resolve to a different class object
    than the one `manifest` is actually an instance of)."""

    manifest, authorization_ids = _manifest_and_ids()
    payload = build_shape_a_batch_owner_approval_payload(
        manifest, batch_id="batch-1", authorization_ids=authorization_ids, issued_at=_NOW, expires_at=_EXPIRES
    )
    assert payload.manifest_digest == compute_shape_a_batch_manifest_digest(manifest)


def test_payload_entries_are_in_canonical_manifest_order():
    manifest, authorization_ids = _manifest_and_ids()
    payload = build_shape_a_batch_owner_approval_payload(
        manifest, batch_id="batch-1", authorization_ids=authorization_ids, issued_at=_NOW, expires_at=_EXPIRES
    )
    assert tuple(entry.capability_symbol for entry in payload.entries) == manifest.capability_symbols


def test_sign_and_verify_round_trip():
    manifest, authorization_ids = _manifest_and_ids()
    private_key, authority = _authority()
    payload = build_shape_a_batch_owner_approval_payload(
        manifest, batch_id="batch-1", authorization_ids=authorization_ids, issued_at=_NOW, expires_at=_EXPIRES
    )
    approval = sign_shape_a_batch_owner_approval(payload, authority_id=authority.authority_id, private_key=private_key)

    assert verify_shape_a_batch_owner_approval_signature(approval, PinnedAuthoritySet((authority,))) is True


def test_verify_fails_for_wrong_authority():
    manifest, authorization_ids = _manifest_and_ids()
    private_key, authority = _authority()
    _wrong_private_key, wrong_authority = _authority()
    payload = build_shape_a_batch_owner_approval_payload(
        manifest, batch_id="batch-1", authorization_ids=authorization_ids, issued_at=_NOW, expires_at=_EXPIRES
    )
    approval = sign_shape_a_batch_owner_approval(payload, authority_id=authority.authority_id, private_key=private_key)

    assert verify_shape_a_batch_owner_approval_signature(approval, PinnedAuthoritySet((wrong_authority,))) is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("manifest_digest", "f" * 64),
        ("batch_id", "batch-tampered"),
        ("requested_plan_digest", "e" * 64),
    ],
)
def test_verify_fails_when_a_signed_field_is_tampered(field, value):
    manifest, authorization_ids = _manifest_and_ids()
    private_key, authority = _authority()
    payload = build_shape_a_batch_owner_approval_payload(
        manifest, batch_id="batch-1", authorization_ids=authorization_ids, issued_at=_NOW, expires_at=_EXPIRES
    )
    approval = sign_shape_a_batch_owner_approval(payload, authority_id=authority.authority_id, private_key=private_key)
    tampered = replace(approval, **{field: value})

    assert verify_shape_a_batch_owner_approval_signature(tampered, PinnedAuthoritySet((authority,))) is False


def test_verify_fails_when_an_entry_authorization_id_is_tampered():
    manifest, authorization_ids = _manifest_and_ids()
    private_key, authority = _authority()
    payload = build_shape_a_batch_owner_approval_payload(
        manifest, batch_id="batch-1", authorization_ids=authorization_ids, issued_at=_NOW, expires_at=_EXPIRES
    )
    approval = sign_shape_a_batch_owner_approval(payload, authority_id=authority.authority_id, private_key=private_key)
    tampered_entries = tuple(
        replace(entry, authorization_id="authz-substituted") if entry.capability_symbol == "SYSTEM_TIMEZONE" else entry
        for entry in approval.entries
    )
    tampered = replace(approval, entries=tampered_entries)

    assert verify_shape_a_batch_owner_approval_signature(tampered, PinnedAuthoritySet((authority,))) is False


def test_serialization_round_trip_preserves_verifiability():
    manifest, authorization_ids = _manifest_and_ids()
    private_key, authority = _authority()
    payload = build_shape_a_batch_owner_approval_payload(
        manifest, batch_id="batch-1", authorization_ids=authorization_ids, issued_at=_NOW, expires_at=_EXPIRES
    )
    approval = sign_shape_a_batch_owner_approval(payload, authority_id=authority.authority_id, private_key=private_key)

    reloaded = shape_a_batch_owner_approval_from_bytes(shape_a_batch_owner_approval_to_bytes(approval))

    assert reloaded == approval
    assert verify_shape_a_batch_owner_approval_signature(reloaded, PinnedAuthoritySet((authority,))) is True


def test_from_bytes_refuses_malformed_json():
    with pytest.raises(ShapeABatchOwnerApprovalError, match="not valid JSON"):
        shape_a_batch_owner_approval_from_bytes(b"not json")


def test_from_bytes_refuses_unexpected_field_set():
    with pytest.raises(ShapeABatchOwnerApprovalError, match="unexpected field set"):
        shape_a_batch_owner_approval_from_bytes(b'{"only_one_field": true}')


def test_schema_version_is_current():
    assert SHAPE_A_BATCH_OWNER_APPROVAL_SCHEMA_VERSION == 1
