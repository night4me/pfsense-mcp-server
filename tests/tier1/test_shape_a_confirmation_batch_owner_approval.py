"""Tests for the 2026-09-05 `ShapeAConfirmationBatchOwnerApproval`
addition -- the confirmation-side counterpart to
`shape_a_batch_owner_approval.py`. Binds directly to each capability's
already-existing `contract_id`/`operation_id`/`intent_digest` (no
signer-generated identifier needs pre-committing here, unlike the
authorization case's `authorization_id`).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.shape_a_artifact_exchange import ShapeAPendingConfirmationRequest
from pfsense_mcp.tier1.shape_a_confirmation_batch_manifest import (
    build_shape_a_confirmation_batch_manifest,
    compute_shape_a_confirmation_batch_manifest_digest,
)
from signing.shape_a_confirmation_batch_owner_approval import (
    SHAPE_A_CONFIRMATION_BATCH_OWNER_APPROVAL_SCHEMA_VERSION,
    ShapeAConfirmationBatchOwnerApprovalError,
    build_shape_a_confirmation_batch_owner_approval_payload,
    shape_a_confirmation_batch_owner_approval_from_bytes,
    shape_a_confirmation_batch_owner_approval_to_bytes,
    sign_shape_a_confirmation_batch_owner_approval,
    verify_shape_a_confirmation_batch_owner_approval_signature,
)

_NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
_EXPIRES_REQUEST = _NOW + timedelta(minutes=5)
_APPROVAL_EXPIRES = _NOW + timedelta(hours=1)
_AUTHORITY_ID = "confirm-owner-1"
_TWO_SYMBOLS = ("LOG_RETENTION_SETTINGS", "SYSTEM_TIMEZONE")


def _pending(capability_symbol: str) -> ShapeAPendingConfirmationRequest:
    return ShapeAPendingConfirmationRequest(
        capability_symbol=capability_symbol,
        contract_id=f"contract-{capability_symbol.lower()}",
        operation_id=f"operation-{capability_symbol.lower()}",
        semantic_fields=(("field", "value"),),
        target_identity_digest="a" * 64,
        target_fingerprint="b" * 64,
        intent_digest="c" * 64,
        expires_at=_EXPIRES_REQUEST,
        expected_authority_id=_AUTHORITY_ID,
        expected_algorithm=ACCEPTED_ALGORITHM,
    )


def _manifest():
    requests = tuple(_pending(symbol) for symbol in _TWO_SYMBOLS)
    return build_shape_a_confirmation_batch_manifest(requests, batch_id="batch-1")


def _authority() -> tuple[Ed25519PrivateKey, PinnedAuthority]:
    private_key = Ed25519PrivateKey.generate()
    authority = PinnedAuthority(authority_id=_AUTHORITY_ID, public_key=private_key.public_key().public_bytes_raw())
    return private_key, authority


def test_build_payload_binds_manifest_digest_independently():
    """Uses the module-level `compute_shape_a_confirmation_batch_manifest_digest`
    import above rather than a function-local re-import: a local import
    executes at test-RUN time, so if another test's isolation check has
    deleted/reloaded `pfsense_mcp.tier1.shape_a_confirmation_batch_manifest`
    from `sys.modules` in the same xdist worker by then, a fresh re-import
    would resolve to a different `ShapeAConfirmationBatchManifest` class
    object than the one `manifest` (built via this file's own top-level
    import, captured at collection time) is actually an instance of --
    `isinstance()` inside `compute_shape_a_confirmation_batch_manifest_digest()`
    would then fail closed on a false mismatch. Both names captured at
    module level together stay self-consistent regardless of what
    `sys.modules` holds later (found via `tests/api_surface/
    test_catalogue_isolation.py`'s own blanket `pfsense_mcp.tier1.*`
    reload, which triggered exactly this under `make quick`'s xdist run)."""

    manifest = _manifest()
    payload = build_shape_a_confirmation_batch_owner_approval_payload(
        manifest, batch_id="batch-1", issued_at=_NOW, expires_at=_APPROVAL_EXPIRES
    )
    assert payload.manifest_digest == compute_shape_a_confirmation_batch_manifest_digest(manifest)
    assert tuple(entry.capability_symbol for entry in payload.entries) == manifest.capability_symbols


def test_sign_and_verify_round_trip():
    manifest = _manifest()
    private_key, authority = _authority()
    payload = build_shape_a_confirmation_batch_owner_approval_payload(
        manifest, batch_id="batch-1", issued_at=_NOW, expires_at=_APPROVAL_EXPIRES
    )
    approval = sign_shape_a_confirmation_batch_owner_approval(
        payload, authority_id=authority.authority_id, private_key=private_key
    )

    assert (
        verify_shape_a_confirmation_batch_owner_approval_signature(approval, PinnedAuthoritySet((authority,))) is True
    )


def test_verify_fails_for_wrong_authority():
    manifest = _manifest()
    private_key, authority = _authority()
    _wrong_private_key, wrong_authority = _authority()
    payload = build_shape_a_confirmation_batch_owner_approval_payload(
        manifest, batch_id="batch-1", issued_at=_NOW, expires_at=_APPROVAL_EXPIRES
    )
    approval = sign_shape_a_confirmation_batch_owner_approval(
        payload, authority_id=authority.authority_id, private_key=private_key
    )

    assert (
        verify_shape_a_confirmation_batch_owner_approval_signature(approval, PinnedAuthoritySet((wrong_authority,)))
        is False
    )


@pytest.mark.parametrize("field,value", [("manifest_digest", "f" * 64), ("batch_id", "batch-tampered")])
def test_verify_fails_when_a_signed_field_is_tampered(field, value):
    manifest = _manifest()
    private_key, authority = _authority()
    payload = build_shape_a_confirmation_batch_owner_approval_payload(
        manifest, batch_id="batch-1", issued_at=_NOW, expires_at=_APPROVAL_EXPIRES
    )
    approval = sign_shape_a_confirmation_batch_owner_approval(
        payload, authority_id=authority.authority_id, private_key=private_key
    )
    tampered = replace(approval, **{field: value})

    assert (
        verify_shape_a_confirmation_batch_owner_approval_signature(tampered, PinnedAuthoritySet((authority,))) is False
    )


def test_verify_fails_when_an_entry_contract_id_is_tampered():
    manifest = _manifest()
    private_key, authority = _authority()
    payload = build_shape_a_confirmation_batch_owner_approval_payload(
        manifest, batch_id="batch-1", issued_at=_NOW, expires_at=_APPROVAL_EXPIRES
    )
    approval = sign_shape_a_confirmation_batch_owner_approval(
        payload, authority_id=authority.authority_id, private_key=private_key
    )
    tampered_entries = tuple(
        replace(entry, contract_id="contract-substituted") if entry.capability_symbol == "SYSTEM_TIMEZONE" else entry
        for entry in approval.entries
    )
    tampered = replace(approval, entries=tampered_entries)

    assert (
        verify_shape_a_confirmation_batch_owner_approval_signature(tampered, PinnedAuthoritySet((authority,))) is False
    )


def test_serialization_round_trip_preserves_verifiability():
    manifest = _manifest()
    private_key, authority = _authority()
    payload = build_shape_a_confirmation_batch_owner_approval_payload(
        manifest, batch_id="batch-1", issued_at=_NOW, expires_at=_APPROVAL_EXPIRES
    )
    approval = sign_shape_a_confirmation_batch_owner_approval(
        payload, authority_id=authority.authority_id, private_key=private_key
    )

    reloaded = shape_a_confirmation_batch_owner_approval_from_bytes(
        shape_a_confirmation_batch_owner_approval_to_bytes(approval)
    )

    assert reloaded == approval
    assert (
        verify_shape_a_confirmation_batch_owner_approval_signature(reloaded, PinnedAuthoritySet((authority,))) is True
    )


def test_from_bytes_refuses_malformed_json():
    with pytest.raises(ShapeAConfirmationBatchOwnerApprovalError, match="not valid JSON"):
        shape_a_confirmation_batch_owner_approval_from_bytes(b"not json")


def test_schema_version_is_current():
    assert SHAPE_A_CONFIRMATION_BATCH_OWNER_APPROVAL_SCHEMA_VERSION == 1
