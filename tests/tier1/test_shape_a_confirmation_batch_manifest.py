"""Tests for the 2026-09-05 `ShapeAConfirmationBatchManifest` addition --
the confirmation-side counterpart to `shape_a_batch_manifest.py`. Its
homogeneity predicate is deliberately different: `expected_authority_id`/
`expected_algorithm` only, never a shared plan digest (no such shared
fact exists for confirmations -- see the module's own docstring).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM
from pfsense_mcp.tier1.shape_a_artifact_exchange import ShapeAPendingConfirmationRequest
from pfsense_mcp.tier1.shape_a_confirmation_batch_manifest import (
    SHAPE_A_CONFIRMATION_BATCH_MANIFEST_SCHEMA_VERSION,
    ShapeAConfirmationBatchManifestError,
    build_shape_a_confirmation_batch_manifest,
    compute_shape_a_confirmation_batch_manifest_digest,
    render_shape_a_confirmation_batch_manifest_review,
)

_NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
_EXPIRES = _NOW + timedelta(minutes=5)
_AUTHORITY_ID = "confirm-owner-1"

_FIVE_SYMBOLS = (
    "NTP_TIME_SERVER_PREFER",
    "NTP_SETTINGS_OBSERVABILITY_TOGGLES",
    "LOG_DISPLAY_PREFERENCES",
    "LOG_RETENTION_SETTINGS",
    "SYSTEM_TIMEZONE",
)


def _pending(
    capability_symbol: str,
    *,
    contract_id: str | None = None,
    operation_id: str | None = None,
    intent_digest: str | None = None,
    expected_authority_id: str = _AUTHORITY_ID,
    expected_algorithm: str = ACCEPTED_ALGORITHM,
) -> ShapeAPendingConfirmationRequest:
    return ShapeAPendingConfirmationRequest(
        capability_symbol=capability_symbol,
        contract_id=contract_id or f"contract-{capability_symbol.lower()}",
        operation_id=operation_id or f"operation-{capability_symbol.lower()}",
        semantic_fields=(("field", "value"),),
        target_identity_digest="a" * 64,
        target_fingerprint="b" * 64,
        intent_digest=intent_digest or "c" * 64,
        expires_at=_EXPIRES,
        expected_authority_id=expected_authority_id,
        expected_algorithm=expected_algorithm,
    )


def test_refuses_empty_batch():
    with pytest.raises(ShapeAConfirmationBatchManifestError, match="non-empty"):
        build_shape_a_confirmation_batch_manifest((), batch_id="batch-1")


def test_refuses_duplicate_capability_symbol():
    requests = (_pending("SYSTEM_TIMEZONE"), _pending("SYSTEM_TIMEZONE"))
    with pytest.raises(ShapeAConfirmationBatchManifestError, match="duplicate"):
        build_shape_a_confirmation_batch_manifest(requests, batch_id="batch-1")


def test_refuses_oversized_batch():
    requests = tuple(_pending("SYSTEM_TIMEZONE", contract_id=f"contract-{i}") for i in range(201))
    with pytest.raises(ShapeAConfirmationBatchManifestError, match="exceeds the maximum"):
        build_shape_a_confirmation_batch_manifest(requests, batch_id="batch-1")


@pytest.mark.parametrize(
    ("field", "value"),
    [("expected_authority_id", "a-different-authority"), ("expected_algorithm", "not-ed25519")],
)
def test_refuses_heterogeneous_batch(field, value):
    first = _pending("SYSTEM_TIMEZONE")
    kwargs = {field: value}
    second = _pending("LOG_RETENTION_SETTINGS", **kwargs)
    with pytest.raises(ShapeAConfirmationBatchManifestError, match="share the exact same"):
        build_shape_a_confirmation_batch_manifest((first, second), batch_id="batch-1")


def test_builds_a_valid_batch_with_distinct_contract_and_operation_ids():
    """Unlike authorization previews, confirmations are NOT required to
    share any digest -- each capability's own contract_id/operation_id/
    intent_digest is expected to differ."""

    requests = tuple(_pending(symbol) for symbol in _FIVE_SYMBOLS)
    manifest = build_shape_a_confirmation_batch_manifest(requests, batch_id="batch-1")

    assert manifest.schema_version == SHAPE_A_CONFIRMATION_BATCH_MANIFEST_SCHEMA_VERSION
    assert manifest.expected_authority_id == _AUTHORITY_ID
    assert manifest.expected_algorithm == ACCEPTED_ALGORITHM
    assert manifest.capability_symbols == tuple(sorted(_FIVE_SYMBOLS))
    contract_ids = {entry.contract_id for entry in manifest.entries}
    assert len(contract_ids) == 5


def test_canonical_ordering_is_independent_of_input_order():
    requests_forward = tuple(_pending(symbol) for symbol in _FIVE_SYMBOLS)
    requests_reversed = tuple(reversed(requests_forward))

    manifest_forward = build_shape_a_confirmation_batch_manifest(requests_forward, batch_id="batch-1")
    manifest_reversed = build_shape_a_confirmation_batch_manifest(requests_reversed, batch_id="batch-1")

    assert manifest_forward.capability_symbols == manifest_reversed.capability_symbols == tuple(sorted(_FIVE_SYMBOLS))


def test_digest_is_deterministic_and_order_independent():
    requests_forward = tuple(_pending(symbol) for symbol in _FIVE_SYMBOLS)
    requests_reversed = tuple(reversed(requests_forward))

    manifest_forward = build_shape_a_confirmation_batch_manifest(requests_forward, batch_id="batch-1")
    manifest_reversed = build_shape_a_confirmation_batch_manifest(requests_reversed, batch_id="batch-1")

    digest_forward = compute_shape_a_confirmation_batch_manifest_digest(manifest_forward)
    digest_reversed = compute_shape_a_confirmation_batch_manifest_digest(manifest_reversed)

    assert digest_forward == digest_reversed
    assert len(digest_forward) == 64


def test_digest_changes_when_a_contract_id_changes():
    requests_a = tuple(_pending(symbol) for symbol in _FIVE_SYMBOLS)
    requests_b = (*requests_a[:-1], _pending(_FIVE_SYMBOLS[-1], contract_id="a-different-contract"))
    manifest_a = build_shape_a_confirmation_batch_manifest(requests_a, batch_id="batch-1")
    manifest_b = build_shape_a_confirmation_batch_manifest(requests_b, batch_id="batch-1")

    assert compute_shape_a_confirmation_batch_manifest_digest(
        manifest_a
    ) != compute_shape_a_confirmation_batch_manifest_digest(manifest_b)


def test_render_review_lists_every_capability_and_the_digest():
    requests = tuple(_pending(symbol) for symbol in _FIVE_SYMBOLS)
    manifest = build_shape_a_confirmation_batch_manifest(requests, batch_id="batch-1")
    review = render_shape_a_confirmation_batch_manifest_review(manifest)

    assert compute_shape_a_confirmation_batch_manifest_digest(manifest) in review
    for symbol in _FIVE_SYMBOLS:
        assert symbol in review
    assert "5 capabilities" in review
    assert "ONE owner approval" in review
