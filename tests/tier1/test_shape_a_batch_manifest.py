"""Tests for the 2026-09-05 `ShapeABatchManifest` addition -- an immutable,
read-only, non-signing view over N already-integrity-verified
`ShapeAAuthorizationPreview` artifacts, letting one owner review/approval
cover a whole homogeneous batch instead of one ceremony per capability.

Every preview constructed here is synthetic (no real signer, no real
production evidence) -- this module never signs anything and never
touches a key.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from pfsense_mcp.security_posture_types import AnchorAssurance, CapabilityPosture
from pfsense_mcp.tier1.shape_a_artifact_exchange import ShapeAAuthorizationPreview
from pfsense_mcp.tier1.shape_a_batch_manifest import (
    SHAPE_A_BATCH_MANIFEST_SCHEMA_VERSION,
    ShapeABatchManifestError,
    build_shape_a_batch_manifest,
    compute_shape_a_batch_manifest_digest,
    render_shape_a_batch_manifest_review,
)

_PLAN_DIGEST = "a" * 64
_STEP_ID = "milestone-9-write-activation"
_POSTURE = CapabilityPosture.WRITE_PROTECTED
_ASSURANCE = AnchorAssurance.HARDWARE_WITNESS
_NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)

_FIVE_SYMBOLS = (
    "NTP_TIME_SERVER_PREFER",
    "NTP_SETTINGS_OBSERVABILITY_TOGGLES",
    "LOG_DISPLAY_PREFERENCES",
    "LOG_RETENTION_SETTINGS",
    "SYSTEM_TIMEZONE",
)


def _preview(
    capability_symbol: str,
    *,
    execution_intent_digest: str | None = None,
    requested_plan_digest: str = _PLAN_DIGEST,
    requested_step_id: str = _STEP_ID,
    target_capability_posture: CapabilityPosture = _POSTURE,
    target_anchor_assurance: AnchorAssurance = _ASSURANCE,
) -> ShapeAAuthorizationPreview:
    digest = execution_intent_digest or hashlib.sha256(capability_symbol.encode()).hexdigest()
    return ShapeAAuthorizationPreview(
        capability_symbol=capability_symbol,
        semantic_fields=(("field", "value"),),
        execution_intent_digest=digest,
        requested_plan_digest=requested_plan_digest,
        requested_step_id=requested_step_id,
        target_capability_posture=target_capability_posture,
        target_anchor_assurance=target_anchor_assurance,
        generated_at=_NOW,
    )


def test_refuses_empty_batch():
    with pytest.raises(ShapeABatchManifestError, match="non-empty"):
        build_shape_a_batch_manifest((), batch_id="batch-1")


def test_refuses_non_tuple_input():
    with pytest.raises(ShapeABatchManifestError, match="non-empty"):
        build_shape_a_batch_manifest([_preview("SYSTEM_TIMEZONE")], batch_id="batch-1")  # type: ignore[arg-type]


def test_refuses_empty_batch_id():
    with pytest.raises(ShapeABatchManifestError, match="batch_id"):
        build_shape_a_batch_manifest((_preview("SYSTEM_TIMEZONE"),), batch_id="")


def test_refuses_duplicate_capability_symbol():
    previews = (_preview("SYSTEM_TIMEZONE"), _preview("SYSTEM_TIMEZONE"))
    with pytest.raises(ShapeABatchManifestError, match="duplicate"):
        build_shape_a_batch_manifest(previews, batch_id="batch-1")


def test_refuses_oversized_batch():
    # The size check runs before the duplicate-symbol check, so a batch of
    # 201 entries sharing one capability_symbol still exercises the size
    # guard specifically, not the duplicate guard.
    previews = tuple(_preview("SYSTEM_TIMEZONE", execution_intent_digest=f"{i:064x}") for i in range(201))
    with pytest.raises(ShapeABatchManifestError, match="exceeds the maximum"):
        build_shape_a_batch_manifest(previews, batch_id="batch-1")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("requested_plan_digest", "b" * 64),
        ("requested_step_id", "a-different-step-id"),
        ("target_capability_posture", CapabilityPosture.READ_ONLY),
        ("target_anchor_assurance", AnchorAssurance.SOFTWARE),
    ],
)
def test_refuses_heterogeneous_batch(field, value):
    first = _preview("SYSTEM_TIMEZONE")
    kwargs = {field: value}
    second = _preview("LOG_RETENTION_SETTINGS", **kwargs)
    with pytest.raises(ShapeABatchManifestError, match=r"homogeneous|share the exact same"):
        build_shape_a_batch_manifest((first, second), batch_id="batch-1")


def test_builds_a_valid_homogeneous_batch():
    previews = tuple(_preview(symbol) for symbol in _FIVE_SYMBOLS)
    manifest = build_shape_a_batch_manifest(previews, batch_id="batch-1")

    assert manifest.schema_version == SHAPE_A_BATCH_MANIFEST_SCHEMA_VERSION
    assert manifest.batch_id == "batch-1"
    assert manifest.requested_plan_digest == _PLAN_DIGEST
    assert manifest.requested_step_id == _STEP_ID
    assert manifest.target_capability_posture is _POSTURE
    assert manifest.target_anchor_assurance is _ASSURANCE
    assert manifest.capability_symbols == tuple(sorted(_FIVE_SYMBOLS))
    assert len(manifest.entries) == 5


def test_canonical_ordering_is_independent_of_input_order():
    previews_forward = tuple(_preview(symbol) for symbol in _FIVE_SYMBOLS)
    previews_reversed = tuple(reversed(previews_forward))

    manifest_forward = build_shape_a_batch_manifest(previews_forward, batch_id="batch-1")
    manifest_reversed = build_shape_a_batch_manifest(previews_reversed, batch_id="batch-1")

    assert manifest_forward.capability_symbols == manifest_reversed.capability_symbols
    assert manifest_forward.capability_symbols == tuple(sorted(_FIVE_SYMBOLS))


def test_digest_is_deterministic_and_order_independent():
    previews_forward = tuple(_preview(symbol) for symbol in _FIVE_SYMBOLS)
    previews_reversed = tuple(reversed(previews_forward))

    manifest_forward = build_shape_a_batch_manifest(previews_forward, batch_id="batch-1")
    manifest_reversed = build_shape_a_batch_manifest(previews_reversed, batch_id="batch-1")

    digest_forward = compute_shape_a_batch_manifest_digest(manifest_forward)
    digest_reversed = compute_shape_a_batch_manifest_digest(manifest_reversed)

    assert digest_forward == digest_reversed
    assert len(digest_forward) == 64
    assert all(c in "0123456789abcdef" for c in digest_forward)


def test_digest_changes_when_batch_id_changes():
    previews = tuple(_preview(symbol) for symbol in _FIVE_SYMBOLS)
    manifest_a = build_shape_a_batch_manifest(previews, batch_id="batch-a")
    manifest_b = build_shape_a_batch_manifest(previews, batch_id="batch-b")

    assert compute_shape_a_batch_manifest_digest(manifest_a) != compute_shape_a_batch_manifest_digest(manifest_b)


def test_digest_changes_when_a_capability_execution_intent_digest_changes():
    previews_a = tuple(_preview(symbol) for symbol in _FIVE_SYMBOLS)
    previews_b = (
        *previews_a[:-1],
        _preview(_FIVE_SYMBOLS[-1], execution_intent_digest="f" * 64),
    )
    manifest_a = build_shape_a_batch_manifest(previews_a, batch_id="batch-1")
    manifest_b = build_shape_a_batch_manifest(previews_b, batch_id="batch-1")

    assert compute_shape_a_batch_manifest_digest(manifest_a) != compute_shape_a_batch_manifest_digest(manifest_b)


def test_digest_rejects_wrong_type():
    with pytest.raises(ShapeABatchManifestError, match="Expected ShapeABatchManifest"):
        compute_shape_a_batch_manifest_digest("not a manifest")  # type: ignore[arg-type]


def test_render_review_lists_every_capability_and_the_digest():
    previews = tuple(_preview(symbol) for symbol in _FIVE_SYMBOLS)
    manifest = build_shape_a_batch_manifest(previews, batch_id="batch-1")
    review = render_shape_a_batch_manifest_review(manifest)

    assert compute_shape_a_batch_manifest_digest(manifest) in review
    for symbol in _FIVE_SYMBOLS:
        assert symbol in review
    assert "5 capabilities" in review
    assert "ONE owner approval" in review


def test_manifest_is_frozen():
    previews = tuple(_preview(symbol) for symbol in _FIVE_SYMBOLS)
    manifest = build_shape_a_batch_manifest(previews, batch_id="batch-1")
    with pytest.raises(Exception):  # noqa: B017 -- frozen dataclass raises FrozenInstanceError
        manifest.batch_id = "tampered"  # type: ignore[misc]
