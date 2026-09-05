"""ADR-037/ADR-022 amendment (2026-09-05): an immutable, human-reviewable
batch manifest binding N Shape-A authorization previews to one owner
approval, so a homogeneous WRITE batch of 20-50 capabilities requires
exactly one literal owner `yes` instead of one per capability.

## Why this exists

Round-1 Batch-1 (5 capabilities) already required five separate,
literal, interactively-typed `yes` responses -- one full ceremony per
capability. The owner's own explicit direction: "The current ceremony
requiring one literal owner `yes` per capability does not scale. Future
homogeneous batches are expected to contain 20-50 WRITE capabilities...
Preserve explicit human owner authorization, but redesign the ceremony
so the normal model becomes: exact immutable batch manifest -> one
complete human review -> one literal owner `yes` -> N individually
verifiable authorization artifacts."

## What this module is, and is not

This is a **derived, read-only view** over already-integrity-verified
`ShapeAAuthorizationPreview` artifacts -- never a new source of truth,
never itself cryptographically signed by any authority, and never
itself sufficient to authorize anything on its own. Its sole purposes
are: (1) collapse N previews into one deterministic, canonical,
human-reviewable structure so an operator approves the *exact* set
once, and (2) produce one deterministic digest of that exact structure
for audit/logging, so a specific owner approval can later be tied to a
specific, unambiguous batch content. Approving a manifest never
produces a signature by itself -- the caller (`write_batch1_signing.py`)
still independently signs N individual `PlanAuthorizationV2` artifacts
afterward, one per capability, each exactly as verifiable in isolation
as before this module existed (see that module's own `sign_
authorization_batch_command()`).

## Strict invariants this module enforces (fail closed, never silently
## downgrades a bad input into a narrower/partial manifest)

- The input MUST be an explicit, finite, already-integrity-verified
  tuple of `ShapeAAuthorizationPreview` objects -- never a capability
  count, a wildcard, or a "discover what's registered" query. There is
  no `--all-registered` equivalent anywhere in this module.
- Empty input is refused.
- Duplicate `capability_symbol` values are refused.
- Every preview in one manifest MUST share the exact same
  `requested_plan_digest`, `requested_step_id`,
  `target_capability_posture`, and `target_anchor_assurance` --
  refused otherwise. This is deliberate, not a limitation to be lifted
  later: it is what makes "one posture check governs the whole batch"
  meaningful. A batch spanning two different plan digests or step IDs
  would silently launder a "mixed risk class" or "different posture
  target" case into looking like one homogeneous approval; this module
  refuses to construct a manifest for that shape at all, forcing any
  such heterogeneous set to be split into separate, separately-reviewed
  manifests instead.
- The manifest's own capability ordering is always the canonical
  sorted order of `capability_symbol`, computed by this module,
  regardless of the order previews were supplied in -- so two calls
  with the same *set* of previews in a different *order* always
  produce byte-identical canonical output and the identical digest;
  reordering the input can never change what is reviewed or signed.
- Nothing in this manifest is ever mutable after construction
  (`@dataclass(frozen=True)` throughout, plain immutable tuples).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ..security_posture_types import AnchorAssurance, CapabilityPosture
from .canonical import CanonicalValue, canonical_json
from .errors import Tier1Error
from .shape_a_artifact_exchange import ShapeAAuthorizationPreview

SHAPE_A_BATCH_MANIFEST_SCHEMA_VERSION = 1

#: Domain-separation literal for the manifest digest -- mirrors
#: `anchor_evidence_export.py`'s own `_SIGNING_DOMAIN` literal-string
#: precedent rather than adding a new `tier1.canonical.DigestPurpose`
#: member: this digest is never used as an HMAC/signature pre-image for
#: any *other* artifact type in this codebase, so a plain domain-
#: separated SHA-256 (not `digest_value()`) is sufficient and avoids
#: touching the widely shared `DigestPurpose` enum for a narrow,
#: display/audit-only value.
_MANIFEST_DIGEST_DOMAIN = b"pfsense-mcp-shape-a-batch-manifest-v1\0"

_MAX_BATCH_SIZE = 200


class ShapeABatchManifestError(Tier1Error):
    """Refused: empty batch, duplicate capability, or a batch whose
    previews do not share one homogeneous plan_digest/step_id/target."""


@dataclass(frozen=True)
class ShapeABatchManifestEntry:
    """Exactly the per-capability fields an owner needs to review one
    entry's projected mutation -- a narrowed, display-oriented copy of
    the corresponding `ShapeAAuthorizationPreview`'s own fields, never
    a new source of truth for them."""

    capability_symbol: str
    execution_intent_digest: str
    semantic_fields: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ShapeABatchManifest:
    """The complete, immutable content one owner `yes` approves.
    Constructing an instance never performs I/O, never signs anything,
    and never consumes or admits anything into any store."""

    schema_version: int
    batch_id: str
    capability_symbols: tuple[str, ...]
    entries: tuple[ShapeABatchManifestEntry, ...]
    requested_plan_digest: str
    requested_step_id: str
    target_capability_posture: CapabilityPosture
    target_anchor_assurance: AnchorAssurance


def build_shape_a_batch_manifest(
    previews: tuple[ShapeAAuthorizationPreview, ...], *, batch_id: str
) -> ShapeABatchManifest:
    """The one place a `ShapeABatchManifest` is constructed. `previews`
    must already be individually integrity-verified by the caller
    (`load_shape_a_authorization_preview()`, unchanged) -- this
    function never reads a file and never checks a MAC; it only
    validates cross-preview consistency and canonicalizes ordering."""

    if not isinstance(previews, tuple) or not previews:
        raise ShapeABatchManifestError("A batch manifest requires a non-empty, explicit tuple of previews.")
    if len(previews) > _MAX_BATCH_SIZE:
        raise ShapeABatchManifestError(f"Batch size {len(previews)} exceeds the maximum of {_MAX_BATCH_SIZE}.")
    if not all(isinstance(preview, ShapeAAuthorizationPreview) for preview in previews):
        raise ShapeABatchManifestError("Every batch entry must be an already-verified ShapeAAuthorizationPreview.")
    if not isinstance(batch_id, str) or not batch_id:
        raise ShapeABatchManifestError("batch_id must be a non-empty string.")

    symbols = [preview.capability_symbol for preview in previews]
    if len(set(symbols)) != len(symbols):
        raise ShapeABatchManifestError("Batch manifest must not contain duplicate capability_symbol entries.")

    first = previews[0]
    for preview in previews[1:]:
        if (
            preview.requested_plan_digest != first.requested_plan_digest
            or preview.requested_step_id != first.requested_step_id
            or preview.target_capability_posture is not first.target_capability_posture
            or preview.target_anchor_assurance is not first.target_anchor_assurance
        ):
            raise ShapeABatchManifestError(
                "Batch manifest requires every preview to share the exact same requested_plan_digest, "
                "requested_step_id, target_capability_posture, and target_anchor_assurance -- refusing a "
                "heterogeneous batch that would obscure a mixed-posture or mixed-risk-class approval."
            )

    ordered = sorted(previews, key=lambda preview: preview.capability_symbol)
    entries = tuple(
        ShapeABatchManifestEntry(
            capability_symbol=preview.capability_symbol,
            execution_intent_digest=preview.execution_intent_digest,
            semantic_fields=preview.semantic_fields,
        )
        for preview in ordered
    )
    return ShapeABatchManifest(
        schema_version=SHAPE_A_BATCH_MANIFEST_SCHEMA_VERSION,
        batch_id=batch_id,
        capability_symbols=tuple(entry.capability_symbol for entry in entries),
        entries=entries,
        requested_plan_digest=first.requested_plan_digest,
        requested_step_id=first.requested_step_id,
        target_capability_posture=first.target_capability_posture,
        target_anchor_assurance=first.target_anchor_assurance,
    )


def _manifest_payload(manifest: ShapeABatchManifest) -> dict[str, CanonicalValue]:
    return {
        "schema_version": manifest.schema_version,
        "batch_id": manifest.batch_id,
        "capability_symbols": list(manifest.capability_symbols),
        "entries": [
            {
                "capability_symbol": entry.capability_symbol,
                "execution_intent_digest": entry.execution_intent_digest,
                "semantic_fields": [list(pair) for pair in entry.semantic_fields],
            }
            for entry in manifest.entries
        ],
        "requested_plan_digest": manifest.requested_plan_digest,
        "requested_step_id": manifest.requested_step_id,
        "target_capability_posture": manifest.target_capability_posture.value,
        "target_anchor_assurance": manifest.target_anchor_assurance.value,
    }


def compute_shape_a_batch_manifest_digest(manifest: ShapeABatchManifest) -> str:
    """Pure, deterministic. Never signs, never touches a key, never
    performs I/O. Two manifests built from the same *set* of previews
    (any input order) always produce the identical digest; changing
    any capability, projection, digest, or target changes it."""

    if not isinstance(manifest, ShapeABatchManifest):
        raise ShapeABatchManifestError("Expected ShapeABatchManifest.")
    hasher = hashlib.sha256()
    hasher.update(_MANIFEST_DIGEST_DOMAIN)
    hasher.update(canonical_json(_manifest_payload(manifest)))
    return hasher.hexdigest()


def render_shape_a_batch_manifest_review(manifest: ShapeABatchManifest) -> str:
    """One combined, human-readable review covering every capability in
    the manifest -- the sole thing an owner reads before typing the one
    literal `yes` this batch requires."""

    lines = [
        f"Batch authorization review -- {len(manifest.entries)} capabilities, ONE owner approval",
        f"  batch_id:              {manifest.batch_id}",
        f"  manifest_digest:       {compute_shape_a_batch_manifest_digest(manifest)}",
        f"  requested_plan_digest: {manifest.requested_plan_digest}",
        f"  requested_step_id:     {manifest.requested_step_id}",
        f"  target_capability_posture: {manifest.target_capability_posture.value}",
        f"  target_anchor_assurance:   {manifest.target_anchor_assurance.value}",
        "",
        "Capabilities in this batch (canonical order):",
    ]
    for entry in manifest.entries:
        lines.append(f"  - {entry.capability_symbol}")
        lines.append(f"      execution_intent_digest: {entry.execution_intent_digest}")
        for name, value in entry.semantic_fields:
            lines.append(f"      {name} = {value}")
    lines.append("")
    lines.append(
        "Approving this batch authorizes signing exactly these "
        f"{len(manifest.entries)} capabilities against exactly this plan digest -- "
        "no other capability, no future addition, no substitution."
    )
    return "\n".join(lines)


__all__ = [
    "SHAPE_A_BATCH_MANIFEST_SCHEMA_VERSION",
    "ShapeABatchManifest",
    "ShapeABatchManifestEntry",
    "ShapeABatchManifestError",
    "build_shape_a_batch_manifest",
    "compute_shape_a_batch_manifest_digest",
    "render_shape_a_batch_manifest_review",
]
