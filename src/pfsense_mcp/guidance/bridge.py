"""`GuidanceReference` -> `EvidenceReference` bridge (ADR-018, Accepted --
implements the bridge specified in `docs/VERSION_AWARE_GUIDANCE.md`'s
"`GuidanceReference` -> `EvidenceReference` bridge" section; owner-
authorized implementation slice, 2026-08-09).

Pure, deterministic, side-effect-free: performs **zero independent
inference**. `registry.lookup_guidance()` already computed every
classification field (`applicability`/`evidence_level`/
`applicable_overlay_chain`/`observed_edition_used`/
`observed_version_used`) via `applicability.compute_entry_applicability()`
before this module ever sees the reference -- this function only
reshapes an already-final `GuidanceReference` into an `EvidenceReference`.
It does not perform appliance-identity discovery, does not call
`resolve_appliance_identity()`, does not compute applicability, and does
not touch authorization, PREPARE, WRITE, MCP exposure, or capability
decisions in any way -- there is nothing in its own inputs or outputs
those concerns could be read from (same G1 closed-schema discipline
every type in this package already has).
"""

from __future__ import annotations

from .evidence import EvidenceReference
from .models import GuidanceReference


def bridge_guidance_reference(ref: GuidanceReference) -> EvidenceReference:
    """Exactly one `EvidenceReference` out for exactly one
    `GuidanceReference` in -- never zero, never multiple. Does not
    filter by `applicability` (an `EDITION_MISMATCH`/`STALE` entry is
    bridged just as faithfully as an `APPLICABLE` one); filtering, if a
    future caller ever wants it, is that caller's own policy choice,
    applied after this function, never inside it -- a bridge that
    filters is a bridge making a decision it has no business making.

    `trust_label` is the one `GuidanceReference` field with no
    `EvidenceReference` equivalent -- intentionally, not accidentally,
    omitted. Confirmed by the design pass that specified this bridge:
    `trust_label` is currently always the constant `"pinned-summary"`
    (renamed 2026-08-22 from `"pinned-snapshot"` to match the summary-based
    provenance model -- see `models.py`'s module docstring) for the only
    `retrieval_mode` that exists today (`RetrievalMode.BUNDLED_SNAPSHOT`),
    making it fully redundant with `retrieval_mode` in this accepted
    scope. That specific mapping -- `retrieval_mode == BUNDLED_SNAPSHOT`
    implies `trust_label == "pinned-summary"` for every reference this
    function will ever see while only `BUNDLED_SNAPSHOT` exists -- is
    asserted directly here (not merely assumed) so a future
    `retrieval_mode` addition (TB-G3 live retrieval, still unactivated)
    that breaks the assumption fails loudly at the point of bridging, not
    silently. This assertion is the one and only judgment this function
    makes about its input; it never computes a new value from it.

    `content_excerpt`/`content_hash` were renamed `summary`/`summary_hash`
    on both `GuidanceReference` and `EvidenceReference` in the same
    2026-08-22 revision (project-authored summary, not a quotation) -- the
    field-for-field copy below is otherwise unchanged.
    """
    if ref.retrieval_mode.value == "bundled_snapshot" and ref.trust_label != "pinned-summary":
        raise ValueError(
            f"bridge_guidance_reference: trust_label {ref.trust_label!r} no longer matches the "
            "documented bundled_snapshot assumption ('pinned-summary') this bridge relies on to "
            "omit trust_label safely -- re-examine the trust_label/retrieval_mode mapping before "
            "extending retrieval modes further."
        )

    return EvidenceReference(
        capability=ref.capability,
        source_id=ref.source_id,
        title=ref.title,
        canonical_url=ref.canonical_url,
        summary=ref.summary,
        summary_hash=ref.summary_hash,
        pfsense_edition=ref.pfsense_edition,
        evidence_level=ref.evidence_level,
        applicability=ref.applicability,
        applicable_overlay_chain=ref.applicable_overlay_chain,
        observed_edition_used=ref.observed_edition_used,
        observed_version_used=ref.observed_version_used,
        retrieval_mode=ref.retrieval_mode,
        snapshot_version=ref.snapshot_version,
    )
