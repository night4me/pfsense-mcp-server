"""`GuidanceEvidence` composition (ADR-018 Accepted, §5 -- "the
read-recommendation composition model"; this module is ADR-018
Implementation Step 3). Still entirely offline, still not wired into
anything: no MCP tool, no READ tool, no Tier 1 PREPARE consumer.

ADR-018 §5 names exactly this as the "smallest future integration point,
if ever authorized: a single new orchestration function (not a new MCP
tool, not a change to any of the 42 existing tools)." This module is
that orchestration function and nothing more -- it assembles a
`GuidanceEvidence` from already-resolved pieces (`ApplianceIdentity` from
Step 1, `EvidenceReference` values from Step 2) using only the
deterministic primitives Step 2's acceptance already covers
(`compute_overall_state()`, `cap_applicability_by_evidence_level()`). It
does **not** implement the deferred single-entry `APPLICABLE`/
`PARTIALLY_APPLICABLE`/`STALE` decision procedure
(`applicability.applicability_state_for_entry_is_not_implemented_here()`)
-- every `EvidenceReference` this module consumes must already carry its
own `applicability` value, computed elsewhere (still nowhere in this
codebase, since that procedure remains an explicitly deferred,
non-blocking, owner-preserved question per ADR-018's Acceptance record).

No duplicate appliance-identity inference path: this module never calls
`resolve_appliance_identity()` itself and never re-derives edition/
version from anything -- it only reads fields off an `ApplianceIdentity`
the caller already resolved via Step 1's one canonical assembly point.

Guidance remains evidence, never authorization (TB-G4, restated by
ADR-018 unchanged): nothing in this module is read by
`pfsense_mcp.tier1.state_machine` or any confirmation-digest computation
-- verified directly, not only documented, by
`tests/guidance/test_composition_isolation.py`.
"""

from __future__ import annotations

from collections.abc import Sequence

from .appliance_identity import ApplianceIdentity
from .applicability import cap_applicability_by_evidence_level, compute_overall_state
from .evidence import EvidenceReference, GuidanceEvidence


def compose_guidance_evidence(
    *,
    capability: str,
    identity: ApplianceIdentity,
    guidance: Sequence[EvidenceReference],
    overlay_chain: Sequence[str] | None = None,
) -> GuidanceEvidence:
    """Assemble a `GuidanceEvidence` for one capability from an
    already-resolved `ApplianceIdentity` and already-classified
    `EvidenceReference` values. Pure -- no I/O, no network, no clock read
    beyond what `identity`/`guidance` already carry.

    Fail-closed input validation (raises `ValueError`, never silently
    drops or reinterprets a mismatched entry):

    - every `guidance` entry's `.capability` must equal `capability` --
      refuses to silently mix evidence from a different capability into
      one `GuidanceEvidence`.
    - every `guidance` entry's `.observed_edition_used`/
      `.observed_version_used` must equal `identity.observed_edition`/
      `identity.observed_version` -- refuses to silently compose evidence
      that was classified against a *different* appliance's observed
      state than the one this call concerns.

    `overall_state` is computed from each entry's own `.applicability`,
    **defensively re-capped** by `.evidence_level` via
    `cap_applicability_by_evidence_level()` before aggregation -- so a
    caller-supplied `EvidenceReference` whose `.applicability` is
    inconsistent with its own `.evidence_level` (e.g. `APPLICABLE` paired
    with `INFERRED_FROM_CURRENT_DOCS`, which should never happen upstream
    but this module does not trust that it never will) cannot make
    `overall_state` more favorable than the evidence actually supports.
    This capping is applied only for the purpose of computing
    `overall_state` -- the `EvidenceReference` objects themselves are
    stored in the result completely unmodified (they are frozen; nothing
    here could mutate them even by mistake), preserving full,
    uninterpreted provenance in `GuidanceEvidence.guidance`.

    `overlay_chain` defaults to the union of every entry's own
    `applicable_overlay_chain`, concatenated in `guidance` order and
    deduplicated keeping each overlay_id's first occurrence. This is a
    concatenation, **not** a merge algorithm: it invents no new relative
    ordering between overlay_ids that appear in more than one entry's
    chain in a different order than each other -- that class of conflict
    is a registry-integrity concern
    (`applicability.find_duplicate_scope_conflicts()`/
    `find_supersession_chain_defects()`), expected to be caught before
    any `EvidenceReference` reaches this function, not arbitrated here.
    A caller may pass `overlay_chain` explicitly (e.g. already computed
    via `applicability.order_overlay_chain()` against a real overlay
    registry) to bypass this default entirely.
    """
    for entry in guidance:
        if entry.capability != capability:
            raise ValueError(
                f"EvidenceReference.capability {entry.capability!r} does not match "
                f"the requested capability {capability!r}"
            )
        if entry.observed_edition_used != identity.observed_edition:
            raise ValueError(
                f"EvidenceReference.observed_edition_used {entry.observed_edition_used!r} does not match "
                f"identity.observed_edition {identity.observed_edition!r}"
            )
        if entry.observed_version_used != identity.observed_version:
            raise ValueError(
                f"EvidenceReference.observed_version_used {entry.observed_version_used!r} does not match "
                f"identity.observed_version {identity.observed_version!r}"
            )

    effective_states = [
        cap_applicability_by_evidence_level(entry.evidence_level, entry.applicability) for entry in guidance
    ]
    overall_state = compute_overall_state(effective_states)

    resolved_overlay_chain: tuple[str, ...]
    if overlay_chain is not None:
        resolved_overlay_chain = tuple(overlay_chain)
    else:
        seen: set[str] = set()
        merged: list[str] = []
        for entry in guidance:
            for overlay_id in entry.applicable_overlay_chain:
                if overlay_id not in seen:
                    seen.add(overlay_id)
                    merged.append(overlay_id)
        resolved_overlay_chain = tuple(merged)

    return GuidanceEvidence(
        capability=capability,
        observed_edition=identity.observed_edition,
        observed_version=identity.observed_version,
        appliance_identity_source=identity.identity_source,
        guidance=tuple(guidance),
        overlay_chain=resolved_overlay_chain,
        overall_state=overall_state,
    )
