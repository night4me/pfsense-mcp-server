"""The deterministic `Capability -> DocumentSource` registry (ADR-017 G2),
its `ReleaseOverlay` counterpart (ADR-018), and the one public lookup
function `lookup_guidance()` (I5/I6, extended to inclusion-with-state by
the ADR-018 guidance-bridge implementation slice, 2026-08-09).

`_REGISTRY`/`_OVERLAY_REGISTRY` are Git-tracked Python literals --
authored and reviewed exactly like source code, loaded once at import
time, never mutated at runtime (I2). There is no code path anywhere in
this module that constructs a `DocumentSource`/`ReleaseOverlay` from a
network response, environment variable, or any other request-time
input.

Populating either registry with additional entries is registry-authoring
work, not code review of this module: each new entry needs `title`/
`content_excerpt` (or `caveat_excerpt`) verified against the live
`canonical_url` page at review time (`docs/OFFICIAL_GUIDANCE_LAYER.md`'s
Review checklist, Finding 5), `content_hash` computed from the exact
excerpt text, and should stay within the "no more than ~3 entries per
capability" curation guidance (Finding 7) before this module needs any
code change at all.

**Behavior change from the v0.3.1-shipped version** (the "exclude vs.
exclude-with-state" policy change ADR-018 S2 and its Acceptance record
already named as needing its own explicit approval, separate from
ADR-018's own acceptance -- owner-authorized 2026-08-09): `lookup_guidance()`
no longer excludes non-matching entries. Every registry entry for the
requested capability is returned, each carrying its own computed
`ApplicabilityState` via `applicability.compute_entry_applicability()`.
`NO_OFFICIAL_GUIDANCE_FOUND` remains represented as the empty tuple (no
registry entry for the capability at all) -- unchanged, and formally
confirmed as the correct representation by the same design pass that
authorized this change (see ADR-018's "Acceptance record", deferred
question #2, CLOSED).
"""

from __future__ import annotations

from pfsense_mcp.capabilities import Capability

from .appliance_identity import ObservedEdition
from .applicability import compute_entry_applicability, find_duplicate_scope_conflicts, find_supersession_chain_defects
from .evidence import ReleaseOverlay
from .models import UNVERSIONED, DocumentSource, Edition, EvidenceLevel, GuidanceReference, RetrievalMode, excerpt_hash

#: Bumped only when `_REGISTRY`'s content changes -- carried on every
#: `GuidanceReference` as provenance (I5), never used to change which
#: entries match.
SNAPSHOT_VERSION = "guidance-registry-2026-08-08"

#: The only trust label this accepted (bundled-snapshot-only) scope
#: produces. TB-G3 (deferred) reserves other values for live-fetched
#: content -- none exist yet.
_TRUST_LABEL_PINNED_SNAPSHOT = "pinned-snapshot"

#: One real, verified seed entry: fetched live from the cited URL during
#: this session's own registry-authoring step (the same review discipline
#: a human contributor would apply -- see the module docstring above),
#: quoted verbatim, short enough to stay well within I4's excerpt bound.
#: Thematically the same capability ADR-016 already names as this
#: project's preferred first WRITE-candidate study.
_ALIAS_DOC = DocumentSource(
    source_id="netgate_docs_aliases",
    title="Aliases",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    # Honest default (EvidenceLevel's own docstring): this is Netgate's
    # undated /latest/ aliases page, fetched live during registry-authoring
    # -- it does not itself affirmatively state "applies regardless of
    # version," so it is INFERRED_FROM_CURRENT_DOCS, not
    # EXPLICIT_UNVERSIONED. A real, deliberate consequence of this choice:
    # per the accepted EvidenceLevel cap, this entry can now only ever
    # reach VERSION_UNCONFIRMED, never APPLICABLE, until a curator
    # re-authors it with a genuine EXPLICIT_UNVERSIONED source citation.
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "Aliases define groups of ports, hosts, or networks. They can be "
        "referenced by firewall rules, port forwards, outbound NAT rules, "
        "and several other areas. Using aliases results in configurations "
        "and rulesets which are significantly shorter, self-documenting, "
        "and easier to manage."
    ),
    content_hash="90de20698df2264ffd1e6fd7829270ea49e95f815b687cf162d81eabbe39df56",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC. "
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_REGISTRY: dict[Capability, tuple[DocumentSource, ...]] = {
    Capability.ALIAS_READ: (_ALIAS_DOC,),
}

#: Empty by default -- the correct starting state, same as `_REGISTRY`
#: (at ADR-017's own introduction) and `WriteEndpoints` before their
#: first real entry. Populating this is registry-authoring work, subject
#: to the same review discipline as `_REGISTRY` above.
_OVERLAY_REGISTRY: dict[Capability, tuple[ReleaseOverlay, ...]] = {}


def _all_overlays() -> tuple[ReleaseOverlay, ...]:
    return tuple(overlay for entries in _OVERLAY_REGISTRY.values() for overlay in entries)


def _check_registry_integrity() -> None:
    """Load-time self-check (I3 failure-mode table): every entry's
    `content_hash` must match a freshly computed hash of its own
    `content_excerpt`/`caveat_excerpt`. A mismatch is a build/deploy
    defect and must fail loudly at import time, not be silently served.

    Extended (ADR-018 Finding 8) with the two independent overlay
    registry-integrity checks already implemented in `applicability.py`:
    duplicate-scope conflicts and supersession-chain defects (dangling
    references, cycles) -- both computed only over `_OVERLAY_REGISTRY`,
    matching `find_duplicate_scope_conflicts()`/
    `find_supersession_chain_defects()`'s own accepted, already-tested
    scope (overlay-vs-overlay; `_REGISTRY` has never had more than one
    `DocumentSource` per capability, so a `DocumentSource`-vs-
    `DocumentSource`/overlay duplicate-scope check has no current
    scenario to exercise and is not added by this slice).
    """

    for entries in _REGISTRY.values():
        for entry in entries:
            expected = excerpt_hash(entry.content_excerpt)
            if entry.content_hash != expected:
                raise ValueError(
                    f"guidance registry integrity check failed for {entry.source_id!r}: "
                    f"content_hash {entry.content_hash!r} does not match computed {expected!r}"
                )

    overlays = _all_overlays()
    for overlay in overlays:
        expected = excerpt_hash(overlay.caveat_excerpt)
        if overlay.content_hash != expected:
            raise ValueError(
                f"guidance registry integrity check failed for overlay {overlay.overlay_id!r}: "
                f"content_hash {overlay.content_hash!r} does not match computed {expected!r}"
            )

    duplicates = find_duplicate_scope_conflicts(overlays)
    if duplicates:
        raise ValueError(f"guidance registry integrity check failed: duplicate-scope overlay conflicts: {duplicates}")

    chain_defects = find_supersession_chain_defects(overlays)
    if chain_defects:
        raise ValueError(
            f"guidance registry integrity check failed: overlay supersession chain defects: {chain_defects}"
        )


_check_registry_integrity()


def lookup_guidance(
    capability: Capability,
    observed_version: str | None,
    observed_edition: ObservedEdition,
) -> tuple[GuidanceReference, ...]:
    """Pure, deterministic (I5): identical inputs always produce identical
    output. Fails closed to an empty tuple when the capability has no
    registered entry at all (I6, `NO_OFFICIAL_GUIDANCE_FOUND`) -- never
    raises past this boundary, never fabricates or guesses.

    **Inclusion-with-state** (the accepted policy change, module
    docstring): every registered entry for `capability` is returned, each
    carrying its own `applicability`/`evidence_level`/
    `applicable_overlay_chain`/`observed_edition_used`/
    `observed_version_used` computed by
    `applicability.compute_entry_applicability()` against
    `_OVERLAY_REGISTRY` -- no entry is silently dropped the way the
    v0.3.1-shipped exclude-only version dropped a version/edition
    mismatch.

    `observed_edition` is `ObservedEdition`, never `Edition` (ADR-018
    Finding 1) -- `ObservedEdition.UNKNOWN` replaces the old `None`
    sentinel; `Edition.BOTH` can no longer be passed here at all, by
    construction (the type itself excludes it).
    """

    entries = _REGISTRY.get(capability, ())
    overlays = _all_overlays()
    results: list[GuidanceReference] = []
    for entry in entries:
        applicability, overlay_chain = compute_entry_applicability(
            entry_id=entry.source_id,
            entry_capability=capability.name,
            entry_edition=entry.pfsense_edition,
            entry_version_applicability=entry.version_applicability,
            entry_evidence_level=entry.evidence_level,
            observed_edition=observed_edition,
            observed_version=observed_version,
            all_overlays=overlays,
        )
        results.append(
            GuidanceReference(
                capability=capability.name,
                source_id=entry.source_id,
                title=entry.title,
                canonical_url=entry.canonical_url,
                content_excerpt=entry.content_excerpt,
                content_hash=entry.content_hash,
                pfsense_edition=entry.pfsense_edition,
                trust_label=_TRUST_LABEL_PINNED_SNAPSHOT,
                applicability=applicability,
                evidence_level=entry.evidence_level,
                applicable_overlay_chain=overlay_chain,
                observed_edition_used=observed_edition,
                observed_version_used=observed_version,
                retrieval_mode=entry.retrieval_mode,
                snapshot_version=SNAPSHOT_VERSION,
            )
        )
    return tuple(results)
