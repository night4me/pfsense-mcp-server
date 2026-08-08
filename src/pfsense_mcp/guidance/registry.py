"""The deterministic `Capability -> DocumentSource` registry (ADR-017 G2)
and the one public lookup function `lookup_guidance()` (I5/I6).

`_REGISTRY` is a Git-tracked Python literal -- authored and reviewed
exactly like source code, loaded once at import time, never mutated at
runtime (I2). There is no code path anywhere in this module that
constructs a `DocumentSource` from a network response, environment
variable, or any other request-time input.

Populating this registry with additional entries is registry-authoring
work, not code review of this module: each new entry needs `title`/
`content_excerpt` verified against the live `canonical_url` page at
review time (`docs/OFFICIAL_GUIDANCE_LAYER.md`'s Review checklist,
Finding 5), `content_hash` computed from the exact excerpt text, and
should stay within the "no more than ~3 entries per capability" curation
guidance (Finding 7) before this module needs any code change at all.
"""

from __future__ import annotations

from pfsense_mcp.capabilities import Capability

from .models import UNVERSIONED, DocumentSource, Edition, GuidanceReference, RetrievalMode, excerpt_hash

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


def _check_registry_integrity() -> None:
    """Load-time self-check (I3 failure-mode table): every entry's
    `content_hash` must match a freshly computed hash of its own
    `content_excerpt`. A mismatch is a build/deploy defect and must fail
    loudly at import time, not be silently served."""

    for entries in _REGISTRY.values():
        for entry in entries:
            expected = excerpt_hash(entry.content_excerpt)
            if entry.content_hash != expected:
                raise ValueError(
                    f"guidance registry integrity check failed for {entry.source_id!r}: "
                    f"content_hash {entry.content_hash!r} does not match computed {expected!r}"
                )


_check_registry_integrity()


def lookup_guidance(
    capability: Capability,
    observed_version: str | None,
    observed_edition: Edition | None,
) -> tuple[GuidanceReference, ...]:
    """Pure, deterministic (I5): identical inputs always produce identical
    output. Fails closed to an empty tuple on any absence or ambiguity
    (I6) -- never raises past this boundary, never fabricates or guesses.

    Edition `None` (unknown): only `Edition.BOTH`-applicable entries are
    eligible -- an edition-specific entry is excluded rather than guessed
    at (`SystemVersion` currently exposes no CE/Plus discriminator; see
    ADR-017's edition self-challenge).

    Version: `UNVERSIONED` entries are always eligible. A version-specific
    entry is eligible only when `observed_version` exactly equals its
    `version_applicability` string -- no ranges, no partial matches (I3).
    Any non-match, including `observed_version is None` against a
    version-specific entry, excludes that entry rather than including it
    with a caveat: this accepted scope's fail-closed policy is exclusion,
    not a flagged best guess.
    """

    results: list[GuidanceReference] = []
    for entry in _REGISTRY.get(capability, ()):
        if entry.pfsense_edition is not Edition.BOTH:
            if observed_edition is None or entry.pfsense_edition is not observed_edition:
                continue

        if entry.version_applicability != UNVERSIONED:
            if observed_version is None or observed_version != entry.version_applicability:
                continue

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
                # Always False in this accepted scope: a version mismatch
                # excludes the entry above rather than including it
                # flagged. Reserved for a possible future policy that
                # includes-with-caveat instead of excludes; not active
                # today, and not something to start setting True without
                # first revising I6's exclude-on-mismatch decision.
                version_mismatch=False,
                snapshot_version=SNAPSHOT_VERSION,
            )
        )
    return tuple(results)
