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
SNAPSHOT_VERSION = "guidance-registry-2026-08-22"

#: Shared, evidence-based `license_note` text for the 2026-08-22 corpus
#: expansion below. Not boilerplate-copied blind: the underlying fact it
#: states -- copyright holder, absence of an explicit documentation-reuse
#: license -- was independently verified this session (fetched
#: docs.netgate.com's page footer directly, and netgate.com's own
#: "Website Terms & Conditions of Use" at
#: https://www.netgate.com/company/web-terms, which covers www.netgate.com/
#: store.netgate.com/www.pfSense.org and does not explicitly name
#: docs.netgate.com). Every entry using this constant was individually
#: checked against its own `canonical_url` at authoring time (Review
#: checklist, Finding 5) -- what's shared is the licensing-fact citation,
#: not the excerpt-to-source verification, matching I4's actual concern.
_NETGATE_DOCS_LICENSE_NOTE = (
    "Short quotation from Netgate pfSense documentation (docs.netgate.com), "
    "for reference only -- not a full-page mirror. Footer: copyright "
    "Electric Sheep Fencing LLC and Rubicon Communications LLC, all rights "
    "reserved (checked 2026-08-22); netgate.com Website Terms omit "
    "docs.netgate.com and state no quotation/fair-use permission. Rights "
    "remain with the copyright holders; verify terms before broader reuse "
    "(ADR-017 licensing self-challenge; not independently resolved beyond "
    "this citation)."
)

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

#: Phase 16 initial corpus (2026-08-22): one verified entry per capability
#: across the priority domain list (System/Interfaces/VLANs/Routing/
#: Firewall/NAT/DHCP/DNS/IPsec/OpenVPN/WireGuard/Certificates/CARP/
#: Logging), each fetched live from its cited `canonical_url` during this
#: registry-authoring step and quoted verbatim (same review discipline as
#: `_ALIAS_DOC` above). None claims `EXPLICIT_UNVERSIONED` or
#: `EXPLICIT_VERSION_SCOPED` -- every fetched page was an undated
#: `/latest/` page with no stated version scope, so each is honestly
#: `INFERRED_FROM_CURRENT_DOCS` (can only ever reach `VERSION_UNCONFIRMED`,
#: never `APPLICABLE`, per the accepted evidence-level cap) until a
#: curator re-authors one with a genuine explicit version citation. The
#: pfSense REST API (`SYSTEM_RESTAPI_SETTINGS_READ` and related
#: capabilities) is deliberately NOT represented here: it is a
#: community-maintained package (pfrest.org / github.com/Netgate/
#: pfsense-api), not docs.netgate.com content, and so has no entry that
#: could satisfy `ALLOWED_DOCUMENT_HOSTS` honestly -- this is a real
#: `GUIDANCE_NOT_FOUND` gap, not an oversight (see the Phase 15 coverage
#: mapping in `reports-ai/`).
_FIREWALL_RULES_DOC = DocumentSource(
    source_id="netgate_docs_firewall_rules",
    title="Firewall",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/firewall/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt="Firewall rules control traffic passing through the firewall.",
    content_hash="628009dafc6ea4920a3387571bf101d20a194c7e24664698bb30f873b4215a08",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_NAT_DOC = DocumentSource(
    source_id="netgate_docs_nat",
    title="Network Address Translation",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/nat/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "Network Address Translation (NAT) allows multiple computers using "
        "IPv4 to be connected to the Internet using a single public IPv4 "
        "address."
    ),
    content_hash="4f6be79f6c8d3e0dfbc2132b4d948699e4d038fffd8bcbb7ba4a01756a3f72c5",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_DHCP_DOC = DocumentSource(
    source_id="netgate_docs_dhcp",
    title="DHCP Server",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/services/dhcp/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "Dynamic Host Configuration Protocol (DHCP), allows a device such as "
        "pfSense® software to dynamically allocate IP addresses to "
        "clients from predefined pools of addresses."
    ),
    content_hash="8b9faf0eef4e0e0e56016903935e5ac301e6fc5e0b96bcc81b2605d90716fe67",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_DNS_RESOLVER_DOC = DocumentSource(
    source_id="netgate_docs_dns_resolver",
    title="DNS Resolver",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/services/dns/resolver.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "The DNS Resolver in pfSense® software utilizes unbound, which is "
        "a validating, recursive, caching DNS resolver capable of using "
        "DNSSEC, DNS over TLS, and a wide variety of options."
    ),
    content_hash="364811ff9c11b92bb55b06201f75ab86229c7e529b138ba917445fb02b4f9a3c",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_IPSEC_DOC = DocumentSource(
    source_id="netgate_docs_ipsec",
    title="IPsec",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "IPsec provides a standards-based VPN implementation that is "
        "compatible with a wide range of clients for mobile connectivity "
        "and other devices for site-to-site connectivity."
    ),
    content_hash="2a895e5cfba8c3970bafb89febda40c47b08e9ddc29e1509a2dfde319f27d9fe",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_WIREGUARD_DOC = DocumentSource(
    source_id="netgate_docs_wireguard",
    title="WireGuard",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/vpn/wireguard/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt="WireGuard is a new VPN Layer 3 protocol designed for speed and simplicity.",
    content_hash="8eaf8af49b7c9c43e0ec71602d2419d48b60d329258f1b42179c5f92b26c82ad",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_OPENVPN_DOC = DocumentSource(
    source_id="netgate_docs_openvpn",
    title="OpenVPN",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/vpn/openvpn/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "OpenVPN is an open source VPN solution which can provide access to "
        "remote access clients and enable site-to-site connectivity."
    ),
    content_hash="9400b50964b3ac32f650fa716cb0b7db06f7de9e0af95f384f7e59a16e233d99",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_HA_CARP_DOC = DocumentSource(
    source_id="netgate_docs_high_availability",
    title="High Availability",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/highavailability/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "pfSense® software is one of very few open source solutions "
        "offering enterprise-class high availability capabilities with "
        "stateful failover, allowing the elimination of the firewall as a "
        "single point of failure."
    ),
    content_hash="86e1e2e669786a6184445d016aba00085fc30b48f6a1c52e502baab632500149",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_CERTIFICATES_DOC = DocumentSource(
    source_id="netgate_docs_certificates",
    title="Certificate Manager",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/certificates/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "The Certificate Manager under System > Certificates, creates and "
        "maintains certificate authority (CA), certificate, and certificate "
        "revocation list (CRL) entries for use by the firewall."
    ),
    content_hash="db5e59c23b12a9b1acf85d7ad1a1a70a4916dfe7a5a86ab8c8da264e60dcdd26",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_INTERFACES_DOC = DocumentSource(
    source_id="netgate_docs_interfaces",
    title="Interface Types and Configuration",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/interfaces/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "pfSense® software is compatible with numerous types of network "
        "interfaces, either using physical interfaces directly or by "
        "employing other protocols such as PPP or VLANs."
    ),
    content_hash="2d91f94c4db6eb6d2fe05d24f81edc313c09a5009e3fa51a8eb6389ff29b51c6",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_VLAN_DOC = DocumentSource(
    source_id="netgate_docs_vlan",
    title="Virtual LANs (VLANs)",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/vlan/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "VLANs enable a switch to carry multiple discrete broadcast "
        "domains, allowing a single switch to function as if it were "
        "multiple switches."
    ),
    content_hash="461cba5f690683808e0b2a3216262adb7a44755844a718e40ade48b8692eb595",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_GATEWAYS_DOC = DocumentSource(
    source_id="netgate_docs_gateways",
    title="Gateways",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/routing/gateways.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "Gateways are the key to routing; They are routers on directly "
        "connected networks through which a host can reach other networks."
    ),
    content_hash="ef7de5b121865ed979b38fedf6124ca37e15b6abd18a00886255b27301edbb7e",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_LOGGING_DOC = DocumentSource(
    source_id="netgate_docs_logging",
    title="System Logs",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/monitoring/logs/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    content_excerpt=(
        "pfSense® software logs a lot of data by default, but does so "
        "in a manner that attempts to avoid overflowing the storage on the "
        "firewall."
    ),
    content_hash="69a64677873f28669075afaff93e42b555ebb3c4ef7cb9ec8abbec841951f82c",
    license_note=(
        "Short quotation from Netgate's official pfSense documentation, used "
        "for contextual reference only -- not a full-page mirror. Full "
        "content and rights remain with Netgate/Rubicon Communications LLC "
        '(site-wide copyright: "All Rights Reserved", confirmed 2026-08-22). '
        "Verify redistribution terms before any broader reuse (ADR-017 "
        "licensing self-challenge; not independently resolved by this "
        "project)."
    ),
)

_REGISTRY: dict[Capability, tuple[DocumentSource, ...]] = {
    Capability.ALIAS_READ: (_ALIAS_DOC,),
    Capability.FIREWALL_READ: (_FIREWALL_RULES_DOC,),
    Capability.FIREWALL_NAT_READ: (_NAT_DOC,),
    Capability.DHCP_SERVER_READ: (_DHCP_DOC,),
    Capability.SERVICES_DNS_RESOLVER_READ: (_DNS_RESOLVER_DOC,),
    Capability.STATUS_IPSEC_SA_READ: (_IPSEC_DOC,),
    Capability.STATUS_WIREGUARD_TUNNEL_READ: (_WIREGUARD_DOC,),
    Capability.STATUS_OPENVPN_SERVER_READ: (_OPENVPN_DOC,),
    Capability.STATUS_CARP_READ: (_HA_CARP_DOC,),
    Capability.SYSTEM_CERTIFICATE_READ: (_CERTIFICATES_DOC,),
    Capability.INTERFACE_READ: (_INTERFACES_DOC,),
    Capability.INTERFACE_VLAN_READ: (_VLAN_DOC,),
    Capability.GATEWAY_READ: (_GATEWAYS_DOC,),
    Capability.STATUS_LOGS_SETTINGS_READ: (_LOGGING_DOC,),
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
