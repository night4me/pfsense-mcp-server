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
`summary` (or `caveat_summary`) verified against the live `canonical_url`
page at review time (`docs/OFFICIAL_GUIDANCE_LAYER.md`'s Review checklist,
Finding 5), `summary_hash`/`source_verification_hash` computed from the
exact text, and should stay within the "no more than ~3 entries per
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

**Provenance-model revision (2026-08-22, owner-authorized)**: every entry
below was rewritten from a short verbatim Netgate quotation to a
project-authored `summary`, to avoid depending on redistributed Netgate
documentation prose. Each entry retains a short (<=300 char)
`source_verification_excerpt` -- genuinely verbatim, drawn from the same
page -- used exclusively by `scripts/guidance_corpus_audit.py`'s
maintainer-only drift check; this text is never exposed through
`GuidanceReference`/`EvidenceReference`. See `models.py`'s module
docstring for the full rationale. Full inventory of what was converted:
`reports-ai/GUIDANCE_CONTENT_CONVERSION_2026-08-22.md`.
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
SNAPSHOT_VERSION = "guidance-registry-2026-08-22b"

#: Shared, evidence-based `license_note` text for the corpus below.
#: Updated 2026-08-22 for the summary/verification-anchor provenance
#: revision: the verbatim footprint per entry dropped from up to 2000
#: characters (the old quoted excerpt) to well under 300 (a short
#: maintainer-only verification anchor, never shown to any consumer) --
#: reducing licensing exposure regardless of exact reuse terms, per
#: ADR-017's own licensing self-challenge. The underlying fact this note
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
    "Summary is project-authored, not Netgate text. Only verbatim text kept is the "
    "<=300-char source_verification_excerpt (maintainer-audit-only, never shown to any "
    "consumer), quoted from docs.netgate.com. Copyright Electric Sheep Fencing LLC / "
    "Rubicon Communications LLC (footer checked 2026-08-22); netgate.com Website Terms "
    "omit docs.netgate.com and grant no quotation permission. Verify before storing more "
    "verbatim text (ADR-017 licensing self-challenge, not fully resolved)."
)

#: The only trust label this accepted (bundled-snapshot-only) scope
#: produces. Renamed 2026-08-22 from "pinned-snapshot" to match the
#: summary-based provenance model (this is a reviewed, static
#: project-authored summary, not a pinned snapshot of source text).
#: TB-G3 (deferred) reserves other values for live-fetched content --
#: none exist yet.
_TRUST_LABEL_PINNED_SUMMARY = "pinned-summary"

#: Phase 16 initial corpus (2026-08-22), content-converted (2026-08-22b):
#: one verified entry per capability across the priority domain list
#: (System/Interfaces/VLANs/Routing/Firewall/NAT/DHCP/DNS/IPsec/OpenVPN/
#: WireGuard/Certificates/CARP/Logging). Each `summary` is independently
#: authored by this project, cross-checked for factual accuracy against
#: the cited `canonical_url` at authoring time -- never a quotation, never
#: word-substitution of one. Each `source_verification_excerpt` is a short,
#: genuinely verbatim anchor phrase from the same page, confirmed present
#: via `scripts/guidance_corpus_audit.py` (15/15 present at conversion
#: time). None claims `EXPLICIT_UNVERSIONED` or `EXPLICIT_VERSION_SCOPED`
#: -- every cited page is an undated `/latest/` page with no stated
#: version scope, so each is honestly `INFERRED_FROM_CURRENT_DOCS` (can
#: only ever reach `VERSION_UNCONFIRMED`, never `APPLICABLE`, per the
#: accepted evidence-level cap) until a curator re-authors one with a
#: genuine explicit version citation. The pfSense REST API
#: (`SYSTEM_RESTAPI_SETTINGS_READ` and related capabilities) is
#: deliberately NOT represented here: it is a community-maintained
#: package (pfrest.org / github.com/Netgate/pfsense-api), not
#: docs.netgate.com content, and so has no entry that could satisfy
#: `ALLOWED_DOCUMENT_HOSTS` honestly -- a real `GUIDANCE_NOT_FOUND` gap,
#: not an oversight.
_ALIAS_DOC = DocumentSource(
    source_id="netgate_docs_aliases",
    title="Aliases",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "In pfSense, an alias is a named, reusable definition of one or more IP "
        "addresses, networks, or ports. Firewall rules, NAT mappings, and "
        "traffic-shaping rules can reference an alias instead of listing individual "
        "values directly, so a single edit to the alias updates every rule that uses "
        "it and keeps rule sets easier to read and maintain."
    ),
    summary_hash="fa6286bcff18075dd1e59ef9d23ce9093942ed71944c42e6f62016a83ca2768f",
    source_verification_excerpt="Aliases define groups of ports, hosts, or networks.",
    source_verification_hash="8c8980ba22e44ade7d977dd77c3b21c9ec5240339f805e0bd9137b6deca408b8",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_SYSTEM_CONFIG_DOC = DocumentSource(
    source_id="netgate_docs_system_configuration",
    title="Configuration",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/config/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "pfSense is primarily administered through its web-based GUI. A smaller set "
        "of configuration and recovery tasks -- useful when the GUI is unreachable -- "
        "can also be performed from the system console, whether accessed directly, "
        "over a serial connection, or via SSH."
    ),
    summary_hash="e6669487fce583c1eb105b7239681091f5c85415e5cc893aeb40f4bc17fb1f35",
    source_verification_excerpt="Most pfSense® software configuration is performed using the web-based GUI.",
    source_verification_hash="7ce923c93a280f2e5b678484a2dda8119da9fce787626bb747a4d18b545ee74f",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_FIREWALL_RULES_DOC = DocumentSource(
    source_id="netgate_docs_firewall_rules",
    title="Firewall",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/firewall/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "Firewall rules are the ordered set of match conditions pfSense evaluates "
        "against traffic crossing an interface, determining whether each connection "
        "is passed or blocked. Rules are evaluated per interface, generally in listed "
        "order, with the first matching rule deciding the outcome."
    ),
    summary_hash="872db853e94d90b34f26572a04dbd3f4e636ef6d1858fbe3b6b592f3c91a20d7",
    source_verification_excerpt="Firewall rules control traffic passing through the firewall.",
    source_verification_hash="628009dafc6ea4920a3387571bf101d20a194c7e24664698bb30f873b4215a08",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_NAT_DOC = DocumentSource(
    source_id="netgate_docs_nat",
    title="Network Address Translation",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/nat/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "Network Address Translation (NAT) lets pfSense rewrite the source or "
        "destination addresses of passing traffic. The most common use is outbound "
        "NAT, which lets many internal IPv4 hosts share a single public IPv4 address; "
        "port forwards (inbound NAT) do the reverse, directing traffic arriving on the "
        "WAN to a specific internal host and port."
    ),
    summary_hash="b3983f340d2200df9fd6001e9cbeccf4b7b4383d5a910b984e1f3b84ac44cb19",
    source_verification_excerpt="Network Address Translation (NAT) allows multiple computers using IPv4",
    source_verification_hash="a5900fb3a6ef96d3f3f2897e039b62682479c4bede6451c72d60debe11e4edc1",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_DHCP_DOC = DocumentSource(
    source_id="netgate_docs_dhcp",
    title="DHCP Server",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/services/dhcp/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "The DHCP server service lets pfSense automatically hand out IP addresses, "
        "and related network settings such as the default gateway and DNS servers, "
        "to clients on a configured interface from one or more defined address pools, "
        "rather than requiring each client to be configured with a static address."
    ),
    summary_hash="b73bf71b1cd020cf7a8ef98c680e4a7ea99ee0e4197d515d348363eff2b86a5f",
    source_verification_excerpt="Dynamic Host Configuration Protocol (DHCP), allows a device such as pfSense",
    source_verification_hash="8893841309dda8dba6a4132e85bab6964b1dc035096b09440eed0a05928ef6ef",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_DNS_RESOLVER_DOC = DocumentSource(
    source_id="netgate_docs_dns_resolver",
    title="DNS Resolver",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/services/dns/resolver.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "The DNS Resolver service runs Unbound, a recursive DNS resolver that can "
        "query authoritative name servers directly rather than forwarding to an "
        "upstream resolver. It supports DNSSEC validation and DNS-over-TLS, and can be "
        "configured with host and domain overrides for local name resolution."
    ),
    summary_hash="3af29670a092d92b1a0eaaebcad73d4f45babe751379dd763315c11bd837eb51",
    source_verification_excerpt="The DNS Resolver in pfSense® software utilizes unbound",
    source_verification_hash="a6cf7e5883abd4abd22ce976edc2abc2d8a0a98e25c39f2e0b73f44420ddfd71",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_IPSEC_DOC = DocumentSource(
    source_id="netgate_docs_ipsec",
    title="IPsec",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "IPsec is pfSense's standards-based VPN implementation, commonly used for "
        "site-to-site tunnels between gateways and for mobile/remote-access clients "
        "using IKEv2. A working tunnel negotiates security associations in two phases "
        "(IKE/Phase 1, then the per-subnet Phase 2 child SAs) before user traffic can "
        "pass."
    ),
    summary_hash="4275f868e7d35a1bdf1ce5b90b7e4f19c8b4ebe20400c6ce3fcdcd3719560d2c",
    source_verification_excerpt="IPsec provides a standards-based VPN implementation",
    source_verification_hash="0910f557c6a4cffbe0967445857660e7c7aa4e82d0e9648f422e97d12275481c",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_WIREGUARD_DOC = DocumentSource(
    source_id="netgate_docs_wireguard",
    title="WireGuard",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/vpn/wireguard/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "WireGuard is a comparatively new, lightweight Layer 3 VPN protocol available "
        "in pfSense as an add-on package. It uses a small, fixed set of modern "
        "cryptographic primitives and a minimal configuration model built around "
        "per-peer public keys, favoring simplicity and throughput over the more "
        "configurable but heavier IPsec/OpenVPN options."
    ),
    summary_hash="a6d4cc634720087105b6c2aa21bdaf40fc55e8d641dcfe35bc0e24ba669b6f05",
    source_verification_excerpt="WireGuard is a new VPN Layer 3 protocol designed for speed and simplicity.",
    source_verification_hash="8eaf8af49b7c9c43e0ec71602d2419d48b60d329258f1b42179c5f92b26c82ad",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_OPENVPN_DOC = DocumentSource(
    source_id="netgate_docs_openvpn",
    title="OpenVPN",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/vpn/openvpn/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "OpenVPN is an open-source, TLS-based VPN option built into pfSense, usable "
        "for both remote-access client connections and site-to-site tunnels. It runs "
        "over a single configurable TCP or UDP port and supports certificate-based, "
        "password, and combined authentication."
    ),
    summary_hash="6a2d08385d4363ca12b9854e1de3be84a4aeccc6196ead47755f1da457207199",
    source_verification_excerpt="OpenVPN is an open source VPN solution",
    source_verification_hash="f41d6482d9028cf293ea8e33180b0bfbbc2f30b51151a74a6158ad292b8f30af",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_HA_CARP_DOC = DocumentSource(
    source_id="netgate_docs_high_availability",
    title="High Availability",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/highavailability/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "pfSense's High Availability feature uses CARP (Common Address Redundancy "
        "Protocol) to let two or more firewalls share virtual IP addresses, with one "
        "node active and the others in standby. Combined with state synchronization "
        "(pfsync), a failover between nodes can preserve existing connections rather "
        "than dropping them, removing the firewall as a single point of failure."
    ),
    summary_hash="1e652f5135ff191cf34554b5d7ab86803ae1cd25399c09eb36687342401debfd",
    source_verification_excerpt=(
        "pfSense® software is one of very few open source solutions offering enterprise-class high availability"
    ),
    source_verification_hash="d24abdbe844d3626196a5e1957e23f8b39c3fc3ae708f6378d0c910322930e46",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_CERTIFICATES_DOC = DocumentSource(
    source_id="netgate_docs_certificates",
    title="Certificate Manager",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/certificates/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "The Certificate Manager, under System > Certificates, is where pfSense "
        "stores and manages the certificate authorities, individual certificates, and "
        "certificate revocation lists the firewall uses -- for example, to secure the "
        "web GUI, or for IPsec, OpenVPN, and captive-portal authentication."
    ),
    summary_hash="68df24e2a9ea896d1ad9c6d789661caa592702c5d0e0c78f2cda6abc1fd71704",
    source_verification_excerpt=(
        "The Certificate Manager under System > Certificates, creates and maintains certificate authority"
    ),
    source_verification_hash="4352155058a7390efd4962f99e09827697dacbddecd29f79a589423c3f4808c2",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_INTERFACES_DOC = DocumentSource(
    source_id="netgate_docs_interfaces",
    title="Interface Types and Configuration",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/interfaces/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "pfSense can assign a network interface from a physical NIC or from a "
        "virtual construct built on top of one, such as a VLAN, PPP-family link "
        "(PPPoE, PPTP, L2TP), bridge, LAGG, or GRE/GIF tunnel. Each assigned interface "
        "gets its own addressing and firewall-rule set, independent of the underlying "
        "hardware."
    ),
    summary_hash="4e6b86251381d772fcb191dfaea4f18b06d630f3392d95c0f5c1dd7b6c594979",
    source_verification_excerpt="pfSense® software is compatible with numerous types of network interfaces",
    source_verification_hash="9ebd14049b58fe2da6953a5f397deb661416d4aa333c75c95b8bc3d2011d2c92",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_VLAN_DOC = DocumentSource(
    source_id="netgate_docs_vlan",
    title="Virtual LANs (VLANs)",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/vlan/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "A VLAN (Virtual LAN) lets a single physical interface and switch trunk "
        "carry traffic for multiple logically separate networks, each tagged with its "
        "own VLAN ID. pfSense treats each configured VLAN as its own assignable "
        "interface, with its own addressing and firewall rules, without requiring a "
        "dedicated physical NIC per network."
    ),
    summary_hash="b98d931d8ebf4b85e80ed93f91ca1152d2bb124c4519cf94090b5896eff94f36",
    source_verification_excerpt="VLANs enable a switch to carry multiple discrete broadcast domains",
    source_verification_hash="10c6a8978a988818eee72199ca2b3278465774acde597010b920b5cdf735436c",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_GATEWAYS_DOC = DocumentSource(
    source_id="netgate_docs_gateways",
    title="Gateways",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/routing/gateways.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "A gateway in pfSense is the next-hop router pfSense uses to reach networks "
        "beyond its directly connected interfaces. pfSense can monitor gateway "
        "reachability and latency, and multiple gateways can be grouped for failover "
        "or load balancing between upstream connections."
    ),
    summary_hash="fb48e7c64f432eae1c017f566d8304374e54ba93cb36c67d3ed2cd52f675351c",
    source_verification_excerpt="Gateways are the key to routing",
    source_verification_hash="cb437dae025e7f5bdb4ce69616efa436f2485c8a1899c221278fdbf9b8327746",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_LOGGING_DOC = DocumentSource(
    source_id="netgate_docs_logging",
    title="System Logs",
    canonical_url="https://docs.netgate.com/pfsense/en/latest/monitoring/logs/index.html",
    pfsense_edition=Edition.BOTH,
    version_applicability=UNVERSIONED,
    evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
    retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
    summary=(
        "pfSense logs firewall, system, and service activity to a set of "
        "category-specific logs, viewable from the GUI or forwarded to a remote "
        "syslog server. Log storage is bounded by configurable size/rotation "
        "settings so that verbose logging by default does not fill the firewall's "
        "local storage."
    ),
    summary_hash="b50f165f102073fe2d38fe02671e8d054c72429c0e93b1a248315dea4a9929cc",
    source_verification_excerpt="pfSense® software logs a lot of data by default",
    source_verification_hash="fd2125d76de5976f09774e4cbfea1f7c304eb3a62a29307db584ca6c4c78acd4",
    license_note=_NETGATE_DOCS_LICENSE_NOTE,
)

_REGISTRY: dict[Capability, tuple[DocumentSource, ...]] = {
    Capability.ALIAS_READ: (_ALIAS_DOC,),
    Capability.SYSTEM_READ: (_SYSTEM_CONFIG_DOC,),
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
#: to the same review discipline as `_REGISTRY` above. Still empty as of
#: the 2026-08-22 content-conversion pass: no verified, evidence-backed
#: release-specific exception currently requires one (owner instruction:
#: do not populate merely because the registry happens to be empty).
_OVERLAY_REGISTRY: dict[Capability, tuple[ReleaseOverlay, ...]] = {}


def _all_overlays() -> tuple[ReleaseOverlay, ...]:
    return tuple(overlay for entries in _OVERLAY_REGISTRY.values() for overlay in entries)


def _check_registry_integrity() -> None:
    """Load-time self-check (I3 failure-mode table): every entry's
    `summary_hash`/`source_verification_hash` (or `caveat_summary_hash`/
    `source_verification_hash` for overlays) must match a freshly
    computed hash of its own text. A mismatch is a build/deploy defect
    and must fail loudly at import time, not be silently served.

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
            expected_summary = excerpt_hash(entry.summary)
            if entry.summary_hash != expected_summary:
                raise ValueError(
                    f"guidance registry integrity check failed for {entry.source_id!r}: "
                    f"summary_hash {entry.summary_hash!r} does not match computed {expected_summary!r}"
                )
            expected_verification = excerpt_hash(entry.source_verification_excerpt)
            if entry.source_verification_hash != expected_verification:
                raise ValueError(
                    f"guidance registry integrity check failed for {entry.source_id!r}: "
                    f"source_verification_hash {entry.source_verification_hash!r} does not match "
                    f"computed {expected_verification!r}"
                )

    overlays = _all_overlays()
    for overlay in overlays:
        expected_caveat = excerpt_hash(overlay.caveat_summary)
        if overlay.caveat_summary_hash != expected_caveat:
            raise ValueError(
                f"guidance registry integrity check failed for overlay {overlay.overlay_id!r}: "
                f"caveat_summary_hash {overlay.caveat_summary_hash!r} does not match computed {expected_caveat!r}"
            )
        expected_verification = excerpt_hash(overlay.source_verification_excerpt)
        if overlay.source_verification_hash != expected_verification:
            raise ValueError(
                f"guidance registry integrity check failed for overlay {overlay.overlay_id!r}: "
                f"source_verification_hash {overlay.source_verification_hash!r} does not match "
                f"computed {expected_verification!r}"
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
                summary=entry.summary,
                summary_hash=entry.summary_hash,
                pfsense_edition=entry.pfsense_edition,
                trust_label=_TRUST_LABEL_PINNED_SUMMARY,
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
