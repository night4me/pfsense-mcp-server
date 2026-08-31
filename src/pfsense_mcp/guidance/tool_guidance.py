"""Project-authored guidance for this project's own MCP READ/guidance
tools (post-v0.8.0 guidance arc, Slice A -- "provenance model +
structured project-tool guidance foundation").

Every string this module returns is **`PROJECT_AUTHORED`** -- a fixed
`Literal`, mirroring `pfsense_mcp.tools.read.official_guidance`'s own
`OfficialGuidanceResult.disclaimer` pattern exactly -- never a Netgate
or pfREST-upstream quotation, and never labeled as either. This module
answers a categorically different question than
`pfsense_mcp.guidance.registry.lookup_guidance()` does: not "what does
official pfSense documentation say about this feature," but "what kind
of evidence does *this specific tool's own result* actually represent,
and what should it not be mistaken for."

**Two-layer design** (chosen over 95 individually hand-authored essays,
per this arc's own research report,
`reports-ai/POST_V0_8_GUIDANCE_AND_DOCS_ARC_RESEARCH_2026-08-27.md`,
Phase 8): every one of the 95 read tools is classified into a closed
`ResultKind` (what shape of evidence its result is -- configuration,
live status, apply-pending status, derived/computed state, history,
a capability list, or appliance self-identity), which alone already
answers most of the task's own "useful guidance" questions (is an
empty result meaningful, is this configuration or live state, etc.) via
one small, reusable template per kind. A tool-specific `override` is
added only where the generic template genuinely is not enough --
concentrated on the `APPLY_STATUS` cluster and a handful of other
tools this arc's own coverage audit flagged as easy to misread.

**Placement**: inside `pfsense_mcp.guidance`, not a new isolated
package, because this module performs **no I/O of any kind** -- it is
pure, Git-tracked, load-once data plus pure functions, exactly the same
trust class `registry.py`'s own `_REGISTRY` already is. It does not
import `network`/`socket`/`requests`/`httpx`, does not construct a
`PfSenseClient`, and has no `Capability`/endpoint/confirmation-token
field anywhere in its shapes (same G1 discipline `models.py` already
enforces) -- verified directly by
`tests/guidance/test_tool_guidance.py`, not left to convention.

**Not yet wired to any MCP tool** in this arc (deliberate -- see the
research report's Phase 7/11): this is the tested foundation a future,
separately-decided slice would expose, mirroring exactly how
`appliance_identity.py`'s `resolve_appliance_identity()` sat fully
implemented and tested for a full ADR-018 acceptance cycle before
`official_guidance.py` became its first and only consumer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

#: I4-style bound, reused from `models.py`'s own `MAX_EXCERPT_LENGTH` --
#: one shared limit across every free-text guidance field this project
#: emits, never a second, independently-chosen number for this module.
from .models import MAX_EXCERPT_LENGTH

PROVENANCE: Literal["PROJECT_AUTHORED"] = "PROJECT_AUTHORED"


class ResultKind(str, Enum):
    """Closed classification of what a READ tool's result actually
    represents -- orthogonal to which pfSense domain (firewall, DHCP,
    VPN, ...) it covers. Chosen from this arc's own 95-tool audit
    (research report Phase 2), not an abstract taxonomy invented in
    advance of looking at the real tool set."""

    #: What is currently *set*, whether or not it has taken effect on
    #: the running system yet. The single largest category (roughly
    #: two-thirds of all 95 tools).
    CONFIGURATION = "configuration"
    #: Whether configuration already saved has been pushed live yet --
    #: pfREST's own "pending changes" control-plane concept, not a
    #: pfSense GUI feature Netgate documents. The exact cluster this
    #: arc's own coverage audit flagged as most likely to be misread.
    APPLY_STATUS = "apply_status"
    #: Live, currently-observed operational state (service up/down,
    #: tunnel connected, CARP role) -- can change from one call to the
    #: next independent of any configuration change.
    RUNTIME_STATUS = "runtime_status"
    #: Computed/aggregated from live system state, not a direct
    #: configuration read and not itself a simple up/down status (a
    #: routing table, a pf table's current contents, the ARP cache).
    DERIVED_STATE = "derived_state"
    #: A record of past events/revisions -- never a claim about
    #: current state, even when the most recent entry looks current.
    HISTORY = "history"
    #: What the appliance/package *could* do or *has available* --
    #: not what is currently configured or active.
    CAPABILITY_LIST = "capability_list"
    #: The appliance's or package's own self-identification (version,
    #: hostname) -- narrower than CONFIGURATION, used only for tools
    #: whose entire purpose is "what am I."
    IDENTITY = "identity"


_RESULT_KIND_TEMPLATES: dict[ResultKind, str] = {
    ResultKind.CONFIGURATION: (
        "This tool reports pfSense CONFIGURATION -- what is currently set on the appliance, not "
        "necessarily what is currently active on the network. An empty or minimal result usually "
        "means genuinely nothing is configured for this feature, not that the tool failed. If the "
        "underlying subsystem supports an apply-pending model, a saved configuration change may not "
        "take effect until applied -- check the matching *_apply_status tool if one exists before "
        "assuming this configuration is already live."
    ),
    ResultKind.APPLY_STATUS: (
        "This tool reports whether saved configuration changes for this subsystem have been applied "
        "to the running system yet -- a pfREST API control-plane concept, not a pfSense product "
        "feature Netgate documents. 'No pending changes' means the running system already matches "
        "what is configured, which is the normal, healthy state -- it does not mean nothing is "
        "configured. Conversely, pending changes existing does not mean anything is broken; it means "
        "a save has not yet been followed by an apply."
    ),
    ResultKind.RUNTIME_STATUS: (
        "This tool reports LIVE, currently-observed operational state, not configuration. Two calls "
        "moments apart can legitimately return different results even with no configuration change "
        "at all. A result showing something as down/disconnected is not necessarily a misconfiguration "
        "-- it may simply not be running right now. For what is actually configured (independent of "
        "whether it is currently running), use the matching configuration-reading tool instead."
    ),
    ResultKind.DERIVED_STATE: (
        "This tool reports state the appliance computes or observes at request time -- not a direct "
        "configuration setting and not a simple up/down status. Results reflect only this exact "
        "moment and may already be different by the time they are read. An empty result commonly "
        "means the underlying table/cache/route set genuinely has no entries right now, not that the "
        "tool failed."
    ),
    ResultKind.HISTORY: (
        "This tool reports a record of past events or revisions. Even the most recent entry describes "
        "something that already happened -- it is never a live status check and must not be read as "
        "a statement about the current moment. An empty result means no recorded history exists yet, "
        "which is expected on a freshly configured system."
    ),
    ResultKind.CAPABILITY_LIST: (
        "This tool reports what the appliance or an installed package SUPPORTS or HAS AVAILABLE, not "
        "what is currently configured or in use. Something appearing in this list does not mean it is "
        "active; something absent may simply not be installed rather than unsupported in general."
    ),
    ResultKind.IDENTITY: (
        "This tool reports the appliance's or the installed REST API package's own self-identification "
        "-- narrow, factual, and independent of any feature configuration. It does not indicate whether "
        "any particular feature is configured, applied, or running."
    ),
}


@dataclass(frozen=True)
class ToolGuidance:
    """The only shape this module ever returns. Deliberately has no
    field of type capability, endpoint, HTTP method, or confirmation
    token (same G1 discipline as `models.GuidanceReference`) -- there
    is nothing in this closed shape an authorization decision could be
    read out of."""

    tool_name: str
    result_kind: ResultKind
    interpretation: str
    related_tools: tuple[str, ...]
    empty_result_is_meaningful: bool
    secrets_intentionally_omitted: bool
    provenance: Literal["PROJECT_AUTHORED"] = PROVENANCE


#: Tool name -> ResultKind, covering every one of the 114 read tools plus
#: `pfsense_mcp_info` (re-derived and cross-checked against
#: `scripts/public_contract.py`'s own live output by
#: `tests/guidance/test_tool_guidance.py::test_every_read_tool_is_classified`
#: -- this dict is never allowed to silently drift from the real 114-tool
#: contract). A tool's presence here is a classification of what KIND of
#: evidence its result is, authored from reading this project's own
#: model/tool source, never a claim about pfREST/Netgate content.
_TOOL_RESULT_KIND: dict[str, ResultKind] = {
    # --- apply-status cluster (the arc's own flagged SPECIAL_CAVEAT group) ---
    "pfsense_get_dhcp_server_apply_status": ResultKind.APPLY_STATUS,
    "pfsense_get_dns_forwarder_apply_status": ResultKind.APPLY_STATUS,
    "pfsense_get_dns_resolver_apply_status": ResultKind.APPLY_STATUS,
    "pfsense_get_firewall_apply_status": ResultKind.APPLY_STATUS,
    "pfsense_get_firewall_virtual_ip_apply_status": ResultKind.APPLY_STATUS,
    "pfsense_get_haproxy_apply_status": ResultKind.APPLY_STATUS,
    "pfsense_get_interface_apply_status": ResultKind.APPLY_STATUS,
    "pfsense_get_ipsec_apply_status": ResultKind.APPLY_STATUS,
    "pfsense_get_routing_apply_status": ResultKind.APPLY_STATUS,
    "pfsense_get_wireguard_apply_status": ResultKind.APPLY_STATUS,
    # --- runtime status ---
    "pfsense_get_carp_status": ResultKind.RUNTIME_STATUS,
    "pfsense_get_gateway_status": ResultKind.RUNTIME_STATUS,
    "pfsense_get_service_status": ResultKind.RUNTIME_STATUS,
    "pfsense_get_status_ipsec_child_sas": ResultKind.RUNTIME_STATUS,
    "pfsense_get_status_ipsec_sas": ResultKind.RUNTIME_STATUS,
    "pfsense_get_status_openvpn_clients": ResultKind.RUNTIME_STATUS,
    "pfsense_get_status_openvpn_server_connections": ResultKind.RUNTIME_STATUS,
    "pfsense_get_status_wireguard_peers": ResultKind.RUNTIME_STATUS,
    "pfsense_get_status_wireguard_tunnels": ResultKind.RUNTIME_STATUS,
    "pfsense_get_system_status": ResultKind.RUNTIME_STATUS,
    # --- derived/computed state ---
    "pfsense_get_arp_table": ResultKind.DERIVED_STATE,
    "pfsense_get_dhcp_leases": ResultKind.DERIVED_STATE,
    "pfsense_get_diagnostics_tables": ResultKind.DERIVED_STATE,
    "pfsense_get_firewall_states": ResultKind.DERIVED_STATE,
    "pfsense_get_firewall_states_size": ResultKind.DERIVED_STATE,
    "pfsense_get_status_openvpn_server_routes": ResultKind.DERIVED_STATE,
    # --- history ---
    "pfsense_get_diagnostics_config_history_revisions": ResultKind.HISTORY,
    # --- capability lists ---
    "pfsense_get_interface_available_interfaces": ResultKind.CAPABILITY_LIST,
    "pfsense_get_system_package_available": ResultKind.CAPABILITY_LIST,
    "pfsense_get_vpn_ipsec_phase1_encryptions": ResultKind.CAPABILITY_LIST,
    "pfsense_get_vpn_ipsec_phase2_encryptions": ResultKind.CAPABILITY_LIST,
    # --- identity ---
    "pfsense_get_system_version": ResultKind.IDENTITY,
    "pfsense_get_system_restapi_version": ResultKind.IDENTITY,
    "pfsense_mcp_info": ResultKind.IDENTITY,
    # --- configuration (everything else) ---
    "pfsense_get_acme_settings": ResultKind.CONFIGURATION,
    "pfsense_get_auth_keys": ResultKind.CONFIGURATION,
    "pfsense_get_bind_access_lists": ResultKind.CONFIGURATION,
    "pfsense_get_bind_settings": ResultKind.CONFIGURATION,
    "pfsense_get_bind_sync_settings": ResultKind.CONFIGURATION,
    "pfsense_get_bind_views": ResultKind.CONFIGURATION,
    "pfsense_get_bind_zone_record": ResultKind.CONFIGURATION,
    "pfsense_get_bind_zones": ResultKind.CONFIGURATION,
    "pfsense_get_cron_jobs": ResultKind.CONFIGURATION,
    "pfsense_get_dhcp_relay": ResultKind.CONFIGURATION,
    "pfsense_get_dhcp_server_address_pools": ResultKind.CONFIGURATION,
    "pfsense_get_dhcp_server_custom_options": ResultKind.CONFIGURATION,
    "pfsense_get_dhcp_servers": ResultKind.CONFIGURATION,
    "pfsense_get_dhcp_static_mappings": ResultKind.CONFIGURATION,
    "pfsense_get_dns_forwarder_host_overrides": ResultKind.CONFIGURATION,
    "pfsense_get_dns_resolver_access_lists": ResultKind.CONFIGURATION,
    "pfsense_get_dns_resolver_domain_overrides": ResultKind.CONFIGURATION,
    "pfsense_get_dns_resolver_host_overrides": ResultKind.CONFIGURATION,
    "pfsense_get_dns_resolver_settings": ResultKind.CONFIGURATION,
    "pfsense_get_email_notification_settings": ResultKind.CONFIGURATION,
    "pfsense_get_firewall_advanced_settings": ResultKind.CONFIGURATION,
    "pfsense_get_firewall_aliases": ResultKind.CONFIGURATION,
    "pfsense_get_firewall_nat_one_to_one_mappings": ResultKind.CONFIGURATION,
    "pfsense_get_firewall_nat_outbound_mappings": ResultKind.CONFIGURATION,
    "pfsense_get_firewall_nat_outbound_mode": ResultKind.CONFIGURATION,
    "pfsense_get_firewall_nat_port_forwards": ResultKind.CONFIGURATION,
    "pfsense_get_firewall_rules": ResultKind.CONFIGURATION,
    "pfsense_get_firewall_schedules": ResultKind.CONFIGURATION,
    "pfsense_get_firewall_traffic_shaper_limiters": ResultKind.CONFIGURATION,
    "pfsense_get_firewall_traffic_shapers": ResultKind.CONFIGURATION,
    "pfsense_get_firewall_virtual_ips": ResultKind.CONFIGURATION,
    "pfsense_get_freeradius_eap": ResultKind.CONFIGURATION,
    "pfsense_get_gateways": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_backend_acls": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_backend_errorfiles": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_backend_servers": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_backends": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_dns_resolvers": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_email_mailers": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_files": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_frontend_acls": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_frontend_addresses": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_frontend_certificates": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_frontend_error_files": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_frontends": ResultKind.CONFIGURATION,
    "pfsense_get_haproxy_settings": ResultKind.CONFIGURATION,
    "pfsense_get_interface_bridges": ResultKind.CONFIGURATION,
    "pfsense_get_interface_configs": ResultKind.CONFIGURATION,
    "pfsense_get_interface_gres": ResultKind.CONFIGURATION,
    "pfsense_get_interface_groups": ResultKind.CONFIGURATION,
    "pfsense_get_interface_laggs": ResultKind.CONFIGURATION,
    "pfsense_get_interface_vlans": ResultKind.CONFIGURATION,
    "pfsense_get_interfaces": ResultKind.CONFIGURATION,
    "pfsense_get_ntp_settings": ResultKind.CONFIGURATION,
    "pfsense_get_ntp_time_servers": ResultKind.CONFIGURATION,
    "pfsense_get_routing_gateway_default": ResultKind.CONFIGURATION,
    "pfsense_get_routing_gateway_groups": ResultKind.CONFIGURATION,
    "pfsense_get_routing_static_routes": ResultKind.CONFIGURATION,
    "pfsense_get_ssh_settings": ResultKind.CONFIGURATION,
    "pfsense_get_status_logs_settings": ResultKind.CONFIGURATION,
    "pfsense_get_status_openvpn_servers": ResultKind.CONFIGURATION,
    "pfsense_get_system_certificate_authorities": ResultKind.CONFIGURATION,
    "pfsense_get_system_certificates": ResultKind.CONFIGURATION,
    "pfsense_get_system_console": ResultKind.CONFIGURATION,
    "pfsense_get_system_crls": ResultKind.CONFIGURATION,
    "pfsense_get_system_dns": ResultKind.CONFIGURATION,
    "pfsense_get_system_hasync": ResultKind.CONFIGURATION,
    "pfsense_get_system_hostname": ResultKind.CONFIGURATION,
    "pfsense_get_system_packages": ResultKind.CONFIGURATION,
    "pfsense_get_system_restapi_access_list": ResultKind.CONFIGURATION,
    "pfsense_get_system_restapi_settings": ResultKind.CONFIGURATION,
    "pfsense_get_system_timezone": ResultKind.CONFIGURATION,
    "pfsense_get_system_tunables": ResultKind.CONFIGURATION,
    "pfsense_get_system_webgui_settings": ResultKind.CONFIGURATION,
    "pfsense_get_user_groups": ResultKind.CONFIGURATION,
    "pfsense_get_users": ResultKind.CONFIGURATION,
    "pfsense_get_vpn_ipsec_phase1s": ResultKind.CONFIGURATION,
    "pfsense_get_vpn_ipsec_phase2s": ResultKind.CONFIGURATION,
    "pfsense_get_vpn_openvpn_clients": ResultKind.CONFIGURATION,
    "pfsense_get_vpn_openvpn_csos": ResultKind.CONFIGURATION,
    "pfsense_get_vpn_openvpn_servers": ResultKind.CONFIGURATION,
    "pfsense_get_vpn_wireguard_peers": ResultKind.CONFIGURATION,
    "pfsense_get_vpn_wireguard_tunnel_addresses": ResultKind.CONFIGURATION,
    "pfsense_get_vpn_wireguard_tunnels": ResultKind.CONFIGURATION,
    "pfsense_get_vpn_wireguard_settings": ResultKind.CONFIGURATION,
    "pfsense_get_services_service_watchdogs": ResultKind.CONFIGURATION,
}

#: Tool-specific caveats, added only where the generic per-kind template
#: (above) genuinely is not enough -- never restates the template, only
#: adds what is specific to this one tool. Concentrated on the
#: APPLY_STATUS cluster (every member gets one, naming its own specific
#: matching configuration-domain tool) plus a small number of other
#: tools this arc's own audit flagged.
_TOOL_OVERRIDES: dict[str, str] = {
    "pfsense_get_dhcp_server_apply_status": "Matching configuration tool: pfsense_get_dhcp_servers.",
    "pfsense_get_dns_forwarder_apply_status": "Matching configuration tool: pfsense_get_dns_forwarder_host_overrides.",
    "pfsense_get_dns_resolver_apply_status": "Matching configuration tool: pfsense_get_dns_resolver_settings.",
    "pfsense_get_firewall_apply_status": (
        "Matching configuration tools: pfsense_get_firewall_rules, pfsense_get_firewall_aliases."
    ),
    "pfsense_get_firewall_virtual_ip_apply_status": "Matching configuration tool: pfsense_get_firewall_virtual_ips.",
    "pfsense_get_haproxy_apply_status": (
        "Matching configuration tools: pfsense_get_haproxy_backends, pfsense_get_haproxy_frontends, "
        "pfsense_get_haproxy_settings."
    ),
    "pfsense_get_interface_apply_status": "Matching configuration tool: pfsense_get_interface_configs.",
    "pfsense_get_ipsec_apply_status": "Matching configuration tool: pfsense_get_vpn_ipsec_phase2s.",
    "pfsense_get_routing_apply_status": (
        "Matching configuration tools: pfsense_get_routing_static_routes, pfsense_get_routing_gateway_default."
    ),
    "pfsense_get_wireguard_apply_status": "Matching configuration tool: pfsense_get_vpn_wireguard_tunnel_addresses.",
    "pfsense_get_dhcp_leases": (
        "Reflects the DHCP server's own current lease table, not the static-mapping configuration "
        "(see pfsense_get_dhcp_static_mappings for reserved/fixed leases). A lease not appearing here "
        "may simply be expired or never issued, not evidence of a DHCP misconfiguration."
    ),
    "pfsense_get_firewall_states_size": (
        "Reports the state table's current SIZE (a count/limit pair), not its contents -- for the "
        "actual live connection entries, use pfsense_get_firewall_states instead."
    ),
    "pfsense_get_system_packages": (
        "Lists packages actually installed on this appliance right now -- for packages that could be "
        "installed but are not, use pfsense_get_system_package_available instead."
    ),
    "pfsense_mcp_info": (
        "Reports this MCP server process's own local state (registered tool/capability counts, "
        "profile) -- makes no network call to any pfSense appliance at all, and so cannot indicate "
        "anything about a specific appliance's configuration or status."
    ),
}

#: Cross-reference hints for a small number of tools whose most useful
#: complementary evidence is not already named in `_TOOL_OVERRIDES`
#: above. Deliberately sparse -- not populated for every tool, only
#: where a genuinely non-obvious pairing exists.
_TOOL_RELATED: dict[str, tuple[str, ...]] = {
    "pfsense_get_dhcp_leases": ("pfsense_get_dhcp_static_mappings", "pfsense_get_dhcp_servers"),
    "pfsense_get_firewall_states_size": ("pfsense_get_firewall_states",),
    "pfsense_get_system_packages": ("pfsense_get_system_package_available",),
    "pfsense_get_system_version": ("pfsense_get_system_restapi_version",),
}

#: Tools whose result being empty is a NON-obvious, easy-to-misjudge
#: case worth flagging structurally (`empty_result_is_meaningful=True`
#: on `ToolGuidance`) rather than left to the free-text interpretation
#: alone. Every APPLY_STATUS/HISTORY/DERIVED_STATE/CONFIGURATION tool
#: qualifies by nature of what it reports; RUNTIME_STATUS/CAPABILITY_LIST/
#: IDENTITY tools are excluded by default since "empty" for those is
#: more often a genuine anomaly than an expected state, unless
#: explicitly listed.
_EMPTY_MEANINGFUL_KINDS = frozenset(
    {
        ResultKind.CONFIGURATION,
        ResultKind.APPLY_STATUS,
        ResultKind.DERIVED_STATE,
        ResultKind.HISTORY,
    }
)

#: Tools whose underlying pfSense/pfREST model is documented (in this
#: project's own `models/` package, cross-checked against pfREST's own
#: field semantics -- not re-verified live upstream by this module)
#: to intentionally omit or redact secret-shaped fields (API keys,
#: passwords, private key material) from the READ response. Kept
#: narrow and explicit rather than inferred from tool name.
_SECRETS_OMITTED_TOOLS = frozenset(
    {
        "pfsense_get_auth_keys",
        "pfsense_get_system_certificates",
        "pfsense_get_system_certificate_authorities",
        "pfsense_get_users",
        "pfsense_get_system_restapi_settings",
    }
)


def get_tool_guidance(tool_name: str) -> ToolGuidance | None:
    """Pure, deterministic, offline (I5-style discipline, same as
    `registry.lookup_guidance()`): identical input always produces
    identical output, never raises, never guesses. Returns `None` for
    any name not in `_TOOL_RESULT_KIND` -- an unknown tool name is a
    real "no guidance" answer, never fabricated.
    """

    kind = _TOOL_RESULT_KIND.get(tool_name)
    if kind is None:
        return None

    template = _RESULT_KIND_TEMPLATES[kind]
    override = _TOOL_OVERRIDES.get(tool_name)
    interpretation = f"{template} {override}" if override else template
    if len(interpretation) > MAX_EXCERPT_LENGTH:
        # Defensive, not expected to trigger with the current fixed
        # template/override set -- fails closed rather than silently
        # emitting an unbounded string if a future override is too long.
        interpretation = interpretation[: MAX_EXCERPT_LENGTH - 3] + "..."

    return ToolGuidance(
        tool_name=tool_name,
        result_kind=kind,
        interpretation=interpretation,
        related_tools=_TOOL_RELATED.get(tool_name, ()),
        empty_result_is_meaningful=kind in _EMPTY_MEANINGFUL_KINDS,
        secrets_intentionally_omitted=tool_name in _SECRETS_OMITTED_TOOLS,
    )


def known_tool_names() -> frozenset[str]:
    """Every tool name this module has a classification for -- exposed
    so tests (and any future consumer) can cross-check against the real
    public contract without reaching into this module's private dict
    directly."""

    return frozenset(_TOOL_RESULT_KIND)
