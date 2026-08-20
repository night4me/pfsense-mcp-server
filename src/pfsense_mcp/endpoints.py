"""Single source of truth for every pfSense REST API endpoint this
project uses. No other module embeds a literal '/api/...' path
string — RestApiClient is the only place a full path is constructed.

Each entry's `verified` flag must be True only once the endpoint has
been independently tested via an authenticated GET against this
instance. tests/test_endpoints_verified.py enforces this mechanically.
"""

from __future__ import annotations

from dataclasses import dataclass

from .api_version import ApiVersion


@dataclass(frozen=True)
class EndpointInfo:
    path_suffix: str  # e.g. "/status/system" — no "/api/vN" prefix
    verified: bool
    min_api_version: ApiVersion


class Endpoints:
    SYSTEM_STATUS = EndpointInfo(
        path_suffix="/status/system",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_INTERFACES = EndpointInfo(
        path_suffix="/status/interfaces",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    ROUTING_GATEWAYS = EndpointInfo(
        path_suffix="/routing/gateways",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_GATEWAYS = EndpointInfo(
        path_suffix="/status/gateways",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_RULES = EndpointInfo(
        path_suffix="/firewall/rules",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_STATES = EndpointInfo(
        path_suffix="/firewall/states",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_STATES_SIZE = EndpointInfo(
        path_suffix="/firewall/states/size",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_APPLY_STATUS = EndpointInfo(
        path_suffix="/firewall/apply",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_ALIASES = EndpointInfo(
        path_suffix="/firewall/aliases",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_SERVICES = EndpointInfo(
        path_suffix="/status/services",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_VERSION = EndpointInfo(
        path_suffix="/system/version",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    INTERFACES = EndpointInfo(
        path_suffix="/interfaces",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_NAT_PORT_FORWARDS = EndpointInfo(
        path_suffix="/firewall/nat/port_forwards",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_NAT_OUTBOUND_MODE = EndpointInfo(
        path_suffix="/firewall/nat/outbound/mode",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20, owner-authorized live production READ
    # verification): the typed GET succeeded against the production
    # appliance (pfSense Plus 26.07-RELEASE) and returned the expected
    # {"data": [...]} envelope. The live account currently has zero
    # configured mappings, so per-field value parsing was not exercised
    # against real instance data -- compatibility for field types/
    # nullability is instead confirmed by an exact, byte-for-byte match
    # between the live OpenAPI schema's `OutboundNATMapping` component
    # (and this endpoint's full "Allowed privileges" description text)
    # and the pinned v2.10 reference this project's model was already
    # derived from. See docs/PFSENSE_LEAST_PRIVILEGE_MATRIX.md.
    FIREWALL_NAT_OUTBOUND_MAPPINGS = EndpointInfo(
        path_suffix="/firewall/nat/outbound/mappings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20) -- see FIREWALL_NAT_OUTBOUND_MAPPINGS's
    # comment immediately above; identical verification method and the
    # same live result (zero configured mappings, schema match exact).
    FIREWALL_NAT_ONE_TO_ONE_MAPPINGS = EndpointInfo(
        path_suffix="/firewall/nat/one_to_one/mappings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    USERS = EndpointInfo(
        path_suffix="/users",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_CERTIFICATES = EndpointInfo(
        path_suffix="/system/certificates",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    USER_GROUPS = EndpointInfo(
        path_suffix="/user/groups",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DIAGNOSTICS_CONFIG_HISTORY_REVISIONS = EndpointInfo(
        path_suffix="/diagnostics/config_history/revisions",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_DHCP_LEASES = EndpointInfo(
        path_suffix="/status/dhcp_server/leases",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DHCP_SERVER_STATIC_MAPPINGS = EndpointInfo(
        path_suffix="/services/dhcp_server/static_mappings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DHCP_SERVERS = EndpointInfo(
        path_suffix="/services/dhcp_servers",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    INTERFACE_BRIDGES = EndpointInfo(
        path_suffix="/interface/bridges",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    STATUS_CARP = EndpointInfo(
        path_suffix="/status/carp",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_RESTAPI_SETTINGS = EndpointInfo(
        path_suffix="/system/restapi/settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_HASYNC = EndpointInfo(
        path_suffix="/system/hasync",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DNS_RESOLVER_HOST_OVERRIDES = EndpointInfo(
        path_suffix="/services/dns_resolver/host_overrides",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DNS_RESOLVER_SETTINGS = EndpointInfo(
        path_suffix="/services/dns_resolver/settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DIAGNOSTICS_ARP_TABLE = EndpointInfo(
        path_suffix="/diagnostics/arp_table",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_TRAFFIC_SHAPER_LIMITERS = EndpointInfo(
        path_suffix="/firewall/traffic_shaper/limiters",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FIREWALL_ADVANCED_SETTINGS = EndpointInfo(
        path_suffix="/firewall/advanced_settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_PACKAGES = EndpointInfo(
        path_suffix="/system/packages",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_TUNABLES = EndpointInfo(
        path_suffix="/system/tunables",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SYSTEM_NOTIFICATIONS_EMAIL_SETTINGS = EndpointInfo(
        path_suffix="/system/notifications/email_settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    BIND_SETTINGS = EndpointInfo(
        path_suffix="/services/bind/settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    NTP_SETTINGS = EndpointInfo(
        path_suffix="/services/ntp/settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    NTP_TIME_SERVERS = EndpointInfo(
        path_suffix="/services/ntp/time_servers",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    SERVICES_SSH = EndpointInfo(
        path_suffix="/services/ssh",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    CRON_JOBS = EndpointInfo(
        path_suffix="/services/cron/jobs",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    ACME_SETTINGS = EndpointInfo(
        path_suffix="/services/acme/settings",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    FREERADIUS_EAP = EndpointInfo(
        path_suffix="/services/freeradius/eap",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    DIAGNOSTICS_TABLES = EndpointInfo(
        path_suffix="/diagnostics/tables",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    AUTH_KEYS = EndpointInfo(
        path_suffix="/auth/keys",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20, owner-authorized LAB READ verification,
    # Phase 8 of the READ capability audit): confirmed LAB identity first
    # (https://pfsense-test.lab.invalid, pfSense CE 2.8.1-RELEASE,
    # distinct from the production https://pfsense.local target) and
    # confirmed the LAB's REST API package is v2.10 -- an exact,
    # byte-for-byte match (267/267 paths) against the pinned v2.10
    # reference this model was derived from. The typed GET succeeded
    # (HTTP 200, correct {"data": [...]} envelope) with zero configured
    # VLANs on the LAB appliance at verification time --
    # ENDPOINT_VERIFIED, not FIELD_MODEL_LIVE_VERIFIED (no populated
    # object to exercise field parsing); compatibility for field types
    # is instead backed by the exact schema-component match above, the
    # same method already established for the NAT mappings verification.
    INTERFACE_VLANS = EndpointInfo(
        path_suffix="/interface/vlans",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20) -- see INTERFACE_VLANS's comment
    # INTERFACE_VLANS's comment immediately above; identical verification
    # method and the same live result (zero configured static routes,
    # schema match exact).
    ROUTING_STATIC_ROUTES = EndpointInfo(
        path_suffix="/routing/static_routes",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20, READ Expansion phase Batch 2, LAB-only
    # verification against https://pfsense-test.lab.invalid): HTTP 200,
    # correct envelope, zero configured interface groups at verification
    # time -- ENDPOINT_VERIFIED, not FIELD_MODEL_LIVE_VERIFIED; field-type
    # compatibility backed by the exact schema-component match already
    # established for this pass's LAB target (REST API v2.10, 267/267
    # paths matching the pinned reference).
    INTERFACE_GROUPS = EndpointInfo(
        path_suffix="/interface/groups",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20) -- same LAB verification pass as
    # INTERFACE_GROUPS immediately above; identical result (zero
    # configured firewall schedules, ENDPOINT_VERIFIED only).
    FIREWALL_SCHEDULES = EndpointInfo(
        path_suffix="/firewall/schedules",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
    # verified=True (2026-08-20) -- same LAB verification pass, but this
    # one reached FIELD_MODEL_LIVE_VERIFIED: the LAB's REST API package
    # returned a fully populated singleton object (current_version,
    # latest_version, latest_version_release_date, update_available,
    # available_versions all present; install_version genuinely absent
    # from the response, confirming SystemRestApiVersion.install_version's
    # optional-field design against real live data, not just schema).
    SYSTEM_RESTAPI_VERSION = EndpointInfo(
        path_suffix="/system/restapi/version",
        verified=True,
        min_api_version=ApiVersion.V2,
    )
