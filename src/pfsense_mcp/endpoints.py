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
    # Future entries added only after individual verification, e.g.:
    # ROUTING_STATIC_ROUTES = EndpointInfo("/routing/static_routes", verified=False, min_api_version=ApiVersion.V2)
