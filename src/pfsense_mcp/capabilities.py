"""Capability model — the long-term authorization unit for this
server, replacing a simple read/write split."""

from __future__ import annotations

from enum import Enum, auto


class Capability(Enum):
    SYSTEM_READ = auto()
    INTERFACE_READ = auto()
    GATEWAY_READ = auto()
    FIREWALL_READ = auto()
    ALIAS_READ = auto()
    SERVICE_READ = auto()
    SYSTEM_INFO_READ = auto()
    INTERFACE_CONFIG_READ = auto()
    FIREWALL_NAT_READ = auto()
    USER_READ = auto()
    SYSTEM_CERTIFICATE_READ = auto()
    USER_GROUP_READ = auto()
    DHCP_LEASE_READ = auto()
    DHCP_STATIC_MAPPING_READ = auto()
    DHCP_SERVER_READ = auto()
    INTERFACE_VIRTUAL_READ = auto()
    STATUS_CARP_READ = auto()
    SYSTEM_RESTAPI_SETTINGS_READ = auto()
    SYSTEM_HA_SYNC_READ = auto()
    SERVICES_DNS_RESOLVER_READ = auto()
    DIAGNOSTICS_ARP_READ = auto()
    FIREWALL_TRAFFIC_SHAPER_READ = auto()
    FIREWALL_ADVANCED_SETTINGS_READ = auto()
    SYSTEM_PACKAGE_READ = auto()
    SYSTEM_TUNABLE_READ = auto()
    SYSTEM_NOTIFICATIONS_READ = auto()
    SERVICES_BIND_READ = auto()
    SERVICES_NTP_READ = auto()
    SERVICES_SSH_READ = auto()
    SERVICES_CRON_READ = auto()
    SERVICES_ACME_READ = auto()
    SERVICES_FREERADIUS_READ = auto()
    DIAGNOSTICS_TABLES_READ = auto()
    AUTH_KEYS_READ = auto()
    SERVER_INFO_READ = auto()
    INTERFACE_VLAN_READ = auto()
    ROUTING_STATIC_ROUTE_READ = auto()
    INTERFACE_GROUP_READ = auto()
    FIREWALL_SCHEDULE_READ = auto()
    SYSTEM_RESTAPI_VERSION_READ = auto()
    FIREWALL_VIRTUAL_IP_READ = auto()
    SYSTEM_CERTIFICATE_AUTHORITY_READ = auto()
    STATUS_IPSEC_SA_READ = auto()
    STATUS_IPSEC_CHILD_SA_READ = auto()
    STATUS_WIREGUARD_TUNNEL_READ = auto()
    STATUS_WIREGUARD_PEER_READ = auto()
    STATUS_OPENVPN_SERVER_READ = auto()
    STATUS_OPENVPN_CLIENT_READ = auto()
    STATUS_OPENVPN_SERVER_CONNECTION_READ = auto()
    STATUS_OPENVPN_SERVER_ROUTE_READ = auto()
    # Not usable until a separate, explicitly authorized implementation phase:
    FIREWALL_WRITE = auto()
    ALIAS_WRITE = auto()
    SERVICE_WRITE = auto()


# The complete READ capability set this build implements. Separated from
# SUPPORTED_CAPABILITIES_THIS_BUILD (below) so the two concepts -- "read
# capabilities that exist" and "capabilities implemented by this build" --
# can never again be conflated with "capabilities granted by a profile"
# (see profiles.py). Referencing this constant never implies a grant.
READ_CAPABILITIES: frozenset[Capability] = frozenset(
    {
        Capability.SYSTEM_READ,
        Capability.INTERFACE_READ,
        Capability.GATEWAY_READ,
        Capability.FIREWALL_READ,
        Capability.ALIAS_READ,
        Capability.SERVICE_READ,
        Capability.SYSTEM_INFO_READ,
        Capability.INTERFACE_CONFIG_READ,
        Capability.FIREWALL_NAT_READ,
        Capability.USER_READ,
        Capability.SYSTEM_CERTIFICATE_READ,
        Capability.USER_GROUP_READ,
        Capability.DHCP_LEASE_READ,
        Capability.DHCP_STATIC_MAPPING_READ,
        Capability.DHCP_SERVER_READ,
        Capability.INTERFACE_VIRTUAL_READ,
        Capability.STATUS_CARP_READ,
        Capability.SYSTEM_RESTAPI_SETTINGS_READ,
        Capability.SYSTEM_HA_SYNC_READ,
        Capability.SERVICES_DNS_RESOLVER_READ,
        Capability.DIAGNOSTICS_ARP_READ,
        Capability.FIREWALL_TRAFFIC_SHAPER_READ,
        Capability.FIREWALL_ADVANCED_SETTINGS_READ,
        Capability.SYSTEM_PACKAGE_READ,
        Capability.SYSTEM_TUNABLE_READ,
        Capability.SYSTEM_NOTIFICATIONS_READ,
        Capability.SERVICES_BIND_READ,
        Capability.SERVICES_NTP_READ,
        Capability.SERVICES_SSH_READ,
        Capability.SERVICES_CRON_READ,
        Capability.SERVICES_ACME_READ,
        Capability.SERVICES_FREERADIUS_READ,
        Capability.DIAGNOSTICS_TABLES_READ,
        Capability.AUTH_KEYS_READ,
        Capability.SERVER_INFO_READ,
        Capability.INTERFACE_VLAN_READ,
        Capability.ROUTING_STATIC_ROUTE_READ,
        Capability.INTERFACE_GROUP_READ,
        Capability.FIREWALL_SCHEDULE_READ,
        Capability.SYSTEM_RESTAPI_VERSION_READ,
        Capability.FIREWALL_VIRTUAL_IP_READ,
        Capability.SYSTEM_CERTIFICATE_AUTHORITY_READ,
        Capability.STATUS_IPSEC_SA_READ,
        Capability.STATUS_IPSEC_CHILD_SA_READ,
        Capability.STATUS_WIREGUARD_TUNNEL_READ,
        Capability.STATUS_WIREGUARD_PEER_READ,
        Capability.STATUS_OPENVPN_SERVER_READ,
        Capability.STATUS_OPENVPN_CLIENT_READ,
        Capability.STATUS_OPENVPN_SERVER_CONNECTION_READ,
        Capability.STATUS_OPENVPN_SERVER_ROUTE_READ,
    }
)

# "Implemented by this build" only -- never a grant. Distinct from
# READ_CAPABILITIES so a future capability can be added here (marking it
# implemented) without that alone making it reachable from any profile;
# only an explicit profile grant (profiles.py) and, for a WRITE capability,
# the full three-condition registration gate (ADR-028 W3-D2) can do that.
# Equal to READ_CAPABILITIES today because no WRITE capability is
# implemented yet.
SUPPORTED_CAPABILITIES_THIS_BUILD: frozenset[Capability] = READ_CAPABILITIES
