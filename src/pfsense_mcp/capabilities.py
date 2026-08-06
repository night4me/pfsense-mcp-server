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
    # Not usable until a separate, explicitly authorized implementation phase:
    FIREWALL_WRITE = auto()
    ALIAS_WRITE = auto()
    SERVICE_WRITE = auto()


SUPPORTED_CAPABILITIES_THIS_BUILD: frozenset[Capability] = frozenset(
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
    }
)
