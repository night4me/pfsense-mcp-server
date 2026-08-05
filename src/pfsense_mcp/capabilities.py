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
    }
)
