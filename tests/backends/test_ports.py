"""Structural sanity for ADR-030's port definitions -- proves each
Protocol is satisfiable by a plain class returning the existing
domain models unchanged, without asserting anything about a real
backend (none exists yet)."""

from __future__ import annotations

from pfsense_mcp.backends.ports import FirewallAliasReader, GatewayStatusReader, SystemPackageReader
from pfsense_mcp.models.firewall_alias import FirewallAlias
from pfsense_mcp.models.gateways import GatewayStatus
from pfsense_mcp.models.system_package import SystemPackage


class _FakeGatewayStatusReader:
    def get_gateway_status(self) -> list[GatewayStatus]:
        return []


class _FakeFirewallAliasReader:
    def get_firewall_aliases(self) -> list[FirewallAlias]:
        return []


class _FakeSystemPackageReader:
    def get_system_packages(self) -> list[SystemPackage]:
        return []


def test_gateway_status_reader_is_structurally_satisfiable():
    reader: GatewayStatusReader = _FakeGatewayStatusReader()
    assert reader.get_gateway_status() == []


def test_firewall_alias_reader_is_structurally_satisfiable():
    reader: FirewallAliasReader = _FakeFirewallAliasReader()
    assert reader.get_firewall_aliases() == []


def test_system_package_reader_is_structurally_satisfiable():
    reader: SystemPackageReader = _FakeSystemPackageReader()
    assert reader.get_system_packages() == []


def test_ports_module_has_no_concrete_nexus_implementation():
    """ADR-030: this Phase intentionally stops at Protocol definitions.
    A concrete Nexus reader would require fabricating fields the
    schema doesn't provide -- see the compatibility matrix's PARTIAL/
    UNKNOWN rows. Guards against a future edit silently adding one
    without updating this test and the ADR."""

    import pfsense_mcp.backends.ports as ports_module

    assert not hasattr(ports_module, "NexusClient")
    assert not hasattr(ports_module, "NexusGatewayStatusReader")
