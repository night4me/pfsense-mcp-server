import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.errors import ConfigurationError
from pfsense_mcp.profiles import AuditorProfile, EngineerProfile, get_profile


def test_auditor_profile_has_system_read():
    assert Capability.SYSTEM_READ in AuditorProfile.capabilities


def test_auditor_profile_has_gateway_read():
    assert Capability.GATEWAY_READ in AuditorProfile.capabilities


def test_auditor_profile_has_firewall_read():
    assert Capability.FIREWALL_READ in AuditorProfile.capabilities


def test_auditor_profile_has_system_info_read():
    assert Capability.SYSTEM_INFO_READ in AuditorProfile.capabilities


def test_auditor_profile_has_interface_config_read():
    assert Capability.INTERFACE_CONFIG_READ in AuditorProfile.capabilities


def test_auditor_profile_has_firewall_nat_read():
    assert Capability.FIREWALL_NAT_READ in AuditorProfile.capabilities


def test_auditor_profile_has_user_read():
    assert Capability.USER_READ in AuditorProfile.capabilities


def test_auditor_profile_has_system_certificate_read():
    assert Capability.SYSTEM_CERTIFICATE_READ in AuditorProfile.capabilities


def test_auditor_profile_has_user_group_read():
    assert Capability.USER_GROUP_READ in AuditorProfile.capabilities


def test_auditor_profile_has_dhcp_lease_read():
    assert Capability.DHCP_LEASE_READ in AuditorProfile.capabilities


def test_auditor_profile_has_dhcp_static_mapping_read():
    assert Capability.DHCP_STATIC_MAPPING_READ in AuditorProfile.capabilities


def test_auditor_profile_has_dhcp_server_read():
    assert Capability.DHCP_SERVER_READ in AuditorProfile.capabilities


def test_auditor_profile_has_interface_virtual_read():
    assert Capability.INTERFACE_VIRTUAL_READ in AuditorProfile.capabilities


def test_auditor_profile_has_status_carp_read():
    assert Capability.STATUS_CARP_READ in AuditorProfile.capabilities


def test_auditor_profile_has_system_restapi_settings_read():
    assert Capability.SYSTEM_RESTAPI_SETTINGS_READ in AuditorProfile.capabilities


def test_auditor_profile_has_system_ha_sync_read():
    assert Capability.SYSTEM_HA_SYNC_READ in AuditorProfile.capabilities


def test_engineer_profile_has_no_capabilities_yet():
    assert EngineerProfile.capabilities == frozenset()


def test_get_profile_returns_auditor():
    assert get_profile("auditor") is AuditorProfile


def test_get_profile_returns_engineer():
    assert get_profile("engineer") is EngineerProfile


def test_get_profile_rejects_unknown_name():
    with pytest.raises(ConfigurationError):
        get_profile("nonexistent")


def test_auditor_profile_has_services_dns_resolver_read():
    assert Capability.SERVICES_DNS_RESOLVER_READ in AuditorProfile.capabilities


def test_auditor_profile_has_diagnostics_arp_read():
    assert Capability.DIAGNOSTICS_ARP_READ in AuditorProfile.capabilities


def test_auditor_profile_has_firewall_traffic_shaper_read():
    assert Capability.FIREWALL_TRAFFIC_SHAPER_READ in AuditorProfile.capabilities


def test_auditor_profile_has_firewall_advanced_settings_read():
    assert Capability.FIREWALL_ADVANCED_SETTINGS_READ in AuditorProfile.capabilities


def test_auditor_profile_has_system_package_read():
    assert Capability.SYSTEM_PACKAGE_READ in AuditorProfile.capabilities


def test_auditor_profile_has_system_tunable_read():
    assert Capability.SYSTEM_TUNABLE_READ in AuditorProfile.capabilities


def test_auditor_profile_has_system_notifications_read():
    assert Capability.SYSTEM_NOTIFICATIONS_READ in AuditorProfile.capabilities
