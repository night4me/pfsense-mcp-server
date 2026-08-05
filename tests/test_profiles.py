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


def test_engineer_profile_has_no_capabilities_yet():
    assert EngineerProfile.capabilities == frozenset()


def test_get_profile_returns_auditor():
    assert get_profile("auditor") is AuditorProfile


def test_get_profile_returns_engineer():
    assert get_profile("engineer") is EngineerProfile


def test_get_profile_rejects_unknown_name():
    with pytest.raises(ConfigurationError):
        get_profile("nonexistent")
