from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.config import PfSenseConfig
from pfsense_mcp.factory import build_pfsense_client
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.profiles import AuditorProfile
from pfsense_mcp.tls import TLSMode
from pfsense_mcp.transport.http import HttpTransport


def _config() -> PfSenseConfig:
    return PfSenseConfig(
        base_url="https://pfsense.example.invalid",
        identity="api-mcp-admin",
        key_file=None,
        tls_mode=TLSMode.INSECURE,
        tls_ca_file=None,
        api_version=ApiVersion.V2,
        profile=AuditorProfile,
        log_max_bytes=5_000_000,
        log_backup_count=5,
    )


def test_build_pfsense_client_returns_expected_types():
    transport, client = build_pfsense_client(_config(), "fake-key")
    try:
        assert isinstance(transport, HttpTransport)
        assert isinstance(client, PfSenseClient)
    finally:
        transport.close()
