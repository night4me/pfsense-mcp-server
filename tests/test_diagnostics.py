from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.config import PfSenseConfig
from pfsense_mcp.diagnostics import build_diagnostics_report
from pfsense_mcp.profiles import AuditorProfile
from pfsense_mcp.tls import TLSMode


def _config() -> PfSenseConfig:
    return PfSenseConfig(
        base_url="https://pfsense.example.invalid",
        identity="api-mcp-admin",
        key_file=None,
        tls_mode=TLSMode.INSECURE,
        tls_ca_file=None,
        api_version=ApiVersion.V2,
        profile=AuditorProfile,
        log_max_bytes=1_000_000,
        log_backup_count=3,
    )


def test_diagnostics_report_reflects_config_without_network():
    report = build_diagnostics_report(_config(), transport_type="HttpTransport")
    assert report.identity == "api-mcp-admin"
    assert report.profile_name == "auditor"
    assert "SYSTEM_READ" in report.capabilities
    assert report.tls_mode == "insecure"
    assert report.api_version == "v2"
    assert report.transport_type == "HttpTransport"
    assert report.log_max_bytes == 1_000_000
    assert report.log_backup_count == 3
