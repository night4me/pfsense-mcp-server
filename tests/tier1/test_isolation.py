from pathlib import Path

from pfsense_mcp.profiles import EngineerProfile
from pfsense_mcp.tier1.policy import INACTIVE_TIER1_POLICY
from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints

ROOT = Path(__file__).parents[2]


def test_tier1_is_not_imported_by_production_bootstrap():
    for relative in (
        "src/pfsense_mcp/__init__.py",
        "src/pfsense_mcp/application.py",
        "src/pfsense_mcp/factory.py",
        "src/pfsense_mcp/server.py",
        "src/pfsense_mcp/tools/registry.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "pfsense_mcp.tier1" not in text
        assert "from .tier1" not in text


def test_tier1_domain_has_no_transport_or_tool_registration_dependency():
    for path in (ROOT / "src/pfsense_mcp/tier1").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "WriteApiClient" not in text
        assert "HttpTransport" not in text
        assert "FastMCP" not in text
        assert ".tool(" not in text


def test_all_production_write_surfaces_remain_inactive():
    assert EngineerProfile.capabilities == frozenset()
    assert INACTIVE_TIER1_POLICY.rules == frozenset()
    assert not any(isinstance(value, WriteEndpointInfo) for value in vars(WriteEndpoints).values())
