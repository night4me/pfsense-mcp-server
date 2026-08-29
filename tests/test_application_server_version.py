"""v1.0.0 human clean-room finding (2026-08-29): FastMCP never forwards
a `version=` to the low-level `mcp.server.lowlevel.Server` it builds
internally, so an unset `.version` falls back to the installed `mcp`
SDK package's own version in every MCP `initialize` response --
confusingly distinct from the actual installed product version.
Application.__init__ now sets that attribute explicitly; these tests
prove it resolves to the real package version and degrades safely if
the SDK's internal shape ever changes. `pfsense_mcp_info`'s own
`server_version` field (a second, pre-existing version call site) was
consolidated onto the same shared resolver in the same fix."""

import importlib.metadata

from mcp.server.fastmcp import FastMCP

from pfsense_mcp._version import resolve_package_version
from pfsense_mcp.application import Application
from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD
from pfsense_mcp.tools.registry import ToolRegistry


def test_mcp_server_version_matches_the_installed_product_package_version():
    app = Application()
    assert app._mcp._mcp_server.version == importlib.metadata.version("pfsense-mcp-server")


def test_mcp_server_version_is_never_the_raw_mcp_sdk_version_by_accident():
    app = Application()
    assert app._mcp._mcp_server.version != importlib.metadata.version("mcp")


def test_resolve_package_version_handles_a_non_installed_package_gracefully(monkeypatch):
    def _raise(_name):
        raise importlib.metadata.PackageNotFoundError(_name)

    monkeypatch.setattr(importlib.metadata, "version", _raise)
    assert resolve_package_version() == "unknown (not installed as a package)"


def test_missing_internal_mcp_server_attribute_never_crashes_construction(monkeypatch):
    class _NoVersionAttr:
        __slots__ = ()

    def _fake_fastmcp_init(self, *_args, **_kwargs):
        self._mcp_server = _NoVersionAttr()

    monkeypatch.setattr("pfsense_mcp.application.FastMCP.__init__", _fake_fastmcp_init)
    app = Application()
    assert isinstance(app._mcp._mcp_server, _NoVersionAttr)


def test_pfsense_mcp_info_server_version_uses_the_same_shared_resolver():
    registry = ToolRegistry(FastMCP("test"), None, "test", SUPPORTED_CAPABILITIES_THIS_BUILD)
    snapshot = registry._build_introspection_snapshot()
    assert snapshot.server_version == importlib.metadata.version("pfsense-mcp-server")
    assert snapshot.server_version != importlib.metadata.version("mcp")
