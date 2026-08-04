"""ToolRegistry — the only place mcp.tool() is called. Registration
is gated by which capabilities are active for this server instance."""

from __future__ import annotations

from ..capabilities import Capability
from ..pfsense_client import PfSenseClient
from .audit import audit_logged
from .read import system_status


class ToolRegistry:
    def __init__(self, mcp, client: PfSenseClient, identity: str, capabilities: frozenset[Capability]) -> None:
        self._mcp = mcp
        self._client = client
        self._identity = identity
        self._capabilities = capabilities

    def register_all(self) -> None:
        if Capability.SYSTEM_READ in self._capabilities:
            self._register_system_read()

    def _register_system_read(self) -> None:
        fn = system_status.build(self._client)
        wrapped = audit_logged("pfsense_get_system_status", self._identity)(fn)
        self._mcp.tool()(wrapped)
