"""pfsense_mcp_info tool definition.

Unlike every other READ tool, this one has no PfSenseClient dependency
and makes no pfSense API call — every field it reports is a fact about
this server process itself, already resolved by the time ToolRegistry
finishes register_all(). build() therefore takes a snapshot provider
callback (supplied by ToolRegistry, the one place that actually knows
the live registered-tool counts and active capability set) instead of
a client.
"""

from __future__ import annotations

from typing import Callable

from ...models.server_introspection import ServerIntrospection


def build(snapshot: Callable[[], ServerIntrospection]) -> Callable[..., ServerIntrospection]:
    def pfsense_mcp_info() -> ServerIntrospection:
        """Get this MCP server's own version, active capability profile,
        registered tool counts, and WRITE/Tier-1/ADR-017 state — so a
        client can determine actual capability and safety state without
        inference. Read-only, local only: makes no pfSense API call.

        Every field is a deterministic local fact, independently and
        redundantly enforced elsewhere (capability gating, the empty
        WriteEndpoints allow-list, CI-enforced Tier 1/ADR-017 isolation
        tests) — this tool only reports already-enforced state and
        cannot itself grant or change any capability."""
        return snapshot()

    return pfsense_mcp_info
