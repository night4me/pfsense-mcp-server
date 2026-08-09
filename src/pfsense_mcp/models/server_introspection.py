"""Model for the pfsense_mcp_info introspection tool.

Every field is a deterministic local fact about this server process —
this build's version, its active profile, its actually-registered tool
counts, and whether the inert Tier 1 / ADR-017 guidance packages have
been imported. Nothing here is derived from a pfSense API call, and
nothing here grants or represents authorization: each fact is already
independently, redundantly enforced elsewhere (capability gating in
ToolRegistry, the empty WriteEndpoints allow-list, the CI-enforced Tier
1 / guidance isolation tests). This tool only reports already-enforced
state; it cannot change it.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ServerIntrospection(BaseModel):
    server_version: str = Field(description="pfsense-mcp-server package version (importlib.metadata).")
    active_profile: str = Field(description="This server instance's active capability profile name.")
    registered_tool_count: int = Field(
        description="Total MCP tools actually registered on this running instance "
        "(after capability and PFSENSE_ALLOWED_TOOLS filtering) — includes this tool itself."
    )
    registered_read_tool_count: int = Field(description="Of registered_tool_count, how many are READ tools.")
    registered_write_tool_count: int = Field(
        description="Of registered_tool_count, how many are WRITE tools. Always 0 in this build — "
        "register_all_write() registers nothing."
    )
    active_capability_set: tuple[str, ...] = Field(
        description="Capability names granted to this server instance's active profile "
        "(the same set ToolRegistry used to decide what to register)."
    )
    active_write_capabilities: tuple[str, ...] = Field(
        description="Of active_capability_set, the entries whose name ends in _WRITE. "
        "Always empty in this build — independently, redundantly re-verified by "
        "scripts/write_capability_check.py in CI."
    )
    active_write_endpoint_count: int = Field(
        description="Entries in the WriteEndpoints mutation allow-list. Always 0 in this build. "
        "This is the allow-list WriteApiClient.execute() itself consults before any network "
        "call — not a separate, potentially-drifting count."
    )
    tier1_package_present: bool = Field(
        description="Whether pfsense_mcp.tier1 is present in this installed distribution "
        "(a packaging fact, not a capability — Tier 1 registers no tool and is never "
        "imported by production bootstrap, independent of whether it is present)."
    )
    tier1_imported_this_process: bool = Field(
        description="Whether pfsense_mcp.tier1 has been imported anywhere in this running "
        "process (sys.modules check). Expected to always be false. This is observed "
        "runtime evidence, not a substitute for the structural isolation CI enforces "
        "(tests/tier1/test_isolation.py) — a false value here does not itself prove "
        "unreachability, only that nothing has imported it yet in this process."
    )
    guidance_package_present: bool = Field(
        description="Whether pfsense_mcp.guidance (ADR-017's official documentation "
        "guidance layer) is present in this installed distribution — packaging fact only."
    )
    guidance_imported_this_process: bool = Field(
        description="Whether pfsense_mcp.guidance has been imported anywhere in this running "
        "process (sys.modules check). Expected to always be false — no READ tool or Tier 1 "
        "path consumes it yet. Same caveat as tier1_imported_this_process: observed runtime "
        "evidence, not a substitute for CI-enforced isolation."
    )
    mcp_transport: str = Field(description="The MCP transport this build serves over. Always 'stdio'.")
