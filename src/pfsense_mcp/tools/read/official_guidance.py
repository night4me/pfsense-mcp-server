"""pfsense_get_official_guidance tool definition.

**The one deliberate, reviewed import-boundary crossing** between the
production MCP tool surface and the previously fully-isolated
`pfsense_mcp.guidance` package (ADR-017/018), owner-authorized
2026-08-22 (Candidate A from
`reports-ai/GUIDANCE_MCP_EXPOSURE_QUALIFICATION_2026-08-22.md`).
`tests/guidance/test_isolation.py` allows exactly this one file to import
`pfsense_mcp.guidance` — nowhere else does, still enforced by AST scan.

This is a GUIDANCE tool, not a pfSense appliance READ capability: it is
not gated by, and does not consume, the `Capability`/privilege/profile
system that governs appliance access (no new `Capability` member was
added for it). It is accounted for separately from the 95 pfSense READ
tools in the public contract (`KNOWN_GUIDANCE_TOOL_NAMES`, distinct from
`KNOWN_READ_TOOL_NAMES`) — never blended into a "96 READ tools" claim.

**Identity resolution is tool-resolved, never model-supplied** (explicit
owner decision, 2026-08-22): this tool uses the *same*, already-
authenticated `PfSenseClient` instance every other READ tool already
uses, via `resolve_appliance_identity()` — the one canonical assembly
point ADR-018 Finding 10 already designated for exactly this, calling
nothing beyond the existing `pfsense_get_system_version`-equivalent
client method. The AI/model is never asked for, and this function never
accepts, an edition/version/identity parameter. On any failure (network,
privilege denial, malformed response — anything `PfSenseMCPError`
covers), this falls back to `ObservedEdition.UNKNOWN`/
`observed_version=None` — fail-closed, exactly the guidance layer's
existing I6 discipline: absence/ambiguity resolves to "no confident
match," never a guess, and never raises past this tool's own boundary.

**Zero runtime documentation network access**: this module never imports
`urllib`/`requests`/`httpx`, never calls `scripts/guidance_corpus_audit.py`,
and never fetches `docs.netgate.com` or any URL. `lookup_guidance()` is a
pure, deterministic, offline function over the Git-tracked registry — the
only network call this tool ever makes is the single, already-authorized
appliance-identity call described above.

**Failure independence (release-readiness audit, 2026-08-22): the
`pfsense_mcp.guidance.registry`/`appliance_identity` imports are
deliberately deferred to call time, inside `pfsense_get_official_guidance()`
itself, not placed at this module's top level.** `registry.py` runs a
load-time integrity self-check (`_check_registry_integrity()`) as a side
effect of being imported — correct and desired for catching a corrupted
registry entry, but only if that check's failure mode stays scoped to
this one tool. Since `tools/registry.py` imports this module at its own
top level (to register every tool during server startup), a module-level
import here would put the guidance registry's integrity check on the
*server startup* path for every profile with any capability granted —
meaning a corrupted guidance registry entry could crash the entire MCP
server, taking all 95 pfSense READ tools down with it. Deferring the
import to call time means a corrupted registry can only ever fail this
one tool's own calls, never server startup or any other tool -- verified
directly in `tests/test_official_guidance_tool.py` (failure-independence
tests).
Only `GuidanceReference` (needed at module level for `OfficialGuidanceResult`'s
own Pydantic field type, hence for MCP schema generation at registration
time) is imported from `models.py` — which does not import `registry.py`
and therefore never triggers its integrity check.
"""

from __future__ import annotations

from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict

from pfsense_mcp.guidance.models import GuidanceReference

from ...capabilities import Capability
from ...errors import PfSenseMCPError
from ...pfsense_client import PfSenseClient


class OfficialGuidanceResult(BaseModel):
    """The only shape `pfsense_get_official_guidance` ever returns.

    `guidance` reuses `GuidanceReference` unchanged — ADR-017/018's own
    closed, G1-compliant, already-tested type. No parallel schema and no
    parallel applicability logic is invented here; `source_verification_excerpt`
    is structurally absent from `GuidanceReference` (verified by
    `tests/guidance/test_models.py::test_guidance_reference_has_no_source_verification_excerpt_field`),
    so this tool cannot leak the maintainer-only verification anchor even
    by accident.

    `disclaimer` is a fixed `Literal`, not free text: a structural, not
    merely prose-based, signal that this content is documentation
    guidance, never observed appliance state or authorization (owner
    instruction, 2026-08-22).
    """

    model_config = ConfigDict(extra="forbid")

    requested_capability: str
    guidance: tuple[GuidanceReference, ...]
    disclaimer: Literal[
        "This is official pfSense/Netgate documentation guidance, project-authored from "
        "official Netgate sources. It is NOT observed live appliance state and does NOT "
        "authorize any action. For current appliance configuration or status, use the "
        "relevant pfsense_get_* READ tool instead."
    ] = (
        "This is official pfSense/Netgate documentation guidance, project-authored from "
        "official Netgate sources. It is NOT observed live appliance state and does NOT "
        "authorize any action. For current appliance configuration or status, use the "
        "relevant pfsense_get_* READ tool instead."
    )


def build(client: PfSenseClient) -> Callable[..., OfficialGuidanceResult]:
    def pfsense_get_official_guidance(capability: str) -> OfficialGuidanceResult:
        """Get project-authored official pfSense/Netgate documentation
        guidance for a known pfsense-mcp-server capability, with
        structural provenance (canonical Netgate source URL, edition/
        version applicability, evidence level). Read-only.

        This tool returns DOCUMENTATION GUIDANCE, never observed live
        appliance state and never authorization for any action. For the
        appliance's actual current configuration or status, use the
        relevant pfsense_get_* READ tool instead.

        The appliance edition/version used to resolve applicability are
        obtained by this tool itself from the connected pfSense
        appliance's own reported system version — never accepted as an
        input parameter, and never supplied by the caller.

        capability: the pfsense-mcp-server capability name to fetch
        guidance for (e.g. "FIREWALL_NAT_READ"). Unknown names are
        rejected rather than guessed at.
        """
        # Deferred to call time, deliberately -- see this module's
        # docstring ("Failure independence") for why these two imports
        # must never move to module level.
        from pfsense_mcp.guidance.appliance_identity import ObservedEdition, resolve_appliance_identity
        from pfsense_mcp.guidance.registry import lookup_guidance

        if capability not in Capability.__members__:
            raise ValueError(f"Unknown capability: {capability!r}")
        requested = Capability[capability]

        try:
            identity = resolve_appliance_identity(client)
            observed_edition = identity.observed_edition
            observed_version = identity.observed_version
        except PfSenseMCPError:
            observed_edition = ObservedEdition.UNKNOWN
            observed_version = None

        guidance = lookup_guidance(requested, observed_version, observed_edition)
        return OfficialGuidanceResult(requested_capability=capability, guidance=guidance)

    return pfsense_get_official_guidance
