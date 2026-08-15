"""set_firewall_alias_description_v1 tool definition -- the first, and
(per the durable owner roadmap decision recorded in
`reports-ai/AI_CONTEXT.md`) only, WRITE MCP tool this build implements.

Imports only `pfsense_mcp.tier1_write_bridge` -- never
`pfsense_mcp.tier1` directly, never `WriteApiClient`, never
`MutationExecutor`. This module performs no authorization, confirmation,
or security logic of its own; it is a thin FastMCP adapter over the
bridge's own single entry point.
"""

from __future__ import annotations

from typing import Callable

from ... import tier1_write_bridge
from ...models.write_outcome import AliasDescriptionWriteResult


def build() -> Callable[..., AliasDescriptionWriteResult]:
    def set_firewall_alias_description_v1(alias_name: str, description: str) -> AliasDescriptionWriteResult:
        """Request a description-only change to an existing pfSense
        firewall alias. This is an asynchronous, authorization-gated
        operation -- a successful call does not itself mean the change
        has taken effect.

        alias_name: the exact, existing alias name (unchanged by this
        operation -- only its description is ever modified).

        description: the new description text for this alias.

        Returns one of five states: "requested" (no matching signed
        authorization has been provided yet -- an out-of-band, offline
        signing step is required before this operation can proceed);
        "awaiting_confirmation" (an authorization was accepted and the
        change is durably pending -- an out-of-band, offline confirmation
        step is required); "verified" (the description change has been
        confirmed applied); "reconciliation_required" (the outcome could
        not be determined with certainty and requires operator
        reconciliation); "refused" (the request could not proceed, for
        any of several reasons that are never distinguished in this
        response).

        Re-invoke this tool with the identical alias_name/description to
        check on or advance a pending request -- the same request is
        recognized and resumed rather than started over."""

        return tier1_write_bridge.request_alias_description_change(alias_name=alias_name, description=description)

    return set_firewall_alias_description_v1
