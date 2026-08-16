"""Mutation allow-list — the single source of truth for which
(path, HTTP method) pairs this server is ever permitted to write to.

Through W3 Slice 3, empty in this build. W3 Slice 4 (ADR-028) adds the
single accepted first-WRITE entry, `FIREWALL_ALIAS_DESCRIPTION` — the
description-only firewall-alias PATCH ADR-026 selected and ADR-028's
three-condition activation gate governs. WriteApiClient.execute()/
send_for_tier1() refuse any MutationPlan/Tier-1 send whose endpoint_symbol
is not an attribute of WriteEndpoints here, before any network call is
made. scripts/write_allow_list_check.py mechanically enforces that this
class has *exactly* this one entry and no more — matching the durable
owner roadmap ceiling (`reports-ai/AI_CONTEXT.md`): any further
WriteEndpoints entry is explicitly post-v0.4.0 work requiring a new,
separate, explicit owner decision.

`FIREWALL_ALIAS_DESCRIPTION.verified` is deliberately `False`: no live
verification of this specific write path has occurred yet (ADR-026's
own acceptance matrix rows 6/17/18 remain the outstanding live-evidence
gap, tracked separately from W3 Slice 4). `WriteApiClient` refuses any
send/execute against an endpoint whose `verified` is not `True` — so
this entry existing, and even the full W3 Slice 4 three-condition
activation gate being satisfied, still cannot reach a live pfSense
mutation until that separately-tracked live-evidence work completes and
sets `verified=True` as its own, separately authorized change. This is
an intentional, additional layer of protection beyond the activation
gate, not an oversight.

Every entry requires: independent live verification before `verified` is
set `True` (the same bar `Endpoints.verified` already sets), an explicit
RollbackPlan if `reversible=True` (this entry's rollback is the existing
alias-description execution core's own snapshot/restore mechanism, not a
new one), and `dry_run_supported=True`.
"""

from __future__ import annotations

from dataclasses import dataclass

from .api_version import ApiVersion


@dataclass(frozen=True)
class WriteEndpointInfo:
    path_suffix: str  # e.g. "/firewall/alias" — no "/api/vN" prefix
    http_method: str  # "POST" | "PUT" | "PATCH" | "DELETE"
    verified: bool
    min_api_version: ApiVersion
    reversible: bool
    dry_run_supported: bool
    #: ADR-029: a distinct, independently-gated property from `verified`.
    #: `True` only permits use through `WriteApiClient.send_for_tier1_
    #: acceptance()` (tier1/acceptance.py) -- a separate, structurally
    #: isolated, LAB-only path for gathering the live evidence that
    #: justifies promoting `verified` to `True`. Never consulted by
    #: `dry_run()`/`execute()`/`send_for_tier1()`, which remain gated on
    #: `verified` alone, unchanged. Default `False` -- every entry must
    #: opt in explicitly.
    acceptance_eligible: bool = False


class WriteEndpoints:
    """Exactly one entry in this build. See module docstring."""

    #: ADR-026's selected, narrowest evidenced first-WRITE candidate:
    #: `PATCH /api/v2/firewall/alias`, description field only. `verified`
    #: is `False` until the separately-tracked live-evidence work sets it
    #: `True` -- see module docstring.
    FIREWALL_ALIAS_DESCRIPTION = WriteEndpointInfo(
        path_suffix="/firewall/alias",
        http_method="PATCH",
        verified=False,
        min_api_version=ApiVersion.V2,
        reversible=True,
        dry_run_supported=True,
        # ADR-029: this is the one endpoint gathering its own promotion
        # evidence via the acceptance-only path. Not a second WRITE
        # capability -- normal exposure still requires verified=True,
        # unchanged.
        acceptance_eligible=True,
    )

    @classmethod
    def active_entries(cls) -> list[str]:
        """Names of all WriteEndpointInfo entries currently declared here.

        The single source of truth for "how many write endpoints are
        allow-listed" — scripts/write_allow_list_check.py and any
        runtime introspection both call this instead of each keeping
        their own copy of the same vars()-scan.
        """
        return [name for name, value in vars(cls).items() if isinstance(value, WriteEndpointInfo)]
