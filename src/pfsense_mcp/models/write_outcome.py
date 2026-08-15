"""Model-visible result of the first-WRITE product surface
(`set_firewall_alias_description_v1`). Exactly one field: the accepted
ADR-028 product-facing state projection, and nothing else -- no contract
identifier, no digest, no internal RecoveryState, no authorization or
confirmation artifact detail. A caller that wants to check on a pending
operation re-invokes the same tool with the same `alias_name`/`description`
-- the underlying runtime's own idempotency-key dedup finds the existing
`PREPARED` contract, so no opaque handle needs to round-trip through the
model.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

AliasDescriptionWriteState = Literal[
    "requested",
    "awaiting_confirmation",
    "verified",
    "reconciliation_required",
    "refused",
]


class AliasDescriptionWriteResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    state: AliasDescriptionWriteState
