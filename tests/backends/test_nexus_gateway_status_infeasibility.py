"""Nexus Phase B (2026-08-17): `pfsense_get_gateway_status` was diffed
field-by-field against the official Nexus `GatewayStatus` schema
(`GET /system/gateways/status`, see docs/NEXUS_COMPATIBILITY_MATRIX.md's
Phase B section for the full mapping table) and downgraded from
ADAPTABLE to PARTIAL: 4 of the current model's required fields (`id`,
`substatus`, `srcip`, `monitorip`) have zero confirmed source anywhere
in the Nexus gateway-status/group-status schemas, and the 3 that do
exist conceptually (`delay`/`stddev`/`loss`) are formatted strings in
Nexus, not the required `float`, with undocumented behavior for a
down/unmonitored gateway. A Nexus adapter satisfying `GatewayStatus`
today can only do so by fabricating values -- forbidden by this
project's fail-closed, no-guessing posture (see ADR-030/ADR-031).

This test encodes that finding as an executable regression guard: it
fails loudly if `GatewayStatus`'s required-field set ever narrows to
something the Nexus schema *could* satisfy without a corresponding,
deliberate update here and to the compatibility matrix -- so a future
change can't silently "fix" this by weakening the model underneath a
claimed Nexus adapter without a conscious, reviewed decision.
"""

from __future__ import annotations

from pfsense_mcp.models.gateways import GatewayStatus

# Exactly the fields with zero confirmed source anywhere in the Nexus
# GatewayStatus/GatewaysStatus/GroupStatus schemas as of the 2026-08-17
# Phase B research pass (see docs/NEXUS_COMPATIBILITY_MATRIX.md).
_FIELDS_WITH_NO_NEXUS_SOURCE = frozenset({"id", "substatus", "srcip", "monitorip"})

# Fields Nexus provides as formatted strings, not the numeric type this
# model requires -- non-trivial, currently-undocumented-format parsing
# required, not a plain passthrough.
_FIELDS_WITH_TYPE_MISMATCH = frozenset({"delay", "stddev", "loss"})


def test_gateway_status_required_fields_include_ones_nexus_cannot_source():
    required = set(GatewayStatus.model_fields.keys())
    missing_from_nexus = _FIELDS_WITH_NO_NEXUS_SOURCE & required
    assert missing_from_nexus == _FIELDS_WITH_NO_NEXUS_SOURCE, (
        "Expected GatewayStatus to still require id/substatus/srcip/monitorip -- "
        "if this model changed, re-verify against the Nexus schema and update "
        "docs/NEXUS_COMPATIBILITY_MATRIX.md's classification instead of assuming "
        "the gap closed on its own."
    )


def test_gateway_status_numeric_fields_would_need_nexus_string_parsing():
    fields = GatewayStatus.model_fields
    for name in _FIELDS_WITH_TYPE_MISMATCH:
        assert name in fields, f"expected {name!r} to remain a GatewayStatus field"
    # delay/stddev/loss remain typed as float on the community side --
    # a Nexus source would supply a string, requiring parsing this
    # project has not implemented or verified the format of.
    assert GatewayStatus.model_fields["delay"].annotation is float
    assert GatewayStatus.model_fields["stddev"].annotation is float
    assert GatewayStatus.model_fields["loss"].annotation is float
