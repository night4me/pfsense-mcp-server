"""Nexus Phase C (2026-08-17): `pfsense_get_firewall_aliases` was diffed
field-by-field against the official Nexus `FWAlias`/`FWAliases` schema
(`GET /aliases`, see docs/NEXUS_COMPATIBILITY_MATRIX.md's Phase C
section for the full mapping table) and classified PARTIAL, matching
gateway_status's Phase B outcome: `id` has zero confirmed source
anywhere in `FWAlias` or `FWSystemAlias` (the `/aliases/{id}` path
parameter is a string, almost certainly the alias's own `name`, not a
distinct numeric identifier), `descr`/`type` are optional in Nexus but
required keys in the current model, and `address`/`detail` have real
type and structural mismatches (a single space-separated string vs. a
required pre-split list; an ambiguous choice between `detail` and the
differently-shaped `targets` array). A Nexus adapter satisfying
`FirewallAlias` today can only do so by fabricating values -- forbidden
by this project's fail-closed, no-guessing posture (see ADR-030/031),
and explicitly declined by the owner for this exact reason.

This test encodes that finding as an executable regression guard,
mirroring test_nexus_gateway_status_infeasibility.py: it fails loudly
if `FirewallAlias`'s required-field set ever narrows to something the
Nexus schema *could* satisfy without a corresponding, deliberate
update here and to the compatibility matrix.
"""

from __future__ import annotations

from pfsense_mcp.models.firewall_alias import FirewallAlias

# Exactly the fields with zero confirmed source anywhere in the Nexus
# FWAlias/FWSystemAlias schemas as of the 2026-08-17 Phase C research
# pass (see docs/NEXUS_COMPATIBILITY_MATRIX.md).
_FIELDS_WITH_NO_NEXUS_SOURCE = frozenset({"id"})

# Fields Nexus provides as a different shape than this model requires --
# a single string where a pre-split list is required, not a plain
# passthrough.
_FIELDS_WITH_TYPE_MISMATCH = frozenset({"address", "detail"})


def test_firewall_alias_required_fields_include_ones_nexus_cannot_source():
    required = set(FirewallAlias.model_fields.keys())
    missing_from_nexus = _FIELDS_WITH_NO_NEXUS_SOURCE & required
    assert missing_from_nexus == _FIELDS_WITH_NO_NEXUS_SOURCE, (
        "Expected FirewallAlias to still require 'id' -- if this model "
        "changed, re-verify against the Nexus schema and update "
        "docs/NEXUS_COMPATIBILITY_MATRIX.md's classification instead of "
        "assuming the gap closed on its own."
    )


def test_firewall_alias_list_fields_would_need_nexus_string_parsing():
    fields = FirewallAlias.model_fields
    for name in _FIELDS_WITH_TYPE_MISMATCH:
        assert name in fields, f"expected {name!r} to remain a FirewallAlias field"
    # address/detail remain typed as list[str] | None on the community
    # side -- a Nexus source (FWAlias.address / .detail) supplies a
    # single space-separated string instead, requiring parsing whose
    # exact rules (multiple spaces, empty alias, unicode) this project
    # has not implemented or verified.
    assert FirewallAlias.model_fields["address"].annotation == (list[str] | None)
    assert FirewallAlias.model_fields["detail"].annotation == (list[str] | None)
