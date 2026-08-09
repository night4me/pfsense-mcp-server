"""Appliance identity resolution (ADR-018, Accepted -- architecture and
inert scaffolding only; no consumer wired).

The one authoritative representation of the observed pfSense appliance's
edition/version, and the one canonical assembly point
(`resolve_appliance_identity()`) any future consumer -- guidance
resolution, a future Tier 1 PREPARE precondition check, or
`pfsense_mcp_info` itself if a future explicit approval ever expands its
scope -- must share, rather than each independently re-deriving edition
from a version string (ADR-018 Finding 10).

Deliberately does not import `.models` or `.registry`: appliance-identity
resolution is independent of, and does not trigger, the document-registry
machinery (load-time integrity checks, the bundled corpus). Nothing here
selects a capability, endpoint, or WRITE action; nothing here has an
import path to `pfsense_mcp.tier1`, `WriteEndpoints`, or any WRITE-capable
transport -- same isolation discipline as the rest of this package,
verified by `tests/guidance/test_isolation.py`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict

from ..pfsense_client import PfSenseClient

#: pfSense CE has used major version 1 or 2 across its entire documented
#: history (1.2.x through the current 2.9.x). Source:
#: docs.netgate.com/pfsense/en/latest/releases/versions.html, re-verified
#: independently twice during ADR-018's design and red-team review
#: (2026-08-09). ANY future change to this bound must cite the specific
#: primary-source page/date re-verified against in the same commit --
#: this is a known-schemes table, reviewed against that page, not an
#: evergreen assumption (ADR-018 Finding 9).
_CE_MAX_MAJOR = 9

#: pfSense Plus's year-based numbering scheme began with version 21.02
#: (February 2021) -- same source, same re-verification requirement.
_PLUS_MIN_YEAR = 21


class ObservedEdition(str, Enum):
    """Closed, fail-safe representation of an *observed* appliance's
    edition -- distinct from `guidance.models.Edition`, which represents
    *document applicability* and includes a `BOTH` member meaningful only
    for documentation, never for a real appliance's actual edition
    (ADR-018 Finding 1, BLOCKING in the original design). A real
    appliance is always exactly one edition or unknown, never both;
    nothing in this type can express `BOTH` for observed state.
    """

    KNOWN_CE = "known_ce"
    KNOWN_PLUS = "known_plus"
    UNKNOWN = "unknown"


def infer_edition_from_version_base(base: str) -> ObservedEdition:
    """Infer pfSense edition from `SystemVersion.base`'s version-string
    shape, per Netgate's own documented CE (``<major>.<minor>.<patch>``)
    vs. Plus (``<year>.<month>.<patch>``) numbering schemes -- ADR-018
    S1. Never a network call: operates purely on a string the caller
    already has from an existing `pfsense_get_system_version` call.

    Only the leading, dot-separated component is inspected -- this is
    deliberate, not an oversight: it means a prerelease/beta/RC suffix
    on a *later* component (e.g. a hypothetical ``"26.03-BETA"``, where
    the suffix trails the second component) does not affect
    classification, since Netgate's documented schemes distinguish
    edition purely by the leading major/year token's numeric range. No
    prerelease/beta/RC form has been observed in `SystemVersion.base`
    specifically (the field is documented as patch-stripped for both
    editions) -- this function does not invent handling for a form with
    no verified evidence; it relies on the same range check to fail
    safe for any input shape, prerelease or not.

    Returns `ObservedEdition.UNKNOWN` on any value outside both known
    ranges, on a non-numeric leading component, or on an empty string --
    never guesses. This is the single function any future consumer
    calls for inference; it must not be reimplemented elsewhere
    (ADR-018's "no duplicated parallel source of truth" requirement,
    the same discipline already applied to
    `WriteEndpoints.active_entries()` in v0.3.1). See
    `resolve_appliance_identity()` below for the one canonical assembly
    point that wraps this function.
    """
    first_component = base.split(".", 1)[0]
    if not first_component.isdigit():
        return ObservedEdition.UNKNOWN
    major = int(first_component)
    if 1 <= major <= _CE_MAX_MAJOR:
        return ObservedEdition.KNOWN_CE
    if _PLUS_MIN_YEAR <= major <= 99:
        return ObservedEdition.KNOWN_PLUS
    return ObservedEdition.UNKNOWN


class ApplianceIdentity(BaseModel):
    """The one shape any future consumer of observed appliance identity
    reads. Deliberately minimal: no hostname, serial number, MAC
    address, public IP, credential, installation identifier, or other
    system metadata -- only what version-aware guidance and future
    compatibility decisions actually need (ADR-018's own accepted
    shape; no field added here without that consumer already named in
    ADR-018/VERSION_AWARE_GUIDANCE.md).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    observed_edition: ObservedEdition
    observed_version: str | None
    identity_source: str
    resolved_at: str


#: The fixed literal `ApplianceIdentity.identity_source` always carries --
#: documentation-as-data, the same value on every call, never a
#: per-appliance identifier.
_IDENTITY_SOURCE = "SystemVersion.base (pfsense_get_system_version)"


def resolve_appliance_identity(client: PfSenseClient) -> ApplianceIdentity:
    """The one canonical assembly point (ADR-018 Finding 10). No other
    module may reimplement this assembly independently -- a code-review
    rule as firm as `capability_adapter_contract.md`'s I2 ("no adapter
    constructs its own client").

    Uses the existing, already-registered `pfsense_get_system_version`
    READ path (`PfSenseClient.get_system_version()`) -- the same
    authoritative source this project's production READ surface already
    exposes. Adds no new endpoint, no new capability, no new network
    behavior.

    Not called from anywhere in production yet: no consumer is wired
    (ADR-018's own "Do not wire this into every READ tool yet" /
    "Do not wire those consumers now" instruction, unchanged by this
    function's existence). `pfsense_mcp_info` in particular does not
    call this -- its zero-pfSense-call invariant is unaffected; see
    ADR-018's "Self-challenge: pfsense_mcp_info".
    """
    version = client.get_system_version()
    edition = infer_edition_from_version_base(version.base) if version.base else ObservedEdition.UNKNOWN
    return ApplianceIdentity(
        observed_edition=edition,
        observed_version=version.base,
        identity_source=_IDENTITY_SOURCE,
        resolved_at=datetime.now(timezone.utc).isoformat(),
    )
