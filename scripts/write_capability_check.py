#!/usr/bin/env python3
"""write_capability_check.py — distinguishes three separate WRITE-capability
concepts (ADR-028 W3-D2, owner-accepted 2026-08-15) and asserts the
default-off invariant precisely for each:

  - implemented: SUPPORTED_CAPABILITIES_THIS_BUILD ("this build contains
    code for it" — never itself a grant; reported, not a failure);
  - granted: which named Profile's capability set contains it;
  - default-safe: the default profile (AuditorProfile, name "auditor" —
    the same literal default `PFSENSE_PROFILE` resolves to when unset) and
    EngineerProfile must both grant zero *_WRITE capabilities, always;
  - scope-contained: WriteProtectedProfile — the one profile permitted to
    grant a *_WRITE capability — must grant nothing beyond exactly
    {ALIAS_WRITE}; any other *_WRITE capability appearing there is
    unreviewed scope creep, not this build's accepted first-WRITE surface.

This is an independent, redundant guard alongside write_allow_list_check.py:
even if this build's WriteEndpoints allow-list ever accidentally gained an
entry, no default-profile caller could reach it without also tripping this
check.

Read-only, no network access — imports the local package only. Exits 0
(default-safe and scope-contained) or 1.
"""

from __future__ import annotations

import sys

from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD, Capability
from pfsense_mcp.profiles import AuditorProfile, EngineerProfile, WriteProtectedProfile

_WRITE_CAPABILITIES = tuple(member for member in Capability if member.name.endswith("_WRITE"))
_ACCEPTED_WRITE_PROTECTED_GRANT = frozenset({Capability.ALIAS_WRITE})


def find_default_safety_violations() -> list[str]:
    """Every failure here means the default-off invariant itself is
    broken: a *_WRITE capability reachable without any explicit posture
    choice. This is the check's authoritative safety proof."""

    findings: list[str] = []
    for member in _WRITE_CAPABILITIES:
        if member in AuditorProfile.capabilities:
            findings.append(f"{member.name} is in AuditorProfile.capabilities (the default profile)")
        if member in EngineerProfile.capabilities:
            findings.append(f"{member.name} is in EngineerProfile.capabilities")
    return findings


def find_scope_creep() -> list[str]:
    """WriteProtectedProfile may grant exactly ALIAS_WRITE and nothing
    else. Any other *_WRITE capability appearing there was never reviewed
    or accepted as part of the first-WRITE product surface."""

    unexpected = WriteProtectedProfile.capabilities & frozenset(_WRITE_CAPABILITIES) - _ACCEPTED_WRITE_PROTECTED_GRANT
    return [
        f"{member.name} is in WriteProtectedProfile.capabilities but is not part of the accepted grant "
        f"{sorted(c.name for c in _ACCEPTED_WRITE_PROTECTED_GRANT)}"
        for member in sorted(unexpected, key=lambda member: member.name)
    ]


def implemented_write_capabilities() -> list[str]:
    """Informational only — SUPPORTED_CAPABILITIES_THIS_BUILD means
    "implemented by this build", never a grant. Never a failure by
    itself."""

    return [member.name for member in _WRITE_CAPABILITIES if member in SUPPORTED_CAPABILITIES_THIS_BUILD]


def main() -> int:
    default_safety_findings = find_default_safety_violations()
    scope_creep_findings = find_scope_creep()
    findings = default_safety_findings + scope_creep_findings

    if findings:
        print("write_capability_check: FAILED", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1

    implemented = implemented_write_capabilities()
    print(
        f"write_capability_check: OK (0 of {len(_WRITE_CAPABILITIES)} *_WRITE capabilities are default-reachable; "
        f"{len(implemented)} implemented: {implemented or 'none'}; "
        f"WriteProtectedProfile grants only {sorted(c.name for c in _ACCEPTED_WRITE_PROTECTED_GRANT)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
