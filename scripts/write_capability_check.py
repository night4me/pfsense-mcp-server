#!/usr/bin/env python3
"""write_capability_check.py — confirms no *_WRITE Capability is active
anywhere: not in SUPPORTED_CAPABILITIES_THIS_BUILD, and not in either
Profile's capability set (AuditorProfile / EngineerProfile). This is an
independent, redundant guard alongside write_allow_list_check.py: even
if this build's WriteEndpoints allow-list ever accidentally gained an
entry, no profile could reach it without also tripping this check.

Read-only, no network access — imports the local package only. Exits 0
(no *_WRITE capability active) or 1.
"""

from __future__ import annotations

import sys

from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD, Capability
from pfsense_mcp.profiles import AuditorProfile, EngineerProfile

_WRITE_CAPABILITIES = tuple(member for member in Capability if member.name.endswith("_WRITE"))


def find_active_write_capabilities() -> list[str]:
    findings: list[str] = []
    for member in _WRITE_CAPABILITIES:
        if member in SUPPORTED_CAPABILITIES_THIS_BUILD:
            findings.append(f"{member.name} is in SUPPORTED_CAPABILITIES_THIS_BUILD")
        if member in AuditorProfile.capabilities:
            findings.append(f"{member.name} is in AuditorProfile.capabilities")
        if member in EngineerProfile.capabilities:
            findings.append(f"{member.name} is in EngineerProfile.capabilities")
    return findings


def main() -> int:
    findings = find_active_write_capabilities()
    if findings:
        print("write_capability_check: FAILED", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1

    print(f"write_capability_check: OK (0 of {len(_WRITE_CAPABILITIES)} *_WRITE capabilities are active)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
