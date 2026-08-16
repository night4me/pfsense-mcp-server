#!/usr/bin/env python3
"""write_allow_list_check.py — confirms WriteEndpoints (the mutation
allow-list) contains exactly the entries W3 has explicitly authorized,
and nothing else. WriteApiClient.execute() refuses any MutationPlan
whose endpoint_symbol is not a WriteEndpoints attribute; this script
proves the allow-list matches the exact accepted scope, so an
accidental or unreviewed second entry can never silently expand what
any correctly-gated caller could ever reach.

Through W3 Slice 3, this asserted the allow-list was empty (no WRITE
surface existed at all yet). W3 Slice 4 added the single accepted
first-WRITE entry (`FIREWALL_ALIAS_DESCRIPTION`, the description-only
alias PATCH) — this script now asserts *exactly* that one entry, no
more and no fewer, mirroring how `write_capability_check.py` was
already re-expressed in W3 Slice 1 for the same reason (a fixed
"expected" set proven exactly, not a permanently-empty invariant).

Read-only, no network access — imports the local package only. Exits 0
(exactly the expected entries) or 1.
"""

from __future__ import annotations

import sys

from pfsense_mcp.write_endpoints import WriteEndpoints

#: The complete, exact set of endpoint names the durable owner roadmap
#: decision (single first-WRITE product surface only, through v0.4.2)
#: currently authorizes. Any entry not in this set — or any expected
#: entry missing from WriteEndpoints — fails this check.
EXPECTED_ACTIVE_ENTRIES = frozenset({"FIREWALL_ALIAS_DESCRIPTION"})


def find_write_endpoint_entries() -> list[str]:
    return WriteEndpoints.active_entries()


def find_allow_list_violations() -> list[str]:
    actual = frozenset(find_write_endpoint_entries())
    unexpected = sorted(actual - EXPECTED_ACTIVE_ENTRIES)
    missing = sorted(EXPECTED_ACTIVE_ENTRIES - actual)
    findings = [f"unexpected WriteEndpoints entry: {name}" for name in unexpected]
    findings += [f"expected WriteEndpoints entry is missing: {name}" for name in missing]
    return findings


def main() -> int:
    findings = find_allow_list_violations()
    if findings:
        print("write_allow_list_check: FAILED", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1

    print(f"write_allow_list_check: OK (WriteEndpoints has exactly {sorted(EXPECTED_ACTIVE_ENTRIES)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
