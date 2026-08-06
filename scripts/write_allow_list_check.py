#!/usr/bin/env python3
"""write_allow_list_check.py — confirms WriteEndpoints (the mutation
allow-list) has zero entries in this build. WriteApiClient.execute()
refuses any MutationPlan whose endpoint_symbol is not a WriteEndpoints
attribute; this script proves that allow-list is still empty, so every
possible mutation attempt refuses regardless of any other gate's
correctness.

Read-only, no network access — imports the local package only. Exits 0
(zero entries) or 1.
"""

from __future__ import annotations

import sys

from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints


def find_write_endpoint_entries() -> list[str]:
    return [name for name, value in vars(WriteEndpoints).items() if isinstance(value, WriteEndpointInfo)]


def main() -> int:
    entries = find_write_endpoint_entries()
    if entries:
        print("write_allow_list_check: FAILED", file=sys.stderr)
        print(f"  WriteEndpoints has {len(entries)} entrie(s), expected 0 in this build: {entries}", file=sys.stderr)
        return 1

    print("write_allow_list_check: OK (WriteEndpoints has zero entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
