#!/usr/bin/env python3
"""get_only_check.py — static confirmation that RestApiClient is the
only place in src/pfsense_mcp that ever calls a Transport's request()
method directly. GET-only is enforced dynamically inside
RestApiClient._request() (covered by test_post_is_rejected_as_unsupported,
checked via validate_junit.py); this script guards the architectural
invariant that no other module can bypass that gate by calling a
Transport object's .request(...) itself.

Deliberately matches only receivers whose name contains "transport"
(e.g. self._transport.request(...)) — NOT every ".request(" call in
the tree. HttpTransport itself legitimately calls the underlying
httpx.Client's .request(...) (e.g. self._client.request(...)); that is
a different, lower layer and not a violation of this invariant.

Read-only. Exits 0 (only rest_api_client.py calls transport.request) or 1.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "pfsense_mcp"
_ALLOWED_CALLER = "rest_api_client.py"
_REQUEST_CALL_RE = re.compile(r"\b\w*transport\w*\.request\(", re.IGNORECASE)


def find_request_call_sites(src_dir: Path = SRC_DIR) -> dict[str, int]:
    """Returns {relative_file_path: number_of_.request(_calls}."""
    hits: dict[str, int] = {}
    for path in sorted(src_dir.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        count = len(_REQUEST_CALL_RE.findall(text))
        if count:
            hits[str(path.relative_to(src_dir))] = count
    return hits


def main() -> int:
    hits = find_request_call_sites()
    unexpected = {f: n for f, n in hits.items() if not f.endswith(_ALLOWED_CALLER)}

    if unexpected:
        print("get_only_check: FAILED", file=sys.stderr)
        print(f"  .request(...) called outside {_ALLOWED_CALLER}:", file=sys.stderr)
        for f, n in unexpected.items():
            print(f"    {f}: {n} call(s)", file=sys.stderr)
        return 1

    if _ALLOWED_CALLER not in hits:
        print("get_only_check: FAILED", file=sys.stderr)
        print(f"  expected {_ALLOWED_CALLER} to call .request(...) at least once; found none", file=sys.stderr)
        return 1

    print(f"get_only_check: OK (.request(...) is only called from {_ALLOWED_CALLER})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
