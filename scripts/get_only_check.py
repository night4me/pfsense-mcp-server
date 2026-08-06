#!/usr/bin/env python3
"""get_only_check.py — static confirmation that only two named, audited
files in src/pfsense_mcp ever call a Transport's request() method
directly: rest_api_client.py (GET-only, enforced dynamically inside
RestApiClient._request(), covered by test_post_is_rejected_as_unsupported
and checked via validate_junit.py) and write_api_client.py (the write
chokepoint — gated by the WriteEndpoints allow-list and a Recovery
Contract, see recovery.py/write_endpoints.py; WriteEndpoints ships empty
in this build, so every call through it currently refuses before any
network call). This script guards the architectural invariant that no
*other* module can bypass either gate by calling a Transport object's
.request(...) itself.

Deliberately matches only receivers whose name contains "transport"
(e.g. self._transport.request(...)) — NOT every ".request(" call in
the tree. HttpTransport itself legitimately calls the underlying
httpx.Client's .request(...) (e.g. self._client.request(...)); that is
a different, lower layer and not a violation of this invariant.

Read-only. Exits 0 (only the two named callers appear, each at least
once) or 1.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "pfsense_mcp"
_ALLOWED_CALLERS: tuple[str, ...] = ("rest_api_client.py", "write_api_client.py")
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
    unexpected = {f: n for f, n in hits.items() if not f.endswith(_ALLOWED_CALLERS)}

    if unexpected:
        print("get_only_check: FAILED", file=sys.stderr)
        print(f"  .request(...) called outside {_ALLOWED_CALLERS}:", file=sys.stderr)
        for f, n in unexpected.items():
            print(f"    {f}: {n} call(s)", file=sys.stderr)
        return 1

    missing = [caller for caller in _ALLOWED_CALLERS if caller not in hits]
    if missing:
        print("get_only_check: FAILED", file=sys.stderr)
        for caller in missing:
            print(f"  expected {caller} to call .request(...) at least once; found none", file=sys.stderr)
        return 1

    print(f"get_only_check: OK (.request(...) is only called from {', '.join(_ALLOWED_CALLERS)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
