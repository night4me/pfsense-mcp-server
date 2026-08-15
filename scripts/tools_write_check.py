#!/usr/bin/env python3
"""tools_write_check.py — confirms pfsense_mcp.tools.write is imported
from exactly one *production* location: src/pfsense_mcp/tools/registry.py
(W3 Slice 4's own accepted wiring of the single first-WRITE MCP tool,
set_firewall_alias_description_v1). Any OTHER import of
pfsense_mcp.tools.write — anywhere else in src/ or scripts/ — is an
unreviewed, unauthorized second production path into the write-tools
package and fails this check; the expected import being absent from
registry.py itself also fails this check.

tests/ is deliberately not scanned: a test file legitimately importing
pfsense_mcp.tools.write directly to test it (as
tests/test_set_firewall_alias_description.py does) is expected and
correct, not a production reachability concern -- this check's job is
proving production code has exactly one path in, never that nothing
outside registry.py may ever reference the package for any purpose.

Through W3 Slice 3, this asserted pfsense_mcp.tools.write was never
imported anywhere (the reserved package stayed empty). W3 Slice 4 added
the single accepted import site — this mirrors the same "was always
zero/absent, now exactly the accepted scope" re-expression already
applied to write_allow_list_check.py and (in W3 Slice 1)
write_capability_check.py.

Read-only. Exits 0 (imported only in the expected location) or 1.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_SCAN_DIRS = ("src", "scripts")

_FORBIDDEN_PATTERNS = (
    re.compile(r"^\s*from\s+.*\btools\.write\b"),
    re.compile(r"^\s*from\s+\.write\b"),
    re.compile(r"^\s*import\s+.*\btools\.write\b"),
)

# The reserved package's own __init__.py legitimately mentions "write"
# in its docstring explaining why it must stay minimal; that is not an
# import and must not be flagged.
_SELF = Path("src/pfsense_mcp/tools/write/__init__.py")

#: W3 Slice 4's own, sole authorized import site.
_EXPECTED_IMPORTER = Path("src/pfsense_mcp/tools/registry.py")


def find_forbidden_imports(root: Path = ROOT) -> list[str]:
    """Every import of pfsense_mcp.tools.write found *outside* the one
    expected, authorized location."""

    findings = []
    for dirname in _SCAN_DIRS:
        scan_dir = root / dirname
        if not scan_dir.is_dir():
            continue
        for path in sorted(scan_dir.rglob("*.py")):
            rel = path.relative_to(root)
            if rel in (_SELF, _EXPECTED_IMPORTER):
                continue
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if any(pattern.search(line) for pattern in _FORBIDDEN_PATTERNS):
                    findings.append(f"{rel}:{lineno}: {line.strip()}")
    return findings


def find_expected_import_present(root: Path = ROOT) -> bool:
    """True only if the one authorized import site actually imports
    pfsense_mcp.tools.write -- proves the expected wiring exists, not
    merely that nothing forbidden was found."""

    path = root / _EXPECTED_IMPORTER
    if not path.is_file():
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    return any(pattern.search(line) for line in lines for pattern in _FORBIDDEN_PATTERNS)


def main() -> int:
    findings = find_forbidden_imports()
    if findings:
        print("tools_write_check: FAILED", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    if not find_expected_import_present():
        print("tools_write_check: FAILED", file=sys.stderr)
        print(f"  expected pfsense_mcp.tools.write import in {_EXPECTED_IMPORTER} was not found", file=sys.stderr)
        return 1
    print(f"tools_write_check: OK (pfsense_mcp.tools.write is imported only by {_EXPECTED_IMPORTER})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
