#!/usr/bin/env python3
"""tools_write_check.py — confirms pfsense_mcp.tools.write is never
imported anywhere. It is a deliberately empty, reserved package
(see src/pfsense_mcp/tools/write/__init__.py) that must stay inert
until a separate, explicitly authorized Engineer-mode phase begins.

Read-only. Exits 0 (no import found) or 1 (a forbidden import found).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_SCAN_DIRS = ("src", "scripts", "tests")

_FORBIDDEN_PATTERNS = (
    re.compile(r"^\s*from\s+.*\btools\.write\b"),
    re.compile(r"^\s*from\s+\.write\b"),
    re.compile(r"^\s*import\s+.*\btools\.write\b"),
)

# The reserved package's own __init__.py legitimately mentions "write"
# in its docstring explaining why it must stay empty; that is not an
# import and must not be flagged.
_SELF = Path("src/pfsense_mcp/tools/write/__init__.py")


def find_forbidden_imports(root: Path = ROOT) -> list[str]:
    findings = []
    for dirname in _SCAN_DIRS:
        scan_dir = root / dirname
        if not scan_dir.is_dir():
            continue
        for path in sorted(scan_dir.rglob("*.py")):
            rel = path.relative_to(root)
            if rel == _SELF:
                continue
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if any(pattern.search(line) for pattern in _FORBIDDEN_PATTERNS):
                    findings.append(f"{rel}:{lineno}: {line.strip()}")
    return findings


def main() -> int:
    findings = find_forbidden_imports()
    if findings:
        print("tools_write_check: FAILED", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("tools_write_check: OK (pfsense_mcp.tools.write is never imported)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
