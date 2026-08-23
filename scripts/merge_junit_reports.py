#!/usr/bin/env python3
"""merge_junit_reports.py — combines two `--junit-xml` reports into one.

`make test` runs pytest twice: a parallel (`-n 6`) pass over the bulk of the
suite, and a serial pass over the small handful of tests that cannot safely
collect under xdist (see AGENTS.md's "Test parallelism" note). Both passes
must land in a single report so `scripts/validate_junit.py`'s per-stage
checks — which only read one file — still see every test case.

Read-only w.r.t. the inputs; writes only the `--output` path. Exits 0 or 1.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _testsuites(path: Path) -> list[ET.Element]:
    root = ET.parse(path).getroot()
    if root.tag == "testsuites":
        return list(root)
    # A lone <testsuite> root (pytest emits this when there is exactly one
    # suite) is itself the element to merge in.
    return [root]


def merge(inputs: list[Path], output: Path) -> None:
    combined = ET.Element("testsuites")
    for path in inputs:
        combined.extend(_testsuites(path))
    ET.ElementTree(combined).write(output, encoding="utf-8", xml_declaration=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    missing = [p for p in args.inputs if not p.is_file()]
    if missing:
        for p in missing:
            print(f"merge_junit_reports: missing input file: {p}", file=sys.stderr)
        return 1

    merge(args.inputs, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
