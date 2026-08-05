#!/usr/bin/env python3
"""git_report.py — read-only, informational report of the current
working-tree state. Never gates pass/fail on its own (an untracked
file mid-development is not inherently wrong) and never modifies or
stages anything.

Only ever invokes: `git status --porcelain` and `git diff --stat`.
No other git subcommand appears in this file.
"""

from __future__ import annotations

import subprocess


def _run(args: list[str]) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def main() -> int:
    status = _run(["git", "status", "--porcelain"])
    diff_stat = _run(["git", "diff", "--stat"])

    print("git_report:")
    if status.strip():
        for line in status.splitlines():
            print(f"  {line}")
    else:
        print("  (working tree clean)")

    if diff_stat.strip():
        print()
        print(diff_stat.rstrip())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
