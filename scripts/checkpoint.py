#!/usr/bin/env python3
"""checkpoint.py — lightweight project-state checkpoint utility.

Generates CHECKPOINT.md and .checkpoint/state.json summarizing current
git state, test/verification status, MCP tool count, and READ backlog
progress — so a new Claude session can resume work by reading those
two files instead of rereading the full conversation history.

Pure Python, no network access, no LLM API calls, no new dependencies.
Never modifies the repository except to write CHECKPOINT.md and
.checkpoint/state.json. This is a lightweight checkpoint utility, not
a session manager — it does not interpret git or test failures beyond
reporting them.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKPOINT_MD = REPO_ROOT / "CHECKPOINT.md"
CHECKPOINT_DIR = REPO_ROOT / ".checkpoint"
CHECKPOINT_JSON = CHECKPOINT_DIR / "state.json"
BACKLOG_PATH = REPO_ROOT / "docs" / "READ_BACKLOG.md"
REGISTRY_PATH = REPO_ROOT / "src" / "pfsense_mcp" / "tools" / "registry.py"
CAPABILITIES_PATH = REPO_ROOT / "src" / "pfsense_mcp" / "capabilities.py"

_PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _run(cmd: list[str], timeout: int) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout + proc.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def get_branch() -> str:
    rc, out = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], timeout=10)
    return out.strip() if rc == 0 and out.strip() else "unknown"


def get_latest_commit() -> dict[str, str | None]:
    rc, out = _run(["git", "log", "-1", "--format=%H%x1f%s"], timeout=10)
    if rc != 0 or not out.strip():
        return {"hash": None, "message": None}
    commit_hash, _, message = out.strip().partition("\x1f")
    return {"hash": commit_hash, "message": message}


def get_git_status() -> dict[str, Any]:
    rc, out = _run(["git", "status", "--porcelain"], timeout=10)
    modified: list[str] = []
    staged: list[str] = []
    untracked: list[str] = []
    if rc == 0:
        for line in out.splitlines():
            if not line:
                continue
            index_status, worktree_status, path = line[0], line[1], line[3:]
            if index_status == "?" and worktree_status == "?":
                untracked.append(path)
                continue
            if index_status not in (" ", "?"):
                staged.append(path)
            if worktree_status not in (" ", "?"):
                modified.append(path)
    clean = not (modified or staged or untracked)
    return {"clean": clean, "modified": modified, "staged": staged, "untracked": untracked}


# Mirrors Makefile's own XDIST_SERIAL_ONLY exactly (see that file's own
# comment for why each test is here) -- duplicated, not imported, the
# same deliberate choice scripts/verify_min_dependencies.py makes for
# the same reason: if a new xdist-incompatible test is ever added to
# the Makefile's own list, add it here too.
_XDIST_SERIAL_ONLY = (
    "tests/tier1/test_crypto.py::test_random_ciphertext_never_raises_anything_but_artifact_decryption_error",
    "tests/tier1/test_acceptance_isolation.py::test_importing_mcp_entrypoints_never_loads_acceptance_module",
)


def _parse_pytest_summary(out: str) -> dict[str, int] | None:
    for line in reversed(out.splitlines()):
        if " in " in line and re.search(r"\d+ (passed|failed|error)", line):
            result: dict[str, int] = {}
            for key in ("passed", "skipped", "failed"):
                m = re.search(rf"(\d+) {key}", line)
                if m:
                    result[key] = int(m.group(1))
            result.setdefault("passed", 0)
            result.setdefault("skipped", 0)
            result.setdefault("failed", 0)
            return result
    return None


def get_pytest_totals() -> dict[str, int] | None:
    """Runs the exact same xdist-parallel + serial-tail split
    `make quick`/`make validate` already use (`Makefile`'s own
    `XDIST_ARGS`/`XDIST_SERIAL_ONLY`), rather than a single serial
    `pytest -q` -- the parallel pass alone roughly halves wall-clock
    time, which is what keeps this comfortably inside its own timeout
    under load, rather than the timeout number itself needing to grow."""

    deselect_args = [arg for test_id in _XDIST_SERIAL_ONLY for arg in ("--deselect", test_id)]
    rc, out = _run([sys.executable, "-m", "pytest", "-q", "-n", "6", "--dist=loadscope", *deselect_args], timeout=240)
    parallel = _parse_pytest_summary(out)
    if parallel is None:
        return None if rc == 0 else {"passed": 0, "skipped": 0, "failed": 0}

    rc_serial, out_serial = _run([sys.executable, "-m", "pytest", "-q", *_XDIST_SERIAL_ONLY], timeout=30)
    serial = _parse_pytest_summary(out_serial)
    if serial is not None:
        for key in ("passed", "skipped", "failed"):
            parallel[key] = parallel.get(key, 0) + serial.get(key, 0)
    elif rc_serial != 0:
        parallel["failed"] = parallel.get("failed", 0) + 1

    return parallel


def get_make_status(target: str) -> str:
    rc, _ = _run(["make", target], timeout=300)
    return "passed" if rc == 0 else "failed"


def get_mcp_tool_count() -> int | None:
    if not REGISTRY_PATH.is_file():
        return None
    text = REGISTRY_PATH.read_text(encoding="utf-8")
    return len(re.findall(r"self\._mcp\.tool\(\)\(", text))


def get_supported_capability_count() -> int | None:
    if not CAPABILITIES_PATH.is_file():
        return None
    text = CAPABILITIES_PATH.read_text(encoding="utf-8")
    match = re.search(r"SUPPORTED_CAPABILITIES_THIS_BUILD.*?frozenset\(\s*\{(.*?)\}\s*\)", text, re.DOTALL)
    if not match:
        return None
    return len(re.findall(r"Capability\.\w+", match.group(1)))


_TABLE_ROW_RE = re.compile(r"^\|(.+)\|\s*$")


def parse_backlog() -> dict[str, Any]:
    """Parses the '## Capabilities' table in docs/READ_BACKLOG.md.
    Returns capability rows bucketed by their literal Status column
    value (Done / Planned / anything else), plus a staleness note
    when the doc's "Done" count doesn't match the real, currently
    supported capability count in capabilities.py — the doc is a
    roadmap maintained separately from the code and can fall behind."""
    completed: list[str] = []
    remaining: list[dict[str, str]] = []
    blocked: list[str] = []
    notes: list[str] = []

    if not BACKLOG_PATH.is_file():
        notes.append("docs/READ_BACKLOG.md not found — backlog progress unavailable.")
        return {
            "completed": completed,
            "remaining": remaining,
            "blocked": blocked,
            "next_capability": None,
            "notes": notes,
        }

    lines = BACKLOG_PATH.read_text(encoding="utf-8").splitlines()
    in_table = False
    for line in lines:
        if not in_table:
            if line.strip().startswith("|") and "Capability" in line and "Status" in line:
                in_table = True
            continue
        if not _TABLE_ROW_RE.match(line):
            break
        # A cell may contain an escaped pipe ("\|") as a literal
        # character (this backlog doc uses it, e.g. inside endpoint
        # patterns like "priorit(y\|ies)") — split only on real
        # column-separator pipes, not escaped ones.
        stripped = line.strip()
        if stripped.startswith("|"):
            stripped = stripped[1:]
        if stripped.endswith("|"):
            stripped = stripped[:-1]
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", stripped)]
        if len(cells) < 7:
            continue
        if set(cells[0]) <= set("-: "):
            continue  # markdown separator row
        name, priority, status = cells[0], cells[5], cells[6]
        if status == "Done":
            completed.append(name)
        elif status in ("Blocked", "Deferred"):
            blocked.append(name)
        else:
            remaining.append({"name": name, "priority": priority})

    remaining.sort(key=lambda r: _PRIORITY_ORDER.get(r["priority"], 99))
    next_capability = remaining[0]["name"] if remaining else None

    real_count = get_supported_capability_count()
    if real_count is not None and real_count != len(completed):
        notes.append(
            f"docs/READ_BACKLOG.md Status column appears stale: {real_count} capabilities are "
            f"actually supported in capabilities.py, but only {len(completed)} rows are marked "
            "Done in the backlog doc. Capability names may also differ between the doc and the "
            "real Capability enum (e.g. historical naming changes) — treat 'next_capability' as "
            "a suggestion to verify, not a guarantee."
        )

    return {
        "completed": completed,
        "remaining": remaining,
        "blocked": blocked,
        "next_capability": next_capability,
        "notes": notes,
    }


def build_state() -> dict[str, Any]:
    git_status = get_git_status()
    backlog = parse_backlog()
    notes = list(backlog["notes"])

    pytest_totals = get_pytest_totals()
    make_quick = get_make_status("quick")
    make_validate = get_make_status("validate")
    tool_count = get_mcp_tool_count()

    if pytest_totals is None:
        notes.append("pytest could not be run or its summary line could not be parsed.")
    if tool_count is None:
        notes.append("MCP tool count could not be determined from tools/registry.py.")

    return {
        "schema_version": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "branch": get_branch(),
        "latest_commit": get_latest_commit(),
        "git": git_status,
        "tests": {
            "pytest": pytest_totals,
            "make_quick": make_quick,
            "make_validate": make_validate,
        },
        "backlog": {
            "completed": backlog["completed"],
            "remaining": backlog["remaining"],
            "blocked": backlog["blocked"],
            "next_capability": backlog["next_capability"],
        },
        "mcp": {"tool_count": tool_count},
        "notes": notes,
    }


_RESUME_PROMPT = """Continue from the current repository state.

Read CHECKPOINT.md.

Resume with the highest-priority remaining READ capability from READ_BACKLOG.md.

Do not rebuild tooling unless a concrete capability-blocking defect is encountered.

Continue following the throughput-first policy."""


def render_checkpoint_md(state: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Project Checkpoint")
    lines.append("")
    lines.append(f"Generated: {state['timestamp_utc']}")
    lines.append("")

    lines.append("## Project status")
    lines.append("")
    lines.append(f"- Current branch: `{state['branch']}`")
    commit = state["latest_commit"]
    lines.append(f"- Latest commit hash: `{commit['hash']}`")
    lines.append(f"- Latest commit message: {commit['message']}")
    git = state["git"]
    lines.append(f"- Git status: {'clean' if git['clean'] else 'dirty'}")
    pytest_totals = state["tests"]["pytest"]
    if pytest_totals is not None:
        extra = f", {pytest_totals['failed']} failed" if pytest_totals.get("failed") else ""
        lines.append(f"- pytest totals: {pytest_totals['passed']} passed, {pytest_totals['skipped']} skipped{extra}")
    else:
        lines.append("- pytest totals: unavailable")
    lines.append(f"- make quick: {state['tests']['make_quick']}")
    lines.append(f"- make validate: {state['tests']['make_validate']}")
    lines.append("")

    backlog = state["backlog"]
    lines.append("## Backlog progress")
    lines.append("")
    lines.append(f"- Completed capabilities: {len(backlog['completed'])}")
    lines.append(f"- Remaining capabilities: {len(backlog['remaining'])}")
    lines.append(f"- Blocked capabilities: {len(backlog['blocked'])}")
    lines.append("")
    lines.append("Remaining capabilities (priority order):")
    lines.append("")
    if backlog["remaining"]:
        for row in backlog["remaining"]:
            lines.append(f"- {row['name']} ({row['priority']})")
    else:
        lines.append("- (none)")
    if backlog["blocked"]:
        lines.append("")
        lines.append("Blocked capabilities:")
        lines.append("")
        for name in backlog["blocked"]:
            lines.append(f"- {name}")
    lines.append("")

    lines.append("## Current work")
    lines.append("")
    if git["clean"]:
        lines.append("Working tree clean.")
    else:
        if git["modified"]:
            lines.append("Modified files:")
            for path in git["modified"]:
                lines.append(f"- {path}")
        if git["staged"]:
            lines.append("Staged files:")
            for path in git["staged"]:
                lines.append(f"- {path}")
        if git["untracked"]:
            lines.append("Untracked files:")
            for path in git["untracked"]:
                lines.append(f"- {path}")
    lines.append("")

    lines.append("## Resume prompt")
    lines.append("")
    lines.append("```")
    lines.append(_RESUME_PROMPT)
    lines.append("```")
    lines.append("")

    lines.append("## Engineering handoff")
    lines.append("")
    lines.append(f"- Latest completed capability (by commit): {commit['message']}")
    tool_count = state["mcp"]["tool_count"]
    lines.append(f"- Latest MCP tool count: {tool_count if tool_count is not None else 'unknown'}")
    lines.append(
        f"- Known blocked endpoints/capabilities: {', '.join(backlog['blocked']) if backlog['blocked'] else 'none'}"
    )
    lines.append(f"- Next recommended capability: {backlog['next_capability'] or 'none — backlog exhausted'}")
    if state["notes"]:
        lines.append("- Outstanding issues requiring attention:")
        for note in state["notes"]:
            lines.append(f"  - {note}")
    else:
        lines.append("- Outstanding issues requiring attention: none")
    lines.append(
        f"- Current verification status: pytest={'ok' if pytest_totals is not None else 'unknown'}, "
        f"make quick={state['tests']['make_quick']}, make validate={state['tests']['make_validate']}"
    )
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    CHECKPOINT_DIR.mkdir(exist_ok=True)
    state = build_state()
    CHECKPOINT_MD.write_text(render_checkpoint_md(state), encoding="utf-8")
    CHECKPOINT_JSON.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"checkpoint: wrote {CHECKPOINT_MD.relative_to(REPO_ROOT)} and {CHECKPOINT_JSON.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
