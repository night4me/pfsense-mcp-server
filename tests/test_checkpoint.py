"""Unit tests for scripts/checkpoint.py.

Uses real temporary git repositories where practical (git status/log
parsing) and synthetic in-memory text for pure parsing functions
(backlog table, registry tool count, capability count)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import checkpoint as cp
import pytest


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _git("config", "user.email", "test@example.invalid", cwd=repo)
    _git("config", "user.name", "Test", cwd=repo)
    (repo / "README.md").write_text("hello\n")
    _git("add", "README.md", cwd=repo)
    _git("commit", "-q", "-m", "Initial commit", cwd=repo)
    return repo


def _patch_paths(monkeypatch: pytest.MonkeyPatch, repo: Path) -> None:
    monkeypatch.setattr(cp, "REPO_ROOT", repo)
    monkeypatch.setattr(cp, "CHECKPOINT_MD", repo / "CHECKPOINT.md")
    monkeypatch.setattr(cp, "CHECKPOINT_DIR", repo / ".checkpoint")
    monkeypatch.setattr(cp, "CHECKPOINT_JSON", repo / ".checkpoint" / "state.json")
    monkeypatch.setattr(cp, "BACKLOG_PATH", repo / "docs" / "READ_BACKLOG.md")
    monkeypatch.setattr(cp, "REGISTRY_PATH", repo / "src" / "pfsense_mcp" / "tools" / "registry.py")
    monkeypatch.setattr(cp, "CAPABILITIES_PATH", repo / "src" / "pfsense_mcp" / "capabilities.py")


# --- git helpers, against a real temporary git repository ----------------


def test_get_branch(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    _patch_paths(monkeypatch, repo)
    assert cp.get_branch() in ("main", "master")


def test_get_latest_commit(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    _patch_paths(monkeypatch, repo)
    commit = cp.get_latest_commit()
    assert commit["message"] == "Initial commit"
    assert commit["hash"] and len(commit["hash"]) == 40


def test_get_latest_commit_no_commits(tmp_path, monkeypatch):
    repo = tmp_path / "empty_repo"
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _patch_paths(monkeypatch, repo)
    commit = cp.get_latest_commit()
    assert commit == {"hash": None, "message": None}


def test_get_git_status_clean(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    _patch_paths(monkeypatch, repo)
    status = cp.get_git_status()
    assert status == {"clean": True, "modified": [], "staged": [], "untracked": []}


def test_get_git_status_dirty_modified_staged_untracked(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    (repo / "README.md").write_text("changed\n")
    (repo / "staged.txt").write_text("new\n")
    _git("add", "staged.txt", cwd=repo)
    (repo / "loose.txt").write_text("untracked\n")
    _patch_paths(monkeypatch, repo)
    status = cp.get_git_status()
    assert status["clean"] is False
    assert "README.md" in status["modified"]
    assert "staged.txt" in status["staged"]
    assert "loose.txt" in status["untracked"]


# --- pure parsing functions, synthetic text -------------------------------


def test_get_mcp_tool_count(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    registry = repo / "src" / "pfsense_mcp" / "tools" / "registry.py"
    registry.parent.mkdir(parents=True)
    registry.write_text(
        "class ToolRegistry:\n"
        "    def _register_a(self):\n"
        "        self._mcp.tool()(fn_a)\n"
        "    def _register_b(self):\n"
        "        self._mcp.tool()(fn_b)\n"
        "        self._mcp.tool()(fn_c)\n"
    )
    monkeypatch.setattr(cp, "REGISTRY_PATH", registry)
    assert cp.get_mcp_tool_count() == 3


def test_get_mcp_tool_count_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "REGISTRY_PATH", tmp_path / "does_not_exist.py")
    assert cp.get_mcp_tool_count() is None


def test_get_supported_capability_count(tmp_path, monkeypatch):
    capabilities = tmp_path / "capabilities.py"
    capabilities.write_text(
        "SUPPORTED_CAPABILITIES_THIS_BUILD: frozenset[Capability] = frozenset(\n"
        "    {\n"
        "        Capability.SYSTEM_READ,\n"
        "        Capability.INTERFACE_READ,\n"
        "        Capability.GATEWAY_READ,\n"
        "    }\n"
        ")\n"
    )
    monkeypatch.setattr(cp, "CAPABILITIES_PATH", capabilities)
    assert cp.get_supported_capability_count() == 3


_SAMPLE_BACKLOG = """# READ Capability Backlog

## Coverage summary

| Metric | Count |
|---|---|
| Total GET endpoints | 10 |

## Capabilities

| Capability | GET endpoint(s) | Complexity | Sensitivity | Dependencies | Priority | Status |
|---|---|---|---|---|---|---|
| SYSTEM_READ | `/status/system` | Low | Low | — | — | Done |
| ESCAPED_PIPE_READ | `/thing(a\\|b)` | Low | Low | — | High | Planned |
| BLOCKED_READ | `/blocked` | Low | Low | — | Medium | Blocked |
| DEFERRED_READ | `/deferred` | Low | Low | — | Low | Deferred |
| LOW_PRIORITY_READ | `/low` | Low | Low | — | Low | Planned |
| HIGH_PRIORITY_READ | `/high` | Low | Low | — | High | Planned |

## Appendix
"""


def test_parse_backlog_buckets_and_priority_order(tmp_path, monkeypatch):
    backlog = tmp_path / "READ_BACKLOG.md"
    backlog.write_text(_SAMPLE_BACKLOG)
    monkeypatch.setattr(cp, "BACKLOG_PATH", backlog)
    monkeypatch.setattr(cp, "get_supported_capability_count", lambda: 1)

    result = cp.parse_backlog()
    assert result["completed"] == ["SYSTEM_READ"]
    assert set(result["blocked"]) == {"BLOCKED_READ", "DEFERRED_READ"}
    names_in_order = [r["name"] for r in result["remaining"]]
    assert names_in_order == ["ESCAPED_PIPE_READ", "HIGH_PRIORITY_READ", "LOW_PRIORITY_READ"]
    assert result["next_capability"] == "ESCAPED_PIPE_READ"


def test_parse_backlog_handles_escaped_pipe_without_column_shift(tmp_path, monkeypatch):
    backlog = tmp_path / "READ_BACKLOG.md"
    backlog.write_text(_SAMPLE_BACKLOG)
    monkeypatch.setattr(cp, "BACKLOG_PATH", backlog)
    monkeypatch.setattr(cp, "get_supported_capability_count", lambda: 1)

    result = cp.parse_backlog()
    escaped = next(r for r in result["remaining"] if r["name"] == "ESCAPED_PIPE_READ")
    assert escaped["priority"] == "High"


def test_parse_backlog_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "BACKLOG_PATH", tmp_path / "does_not_exist.md")
    result = cp.parse_backlog()
    assert result == {
        "completed": [],
        "remaining": [],
        "blocked": [],
        "next_capability": None,
        "notes": result["notes"],
    }
    assert any("not found" in note for note in result["notes"])


def test_parse_backlog_stale_note_when_counts_mismatch(tmp_path, monkeypatch):
    backlog = tmp_path / "READ_BACKLOG.md"
    backlog.write_text(_SAMPLE_BACKLOG)
    monkeypatch.setattr(cp, "BACKLOG_PATH", backlog)
    monkeypatch.setattr(cp, "get_supported_capability_count", lambda: 99)

    result = cp.parse_backlog()
    assert any("stale" in note for note in result["notes"])


# --- render_checkpoint_md --------------------------------------------------


def _minimal_state(**overrides) -> dict:
    state = {
        "schema_version": 1,
        "timestamp_utc": "2026-01-01T00:00:00+00:00",
        "branch": "main",
        "latest_commit": {"hash": "abc123", "message": "Do a thing"},
        "git": {"clean": True, "modified": [], "staged": [], "untracked": []},
        "tests": {"pytest": {"passed": 5, "skipped": 1}, "make_quick": "passed", "make_validate": "passed"},
        "backlog": {
            "completed": ["A"],
            "remaining": [{"name": "B", "priority": "High"}],
            "blocked": [],
            "next_capability": "B",
        },
        "mcp": {"tool_count": 3},
        "notes": [],
    }
    state.update(overrides)
    return state


def test_render_checkpoint_md_clean_tree():
    md = cp.render_checkpoint_md(_minimal_state())
    assert "Working tree clean." in md
    assert "Next recommended capability: B" in md
    assert "Continue from the current repository state." in md
    assert "Resume with the highest-priority remaining READ capability" in md


def test_render_checkpoint_md_dirty_tree_lists_files():
    state = _minimal_state(git={"clean": False, "modified": ["a.py"], "staged": ["b.py"], "untracked": ["c.py"]})
    md = cp.render_checkpoint_md(state)
    assert "Working tree clean." not in md
    assert "a.py" in md
    assert "b.py" in md
    assert "c.py" in md


def test_render_checkpoint_md_no_remaining_capabilities():
    state = _minimal_state(backlog={"completed": ["A"], "remaining": [], "blocked": [], "next_capability": None})
    md = cp.render_checkpoint_md(state)
    assert "backlog exhausted" in md


def test_render_checkpoint_md_includes_notes():
    state = _minimal_state(notes=["Something needs attention."])
    md = cp.render_checkpoint_md(state)
    assert "Something needs attention." in md


# --- end-to-end main(), against a real temporary git repository ----------


def test_main_generates_both_output_files(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    (repo / "Makefile").write_text("quick:\n\t@true\nvalidate:\n\t@true\n")
    docs = repo / "docs"
    docs.mkdir()
    (docs / "READ_BACKLOG.md").write_text(_SAMPLE_BACKLOG)
    registry = repo / "src" / "pfsense_mcp" / "tools" / "registry.py"
    registry.parent.mkdir(parents=True)
    registry.write_text("class ToolRegistry:\n    def x(self):\n        self._mcp.tool()(fn)\n")
    capabilities = repo / "src" / "pfsense_mcp" / "capabilities.py"
    capabilities.write_text(
        "SUPPORTED_CAPABILITIES_THIS_BUILD = frozenset(\n    {\n        Capability.SYSTEM_READ,\n    }\n)\n"
    )
    _patch_paths(monkeypatch, repo)

    exit_code = cp.main()

    assert exit_code == 0
    checkpoint_md = repo / "CHECKPOINT.md"
    checkpoint_json = repo / ".checkpoint" / "state.json"
    assert checkpoint_md.is_file()
    assert checkpoint_json.is_file()

    state = json.loads(checkpoint_json.read_text())
    assert state["schema_version"] == 1
    assert state["branch"] in ("main", "master")
    assert state["mcp"]["tool_count"] == 1
    assert state["backlog"]["completed"] == ["SYSTEM_READ"]
    assert state["tests"]["make_quick"] == "passed"
    assert state["tests"]["make_validate"] == "passed"

    md_text = checkpoint_md.read_text()
    assert "# Project Checkpoint" in md_text
    assert "## Resume prompt" in md_text
    assert "## Engineering handoff" in md_text


def test_main_creates_checkpoint_dir_if_missing(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    (repo / "Makefile").write_text("quick:\n\t@true\nvalidate:\n\t@true\n")
    _patch_paths(monkeypatch, repo)
    assert not (repo / ".checkpoint").exists()

    cp.main()

    assert (repo / ".checkpoint").is_dir()
    assert (repo / ".checkpoint" / "state.json").is_file()


# --- get_pytest_totals: xdist-parallel + serial-tail split ---------------


def test_parse_pytest_summary_extracts_passed_skipped_failed():
    result = cp._parse_pytest_summary("...\n4370 passed, 42 skipped, 1 failed in 165.94s (0:02:44)")
    assert result == {"passed": 4370, "skipped": 42, "failed": 1}


def test_parse_pytest_summary_defaults_missing_keys_to_zero():
    result = cp._parse_pytest_summary("...\n6 passed in 0.43s")
    assert result == {"passed": 6, "skipped": 0, "failed": 0}


def test_parse_pytest_summary_returns_none_when_no_summary_line_found():
    assert cp._parse_pytest_summary("no summary line here\njust noise") is None


def test_get_pytest_totals_merges_parallel_and_serial_passes(monkeypatch):
    calls: list[list[str]] = []

    def _fake_run(cmd: list[str], timeout: int) -> tuple[int, str]:
        calls.append(cmd)
        if "-n" in cmd:
            return 0, "4370 passed, 42 skipped in 165.94s (0:02:44)"
        return 0, "6 passed in 0.43s"

    monkeypatch.setattr(cp, "_run", _fake_run)
    totals = cp.get_pytest_totals()

    assert totals == {"passed": 4376, "skipped": 42, "failed": 0}
    assert len(calls) == 2
    assert "-n" in calls[0] and "6" in calls[0] and "--dist=loadscope" in calls[0]
    for test_id in cp._XDIST_SERIAL_ONLY:
        assert test_id in calls[1]
        # Deselected from the parallel pass, not omitted entirely --
        # it appears in calls[0] only as the argument to --deselect.
        deselect_index = calls[0].index(test_id) - 1
        assert calls[0][deselect_index] == "--deselect"


def test_get_pytest_totals_deselects_the_same_tests_the_serial_pass_runs(monkeypatch):
    calls: list[list[str]] = []

    def _fake_run(cmd: list[str], timeout: int) -> tuple[int, str]:
        calls.append(cmd)
        return 0, "1 passed in 0.1s"

    monkeypatch.setattr(cp, "_run", _fake_run)
    cp.get_pytest_totals()

    deselected = [calls[0][i + 1] for i, arg in enumerate(calls[0]) if arg == "--deselect"]
    assert set(deselected) == set(cp._XDIST_SERIAL_ONLY)


def test_get_pytest_totals_returns_none_when_parallel_pass_unparseable_and_exit_zero(monkeypatch):
    def _fake_run(cmd: list[str], timeout: int) -> tuple[int, str]:
        return 0, "no summary line here"

    monkeypatch.setattr(cp, "_run", _fake_run)
    assert cp.get_pytest_totals() is None


def test_get_pytest_totals_returns_zero_dict_when_parallel_pass_fails_unparseably(monkeypatch):
    def _fake_run(cmd: list[str], timeout: int) -> tuple[int, str]:
        return 1, "some hard crash, no summary line"

    monkeypatch.setattr(cp, "_run", _fake_run)
    assert cp.get_pytest_totals() == {"passed": 0, "skipped": 0, "failed": 0}


def test_get_pytest_totals_counts_a_serial_pass_crash_as_one_failure(monkeypatch):
    def _fake_run(cmd: list[str], timeout: int) -> tuple[int, str]:
        if "-n" in cmd:
            return 0, "100 passed in 10s"
        return 1, "serial pass crashed, no summary line"

    monkeypatch.setattr(cp, "_run", _fake_run)
    totals = cp.get_pytest_totals()

    assert totals == {"passed": 100, "skipped": 0, "failed": 1}
