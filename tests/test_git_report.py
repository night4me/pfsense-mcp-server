"""Static self-check for scripts/git_report.py and the Makefile: this
report must remain read-only, never staging or modifying anything."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_FORBIDDEN_GIT_VERBS = ("add", "commit", "push", "reset", "checkout", "stash", "clean", "rm", "restore")


def test_git_report_never_invokes_a_mutating_git_subcommand():
    text = (REPO_ROOT / "scripts" / "git_report.py").read_text(encoding="utf-8")
    for verb in _FORBIDDEN_GIT_VERBS:
        assert f'"git", "{verb}"' not in text
        assert f"'git', '{verb}'" not in text


def test_makefile_never_invokes_a_mutating_git_subcommand():
    text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    for verb in _FORBIDDEN_GIT_VERBS:
        assert f"git {verb}" not in text
