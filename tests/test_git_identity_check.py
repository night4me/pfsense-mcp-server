from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import git_identity_check
from git_identity_check import _FORBIDDEN_IDENTITY_HASHES, check_git_identity, main

# Deliberately synthetic, never the real leaked values (see
# git_identity_check.py's own module docstring for why plaintext must
# never appear in a public file) -- monkeypatched in as this test
# module's own private blocklist so the detection *mechanism* can be
# exercised without ever writing the real leaked identity anywhere,
# including here. `test_forbidden_identity_hashes_are_well_formed` below
# separately checks the real production constant's shape only.
_FORBIDDEN_NAME = "synthetic-test-forbidden-user"
_FORBIDDEN_EMAIL = "synthetic-forbidden@example.invalid"
_TEST_FORBIDDEN_HASHES = frozenset(
    {
        hashlib.sha256(_FORBIDDEN_NAME.encode()).hexdigest(),
        hashlib.sha256(_FORBIDDEN_EMAIL.encode()).hexdigest(),
    }
)

_CLEAN_NAME = "night4me"
_CLEAN_EMAIL = "night4me@users.noreply.github.com"

# Isolate every test repo from whatever global/system git config the host
# happens to have -- every identity used below is explicit, never inherited.
_ISOLATED_ENV = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, env=_ISOLATED_ENV, check=True)


def _commit(
    path: Path,
    *,
    author_name: str,
    author_email: str,
    committer_name: str,
    committer_email: str,
    message: str = "test commit",
) -> None:
    (path / "file.txt").write_text(f"{message}\n", encoding="utf-8")
    subprocess.run(["git", "add", "file.txt"], cwd=path, env=_ISOLATED_ENV, check=True)
    env = {
        **_ISOLATED_ENV,
        "GIT_AUTHOR_NAME": author_name,
        "GIT_AUTHOR_EMAIL": author_email,
        "GIT_COMMITTER_NAME": committer_name,
        "GIT_COMMITTER_EMAIL": committer_email,
    }
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=path, env=env, check=True)


def test_forbidden_identity_hashes_are_well_formed():
    # Structural check on the real production blocklist -- confirms
    # shape (count, hex format) without ever needing the plaintext this
    # test file must not contain.
    assert len(_FORBIDDEN_IDENTITY_HASHES) == 2
    for value in _FORBIDDEN_IDENTITY_HASHES:
        assert re.fullmatch(r"[0-9a-f]{64}", value)


def test_clean_repo_with_no_commits_and_no_config_passes(tmp_path):
    _init_repo(tmp_path)
    assert check_git_identity(tmp_path) == []


def test_clean_configured_identity_and_clean_commit_passes(tmp_path):
    _init_repo(tmp_path)
    subprocess.run(["git", "config", "user.name", _CLEAN_NAME], cwd=tmp_path, env=_ISOLATED_ENV, check=True)
    subprocess.run(["git", "config", "user.email", _CLEAN_EMAIL], cwd=tmp_path, env=_ISOLATED_ENV, check=True)
    _commit(
        tmp_path,
        author_name=_CLEAN_NAME,
        author_email=_CLEAN_EMAIL,
        committer_name=_CLEAN_NAME,
        committer_email=_CLEAN_EMAIL,
    )
    assert check_git_identity(tmp_path) == []


def test_forbidden_configured_name_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(git_identity_check, "_FORBIDDEN_IDENTITY_HASHES", _TEST_FORBIDDEN_HASHES)
    _init_repo(tmp_path)
    subprocess.run(["git", "config", "user.name", _FORBIDDEN_NAME], cwd=tmp_path, env=_ISOLATED_ENV, check=True)
    subprocess.run(["git", "config", "user.email", _CLEAN_EMAIL], cwd=tmp_path, env=_ISOLATED_ENV, check=True)
    findings = check_git_identity(tmp_path)
    assert any("user.name" in f for f in findings)
    assert not any("user.email" in f for f in findings)


def test_forbidden_configured_email_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(git_identity_check, "_FORBIDDEN_IDENTITY_HASHES", _TEST_FORBIDDEN_HASHES)
    _init_repo(tmp_path)
    subprocess.run(["git", "config", "user.name", _CLEAN_NAME], cwd=tmp_path, env=_ISOLATED_ENV, check=True)
    subprocess.run(["git", "config", "user.email", _FORBIDDEN_EMAIL], cwd=tmp_path, env=_ISOLATED_ENV, check=True)
    findings = check_git_identity(tmp_path)
    assert any("user.email" in f for f in findings)
    assert not any("user.name" in f for f in findings)


def test_configured_identity_check_is_case_insensitive(tmp_path, monkeypatch):
    monkeypatch.setattr(git_identity_check, "_FORBIDDEN_IDENTITY_HASHES", _TEST_FORBIDDEN_HASHES)
    _init_repo(tmp_path)
    subprocess.run(
        ["git", "config", "user.email", _FORBIDDEN_EMAIL.upper()], cwd=tmp_path, env=_ISOLATED_ENV, check=True
    )
    findings = check_git_identity(tmp_path)
    assert any("user.email" in f for f in findings)


def test_forbidden_commit_author_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(git_identity_check, "_FORBIDDEN_IDENTITY_HASHES", _TEST_FORBIDDEN_HASHES)
    _init_repo(tmp_path)
    _commit(
        tmp_path,
        author_name=_FORBIDDEN_NAME,
        author_email=_FORBIDDEN_EMAIL,
        committer_name=_CLEAN_NAME,
        committer_email=_CLEAN_EMAIL,
    )
    findings = check_git_identity(tmp_path)
    assert any("author" in f for f in findings)
    assert not any("committer" in f for f in findings)


def test_forbidden_commit_committer_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(git_identity_check, "_FORBIDDEN_IDENTITY_HASHES", _TEST_FORBIDDEN_HASHES)
    _init_repo(tmp_path)
    _commit(
        tmp_path,
        author_name=_CLEAN_NAME,
        author_email=_CLEAN_EMAIL,
        committer_name=_FORBIDDEN_NAME,
        committer_email=_FORBIDDEN_EMAIL,
    )
    findings = check_git_identity(tmp_path)
    assert any("committer" in f for f in findings)
    assert not any("author" in f for f in findings)


def test_forbidden_identity_several_commits_back_is_still_found(tmp_path, monkeypatch):
    monkeypatch.setattr(git_identity_check, "_FORBIDDEN_IDENTITY_HASHES", _TEST_FORBIDDEN_HASHES)
    _init_repo(tmp_path)
    _commit(
        tmp_path,
        author_name=_CLEAN_NAME,
        author_email=_CLEAN_EMAIL,
        committer_name=_CLEAN_NAME,
        committer_email=_CLEAN_EMAIL,
        message="one",
    )
    _commit(
        tmp_path,
        author_name=_FORBIDDEN_NAME,
        author_email=_FORBIDDEN_EMAIL,
        committer_name=_FORBIDDEN_NAME,
        committer_email=_FORBIDDEN_EMAIL,
        message="two -- the leak",
    )
    _commit(
        tmp_path,
        author_name=_CLEAN_NAME,
        author_email=_CLEAN_EMAIL,
        committer_name=_CLEAN_NAME,
        committer_email=_CLEAN_EMAIL,
        message="three",
    )
    findings = check_git_identity(tmp_path)
    assert len(findings) == 2  # author + committer on the one bad commit


def test_main_returns_nonzero_on_findings(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(git_identity_check, "_FORBIDDEN_IDENTITY_HASHES", _TEST_FORBIDDEN_HASHES)
    _init_repo(tmp_path)
    subprocess.run(["git", "config", "user.email", _FORBIDDEN_EMAIL], cwd=tmp_path, env=_ISOLATED_ENV, check=True)
    monkeypatch.chdir(tmp_path)
    assert main() == 1
    out = capsys.readouterr().out
    assert "FAILED" in out


def test_main_returns_zero_on_clean_repo(tmp_path, monkeypatch, capsys):
    _init_repo(tmp_path)
    subprocess.run(["git", "config", "user.email", _CLEAN_EMAIL], cwd=tmp_path, env=_ISOLATED_ENV, check=True)
    monkeypatch.chdir(tmp_path)
    assert main() == 0
    out = capsys.readouterr().out
    assert "OK" in out
