"""Unit tests for `security_setup_confirm_key.create_confirm_key()` --
the v1.0.0 clean-room finding fix for the previously-undocumented,
unguided `PFSENSE_SETUP_CONFIRM_KEY_FILE` requirement.

Covers: clean first-run creation, secure permissions, idempotency
(never overwrites/rotates), symlink rejection, parent-directory
creation, and that the created key is directly usable by
`security_setup_apply._read_confirm_key()` -- proving this module's
output and that module's input are compatible without re-testing
`setup apply`'s own orchestration (see `tests/test_security_setup_apply.py`
for that)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from pfsense_mcp.security_setup_apply import _read_confirm_key
from pfsense_mcp.security_setup_confirm_key import (
    DEFAULT_CONFIRM_KEY_FILE,
    InitConfirmKeyOutcome,
    create_confirm_key,
)


def test_default_path_uses_established_local_state_directory_convention():
    # Reuses logging_setup.DEFAULT_LOG_DIR's own convention -- never an
    # invented one -- so an operator following only this tool's
    # guidance never has to invent an arbitrary absolute path.
    expected = Path.home() / ".local" / "state" / "pfsense-mcp-server" / "setup-confirm.key"
    assert expected == DEFAULT_CONFIRM_KEY_FILE


def test_clean_first_run_creates_a_key_with_owner_only_permissions(tmp_path):
    target = tmp_path / "sub" / "confirm.key"
    result = create_confirm_key(target)
    assert result.outcome is InitConfirmKeyOutcome.CREATED
    assert result.path == target
    assert target.is_file()
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600


def test_parent_directory_is_created_with_owner_only_permissions(tmp_path):
    target = tmp_path / "does" / "not" / "exist" / "confirm.key"
    create_confirm_key(target)
    parent_mode = stat.S_IMODE(target.parent.stat().st_mode)
    assert parent_mode == 0o700


def test_created_key_is_64_hex_characters_256_bit():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "confirm.key"
        create_confirm_key(target)
        content = target.read_text().strip()
        assert len(content) == 64
        bytes.fromhex(content)  # raises if not valid hex


def test_two_calls_produce_different_random_keys_across_distinct_paths(tmp_path):
    first = create_confirm_key(tmp_path / "a.key")
    second = create_confirm_key(tmp_path / "b.key")
    assert (tmp_path / "a.key").read_text() != (tmp_path / "b.key").read_text()
    assert first.outcome is InitConfirmKeyOutcome.CREATED
    assert second.outcome is InitConfirmKeyOutcome.CREATED


def test_second_call_on_same_path_is_idempotent_and_never_overwrites(tmp_path):
    target = tmp_path / "confirm.key"
    create_confirm_key(target)
    original_content = target.read_bytes()

    result = create_confirm_key(target)
    assert result.outcome is InitConfirmKeyOutcome.ALREADY_EXISTS
    assert target.read_bytes() == original_content


def test_symlink_target_is_rejected_not_followed(tmp_path):
    real = tmp_path / "real.key"
    real.write_text("attacker-controlled-content")
    link = tmp_path / "link.key"
    link.symlink_to(real)

    result = create_confirm_key(link)
    assert result.outcome is InitConfirmKeyOutcome.BLOCKED_UNSAFE_PATH
    # The symlink target must never be modified.
    assert real.read_text() == "attacker-controlled-content"


def test_dangling_symlink_is_also_rejected(tmp_path):
    link = tmp_path / "dangling.key"
    link.symlink_to(tmp_path / "does-not-exist.key")

    result = create_confirm_key(link)
    assert result.outcome is InitConfirmKeyOutcome.BLOCKED_UNSAFE_PATH


def test_result_never_contains_the_key_value(tmp_path):
    target = tmp_path / "confirm.key"
    result = create_confirm_key(target)
    key_value = target.read_text().strip()
    assert key_value not in result.detail
    assert key_value not in str(result.path)


def test_default_argument_none_uses_default_confirm_key_file(monkeypatch, tmp_path):
    # Redirect the default path into tmp_path for this one test rather
    # than touching the real $HOME.
    import pfsense_mcp.security_setup_confirm_key as module

    fake_default = tmp_path / "state" / "setup-confirm.key"
    monkeypatch.setattr(module, "DEFAULT_CONFIRM_KEY_FILE", fake_default)
    result = create_confirm_key(None)
    assert result.path == fake_default
    assert result.outcome is InitConfirmKeyOutcome.CREATED


def test_created_key_is_directly_usable_by_setup_apply_reader(tmp_path):
    target = tmp_path / "confirm.key"
    create_confirm_key(target)
    key_bytes = _read_confirm_key(target)
    assert len(key_bytes) == 64
    assert key_bytes == target.read_text().strip().encode("ascii")


def test_unsupported_platform_without_o_nofollow_fails_closed(tmp_path, monkeypatch):
    import pfsense_mcp.security_setup_confirm_key as module

    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    target = tmp_path / "confirm.key"
    result = module.create_confirm_key(target)
    assert result.outcome is InitConfirmKeyOutcome.FAILED
    assert not target.exists()


def test_parent_path_occupied_by_a_regular_file_fails_closed_not_partially(tmp_path):
    # "Parent directory" already exists as a plain file, not a
    # directory -- mkdir(parents=True, exist_ok=True) cannot tolerate
    # that, so creation must fail closed rather than write anywhere.
    occupied = tmp_path / "not-a-directory"
    occupied.write_text("i am a file, not a directory")
    target = occupied / "confirm.key"

    result = create_confirm_key(target)
    assert result.outcome is InitConfirmKeyOutcome.FAILED
    assert not target.exists()
    assert occupied.read_text() == "i am a file, not a directory"
