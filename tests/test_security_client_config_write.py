"""Orchestration-level adversarial test matrix for
`security_client_config_write.py` (Phase C: `setup write-client-config`).

Mirrors the discipline already established for
`tests/test_security_setup_apply.py` and
`tests/test_security_recovery_orchestration.py`: exercises the real
`run_client_config_write_from_environment()` (and the primitives it
composes) directly, against real `tmp_path` fixtures -- never a real
user's own Claude Desktop/Codex/ChatGPT configuration file, and never
any pfSense network contact (this module makes none).

Covers the C5 checklist: fresh creation, merge into an existing file
with unrelated content preserved, an existing pfsense entry updated
safely, malformed-existing-config refusal (JSON and TOML), a read-only/
permission-denied target, symlink refusal, a non-absolute
(`--config-path`-shaped) override refusal, backup creation, rollback
after a simulated post-write validation failure, a "concurrent write"
race simulated via a leftover `.bak` file, stale confirmation (file
changed on disk since inspection), cross-client and cross-path token
confusion, and that no confirmation-key material ever leaks into any
`WriteResult` field."""

from __future__ import annotations

import json
import os

import pytest

from pfsense_mcp.security_client_config_write import (
    ClientConfigWriteBinding,
    ClientType,
    WriteOutcome,
    _content_digest,
    _find_table_span,
    _merge_json,
    _merge_toml,
    derive_confirmation_token,
    resolve_config_path,
    run_client_config_write_from_environment,
)

_COMMAND = "/opt/pfsense-mcp-server/.venv/bin/pfsense-mcp-server"
_ENV_VARS = {
    "PFSENSE_API_URL": "https://pfsense.example.invalid",
    "PFSENSE_IDENTITY": "api-mcp-admin",
    "PFSENSE_API_KEY_FILE": "/absolute/private/path/pfsense-api.key",
    "PFSENSE_TLS_MODE": "strict",
}
_PLAN_DIGEST = "a" * 64


def _confirm_key(tmp_path, value: bytes = b"real-confirm-key-material") -> dict[str, str]:
    key_path = tmp_path / "confirm-key"
    key_path.write_bytes(value)
    key_path.chmod(0o600)
    return {"PFSENSE_SETUP_CONFIRM_KEY_FILE": str(key_path)}


def _inspect(tmp_path, env, *, client="codex", config_path=None, plan_digest=_PLAN_DIGEST):
    return run_client_config_write_from_environment(
        env,
        client=client,
        config_path_override=config_path,
        command=_COMMAND,
        env_vars=_ENV_VARS,
        plan_digest=plan_digest,
        confirm_token=None,
    )


def _confirm(tmp_path, env, token, *, client="codex", config_path=None, plan_digest=_PLAN_DIGEST):
    return run_client_config_write_from_environment(
        env,
        client=client,
        config_path_override=config_path,
        command=_COMMAND,
        env_vars=_ENV_VARS,
        plan_digest=plan_digest,
        confirm_token=token,
    )


# --- fresh config creation ---------------------------------------------


def test_fresh_codex_config_creation(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = str(tmp_path / "config.toml")

    inspected = _inspect(tmp_path, env, config_path=config_path)
    assert inspected.outcome is WriteOutcome.INSPECT_CURRENT
    assert inspected.confirmation_token is not None
    assert not (tmp_path / "config.toml").exists()

    written = _confirm(tmp_path, env, inspected.confirmation_token, config_path=config_path)
    assert written.outcome is WriteOutcome.WRITE_COMPLETED
    assert written.backup_path is None
    content = (tmp_path / "config.toml").read_text()
    assert "[mcp_servers.pfsense]" in content
    assert "PFSENSE_API_URL" in content


def test_fresh_claude_desktop_config_creation(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = str(tmp_path / "claude_desktop_config.json")

    inspected = _inspect(tmp_path, env, client="claude-desktop", config_path=config_path)
    assert inspected.outcome is WriteOutcome.INSPECT_CURRENT

    written = _confirm(tmp_path, env, inspected.confirmation_token, client="claude-desktop", config_path=config_path)
    assert written.outcome is WriteOutcome.WRITE_COMPLETED
    parsed = json.loads((tmp_path / "claude_desktop_config.json").read_text())
    assert parsed["mcpServers"]["pfsense"]["command"] == _COMMAND


# --- merge into existing config, unrelated entries preserved -----------


def test_merge_preserves_unrelated_toml_tables(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_text('[mcp_servers.other]\ncommand = "other-tool"\nrequired = false\n')

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    written = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))

    assert written.outcome is WriteOutcome.WRITE_COMPLETED
    content = config_path.read_text()
    assert '[mcp_servers.other]\ncommand = "other-tool"' in content
    assert "[mcp_servers.pfsense]" in content


def test_merge_preserves_unrelated_json_keys(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "claude_desktop_config.json"
    config_path.write_text(json.dumps({"someOtherTopLevelSetting": True, "mcpServers": {"other": {"command": "x"}}}))

    inspected = _inspect(tmp_path, env, client="claude-desktop", config_path=str(config_path))
    written = _confirm(
        tmp_path, env, inspected.confirmation_token, client="claude-desktop", config_path=str(config_path)
    )

    assert written.outcome is WriteOutcome.WRITE_COMPLETED
    parsed = json.loads(config_path.read_text())
    assert parsed["someOtherTopLevelSetting"] is True
    assert parsed["mcpServers"]["other"]["command"] == "x"
    assert parsed["mcpServers"]["pfsense"]["command"] == _COMMAND


def test_existing_pfsense_entry_is_updated_not_duplicated(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[mcp_servers.pfsense]\ncommand = "/stale/path"\nrequired = true\n\n'
        '[mcp_servers.pfsense.env]\nPFSENSE_API_URL = "https://stale.invalid"\n'
    )

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    written = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))

    assert written.outcome is WriteOutcome.WRITE_COMPLETED
    content = config_path.read_text()
    assert content.count("[mcp_servers.pfsense]") == 1
    assert "/stale/path" not in content
    assert "stale.invalid" not in content
    assert _COMMAND in content


# --- malformed existing config refusal ----------------------------------


def test_malformed_existing_toml_is_refused(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_text("[this is not valid toml\n")

    result = _inspect(tmp_path, env, config_path=str(config_path))
    assert result.outcome is WriteOutcome.BLOCKED_MALFORMED_EXISTING_CONFIG
    assert config_path.read_text() == "[this is not valid toml\n"


def test_malformed_existing_json_is_refused(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "claude_desktop_config.json"
    config_path.write_text("{not valid json")

    result = _inspect(tmp_path, env, client="claude-desktop", config_path=str(config_path))
    assert result.outcome is WriteOutcome.BLOCKED_MALFORMED_EXISTING_CONFIG
    assert config_path.read_text() == "{not valid json"


def test_json_top_level_not_an_object_is_refused(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "claude_desktop_config.json"
    config_path.write_text("[1, 2, 3]")

    result = _inspect(tmp_path, env, client="claude-desktop", config_path=str(config_path))
    assert result.outcome is WriteOutcome.BLOCKED_MALFORMED_EXISTING_CONFIG


def test_json_mcp_servers_not_an_object_is_refused(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "claude_desktop_config.json"
    config_path.write_text(json.dumps({"mcpServers": "not-an-object"}))

    result = _inspect(tmp_path, env, client="claude-desktop", config_path=str(config_path))
    assert result.outcome is WriteOutcome.BLOCKED_MALFORMED_EXISTING_CONFIG


# --- permission / read-only failures ------------------------------------


def test_unreadable_existing_file_is_a_configuration_error(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root bypasses permission checks")
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_text("[mcp_servers.other]\n")
    config_path.chmod(0o000)
    try:
        result = _inspect(tmp_path, env, config_path=str(config_path))
    finally:
        config_path.chmod(0o600)
    assert result.outcome is WriteOutcome.BLOCKED_CONFIGURATION_ERROR


def test_readonly_directory_blocks_write_without_corrupting_anything(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root bypasses permission checks")
    env = _confirm_key(tmp_path)
    readonly_dir = tmp_path / "readonly"
    readonly_dir.mkdir()
    config_path = readonly_dir / "config.toml"

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    readonly_dir.chmod(0o500)
    try:
        result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))
    finally:
        readonly_dir.chmod(0o700)
    assert result.outcome is WriteOutcome.BLOCKED_CONFIGURATION_ERROR
    assert not config_path.exists()


# --- symlink / path-safety handling --------------------------------------


def test_symlinked_config_path_is_refused(tmp_path):
    env = _confirm_key(tmp_path)
    real_target = tmp_path / "real.toml"
    real_target.write_text("")
    link = tmp_path / "link.toml"
    link.symlink_to(real_target)

    result = _inspect(tmp_path, env, config_path=str(link))
    assert result.outcome is WriteOutcome.BLOCKED_PATH_UNSAFE
    assert real_target.read_text() == ""


def test_non_absolute_config_path_override_is_refused(tmp_path):
    env = _confirm_key(tmp_path)
    result = _inspect(tmp_path, env, config_path="relative/config.toml")
    assert result.outcome is WriteOutcome.BLOCKED_CONFIGURATION_ERROR


def test_claude_desktop_with_no_override_has_no_invented_default(tmp_path):
    env = _confirm_key(tmp_path)
    result = _inspect(tmp_path, env, client="claude-desktop", config_path=None)
    assert result.outcome is WriteOutcome.BLOCKED_CONFIGURATION_ERROR
    assert "no documented default" in result.detail


def test_not_owned_by_current_user_is_refused(tmp_path):
    """Structural proof only (cannot actually chown to another uid in
    a sandboxed test run): a file whose owning uid does not match the
    current process is treated the same as a permission failure by
    `_read_existing()`'s own uid check -- exercised directly here since
    it cannot be triggered end-to-end without root."""

    from pfsense_mcp.security_client_config_write import _read_existing

    config_path = tmp_path / "config.toml"
    config_path.write_text("[mcp_servers.other]\n")
    real_fstat = os.fstat

    class _FakeStat:
        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            return getattr(self._real, name)

        @property
        def st_uid(self):
            return self._real.st_uid + 1

    import pfsense_mcp.security_client_config_write as ccw

    def fake_fstat(fd):
        return _FakeStat(real_fstat(fd))

    original = ccw.os.fstat
    ccw.os.fstat = fake_fstat
    try:
        from pfsense_mcp.security_client_config_write import ClientConfigWriteError

        with pytest.raises(ClientConfigWriteError, match="owned by the current user"):
            _read_existing(config_path)
    finally:
        ccw.os.fstat = original


# --- missing parent directory (v1.0.0 clean-room finding, 2026-08-29) -----
#
# Real human clean-room acceptance testing found `setup write-client-config`
# fails with an opaque "Could not create temporary file for atomic write"
# error on a genuinely clean $HOME with no pre-existing `~/.codex` -- the
# exact first-time-machine scenario the documented Codex default path
# exists to serve. `_ensure_parent_directory()` fixes this; these tests
# prove the fix and that it introduces no new unsafe behavior.


def test_clean_home_missing_codex_parent_directory_inspect_and_write_succeed(tmp_path):
    """The exact reported scenario: a clean $HOME with no `.codex`
    directory at all. Inspection must succeed (it never touches the
    filesystem for writing), and the confirmed write must create both
    the directory and the file without any manual `mkdir` step."""

    env = _confirm_key(tmp_path)
    home = tmp_path / "clean-home"
    home.mkdir()
    config_path = home / ".codex" / "config.toml"
    assert not (home / ".codex").exists()

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    assert inspected.outcome is WriteOutcome.INSPECT_CURRENT
    assert not (home / ".codex").exists()  # inspection alone must not create it

    written = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))
    assert written.outcome is WriteOutcome.WRITE_COMPLETED
    assert config_path.is_file()
    assert "[mcp_servers.pfsense]" in config_path.read_text()


def test_created_parent_directory_has_owner_only_permissions(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "nohome" / ".codex" / "config.toml"

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    written = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))
    assert written.outcome is WriteOutcome.WRITE_COMPLETED

    mode = os.stat(config_path.parent).st_mode & 0o777
    assert mode == 0o700
    # The intermediate ancestor created along the way must be owner-only too.
    mode_ancestor = os.stat(config_path.parent.parent).st_mode & 0o777
    assert mode_ancestor == 0o700


def test_nested_missing_ancestors_are_all_created_safely(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "a" / "b" / "c" / "config.toml"

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    written = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))
    assert written.outcome is WriteOutcome.WRITE_COMPLETED
    assert config_path.is_file()


def test_parent_directory_symlink_is_refused_fail_closed(tmp_path):
    """A pre-existing symlink standing in for `.codex` must never be
    followed or written through -- refused before any file is touched,
    and the symlink's real target must remain completely unmodified."""

    env = _confirm_key(tmp_path)
    real_target = tmp_path / "attacker-controlled"
    real_target.mkdir()
    link_parent = tmp_path / ".codex"
    link_parent.symlink_to(real_target)
    config_path = link_parent / "config.toml"

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    assert inspected.outcome is WriteOutcome.INSPECT_CURRENT  # inspection alone never touches disk

    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))
    assert result.outcome is WriteOutcome.BLOCKED_PATH_UNSAFE
    assert list(real_target.iterdir()) == []


def test_dangling_parent_symlink_is_also_refused(tmp_path):
    env = _confirm_key(tmp_path)
    link_parent = tmp_path / ".codex"
    link_parent.symlink_to(tmp_path / "does-not-exist-target")
    config_path = link_parent / "config.toml"

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))
    assert result.outcome is WriteOutcome.BLOCKED_PATH_UNSAFE


def test_parent_exists_as_a_regular_file_not_a_directory_is_refused(tmp_path):
    env = _confirm_key(tmp_path)
    not_a_dir = tmp_path / ".codex"
    not_a_dir.write_text("i am a file, not a directory")
    config_path = not_a_dir / "config.toml"

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))
    assert result.outcome is WriteOutcome.BLOCKED_PATH_UNSAFE
    assert not_a_dir.read_text() == "i am a file, not a directory"


def test_parent_directory_wrong_owner_is_refused(tmp_path, monkeypatch):
    """Structural proof only (cannot actually chown to another uid in a
    sandboxed test run): an already-existing parent directory whose
    owning uid does not match the current process is refused, mirroring
    `_read_existing()`'s own uid check for the target file."""

    import pfsense_mcp.security_client_config_write as ccw

    existing_parent = tmp_path / ".codex"
    existing_parent.mkdir()
    config_path = existing_parent / "config.toml"
    env = _confirm_key(tmp_path)

    inspected = _inspect(tmp_path, env, config_path=str(config_path))

    real_geteuid = ccw.os.geteuid
    monkeypatch.setattr(ccw.os, "geteuid", lambda: real_geteuid() + 1)
    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))
    assert result.outcome is WriteOutcome.BLOCKED_PATH_UNSAFE
    assert "owned by the current user" in result.detail


def test_wrong_confirm_token_never_creates_the_missing_parent(tmp_path):
    """A wrong/stale token must be refused before `_ensure_parent_directory()`
    is ever reached -- the missing directory must not appear as a side
    effect of a rejected confirmation attempt."""

    env = _confirm_key(tmp_path)
    config_path = tmp_path / ".codex" / "config.toml"
    assert not (tmp_path / ".codex").exists()

    result = _confirm(tmp_path, env, "totally-wrong-token", config_path=str(config_path))
    assert result.outcome is WriteOutcome.CONFIRM_TOKEN_INVALID
    assert not (tmp_path / ".codex").exists()


def test_plan_digest_mismatch_never_creates_the_missing_parent(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / ".codex" / "config.toml"

    inspected = _inspect(tmp_path, env, config_path=str(config_path), plan_digest=_PLAN_DIGEST)
    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path), plan_digest="b" * 64)
    assert result.outcome is WriteOutcome.CONFIRM_TOKEN_INVALID
    assert not (tmp_path / ".codex").exists()


def test_no_api_key_or_secret_value_appears_when_creating_missing_parent(tmp_path):
    api_key_marker = "SECRET-API-KEY-VALUE-SHOULD-NEVER-APPEAR"
    env = _confirm_key(tmp_path)
    config_path = tmp_path / ".codex" / "config.toml"

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    written = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))

    for result in (inspected, written):
        for field in (result.detail, result.confirmation_token, result.diff, result.backup_path, result.config_path):
            if field is not None:
                assert api_key_marker not in field
    assert api_key_marker not in config_path.read_text()


def test_failure_after_parent_creation_leaves_no_partial_config_or_temp_artifact(tmp_path, monkeypatch):
    """If the atomic write itself fails after the (now-safely-created)
    parent directory exists, no partial config file and no leftover
    `.tmp-*` artifact may remain."""

    import pfsense_mcp.security_client_config_write as ccw

    env = _confirm_key(tmp_path)
    config_path = tmp_path / ".codex" / "config.toml"
    inspected = _inspect(tmp_path, env, config_path=str(config_path))

    def _boom(path, content):
        raise ccw.ClientConfigWriteError("simulated atomic-write failure")

    monkeypatch.setattr(ccw, "_write_atomic_with_backup", _boom)
    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))
    assert result.outcome is WriteOutcome.BLOCKED_CONFIGURATION_ERROR
    assert not config_path.exists()
    leftovers = [p for p in (tmp_path / ".codex").iterdir() if p.name != "config.toml"]
    assert leftovers == []


def test_existing_safe_parent_directory_is_left_completely_untouched(tmp_path):
    """A parent directory that already exists, is a real directory, and
    is owned by the current user must be used as-is -- never chmod'd,
    recreated, or otherwise modified, regardless of its existing mode."""

    env = _confirm_key(tmp_path)
    existing_parent = tmp_path / ".codex"
    existing_parent.mkdir(mode=0o755)
    os.chmod(existing_parent, 0o755)  # mkdir's mode is subject to umask; force it explicitly
    config_path = existing_parent / "config.toml"

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    written = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))
    assert written.outcome is WriteOutcome.WRITE_COMPLETED
    assert os.stat(existing_parent).st_mode & 0o777 == 0o755


# --- backup creation + rollback -------------------------------------------


def test_backup_is_created_with_original_content(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "config.toml"
    original = '[mcp_servers.other]\ncommand = "other-tool"\n'
    config_path.write_text(original)

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    written = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))

    assert written.backup_path == str(config_path) + ".bak"
    assert (tmp_path / "config.toml.bak").read_text() == original


def test_leftover_backup_from_interrupted_attempt_blocks_new_write(tmp_path):
    """Simulates a 'concurrent write / lock race' / crash-recovery
    scenario: a `.bak` file already exists (as if a prior write was
    interrupted after backup but before completion). The module must
    refuse to silently overwrite it."""

    env = _confirm_key(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_text('[mcp_servers.other]\ncommand = "other-tool"\n')
    (tmp_path / "config.toml.bak").write_text("leftover-from-a-prior-attempt")

    inspected = _inspect(tmp_path, env, config_path=str(config_path))
    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))

    assert result.outcome is WriteOutcome.BLOCKED_CONFIGURATION_ERROR
    assert (tmp_path / "config.toml.bak").read_text() == "leftover-from-a-prior-attempt"
    assert config_path.read_text() == '[mcp_servers.other]\ncommand = "other-tool"\n'


def test_post_write_validation_failure_rolls_back_to_original(tmp_path, monkeypatch):
    import pfsense_mcp.security_client_config_write as ccw

    env = _confirm_key(tmp_path)
    config_path = tmp_path / "config.toml"
    original = '[mcp_servers.other]\ncommand = "other-tool"\n'
    config_path.write_text(original)

    inspected = _inspect(tmp_path, env, config_path=str(config_path))

    real_replace = ccw.os.replace
    calls = {"count": 0}

    def corrupting_replace(src, dst):
        real_replace(src, dst)
        calls["count"] += 1
        if calls["count"] == 1:
            # Only corrupt the *initial* write -- the module's own
            # rollback path also calls `os.replace()` to restore the
            # backup, and that restore must go through unmodified or
            # this test would be corrupting its own verification step.
            with open(dst, "ab") as handle:
                handle.write(b"UNEXPECTED-CORRUPTION")

    monkeypatch.setattr(ccw.os, "replace", corrupting_replace)

    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))

    assert result.outcome is WriteOutcome.WRITE_VALIDATION_FAILED_ROLLED_BACK
    assert config_path.read_text() == original
    assert not (tmp_path / "config.toml.bak").exists()


def test_post_write_validation_failure_on_fresh_file_removes_it(tmp_path, monkeypatch):
    import pfsense_mcp.security_client_config_write as ccw

    env = _confirm_key(tmp_path)
    config_path = tmp_path / "config.toml"

    inspected = _inspect(tmp_path, env, config_path=str(config_path))

    real_replace = ccw.os.replace

    def corrupting_replace(src, dst):
        real_replace(src, dst)
        with open(dst, "ab") as handle:
            handle.write(b"UNEXPECTED-CORRUPTION")

    monkeypatch.setattr(ccw.os, "replace", corrupting_replace)

    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))

    assert result.outcome is WriteOutcome.WRITE_VALIDATION_FAILED_ROLLED_BACK
    assert not config_path.exists()


# --- stale confirmation / cross-client / cross-path token binding --------


def test_stale_confirmation_after_file_changed_on_disk_is_refused(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_text('[mcp_servers.other]\ncommand = "v1"\n')

    inspected = _inspect(tmp_path, env, config_path=str(config_path))

    config_path.write_text('[mcp_servers.other]\ncommand = "v2-changed-since-inspection"\n')

    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=str(config_path))
    assert result.outcome is WriteOutcome.CONFIRM_TOKEN_INVALID
    assert "v2-changed-since-inspection" in config_path.read_text()


def test_token_issued_for_codex_is_refused_for_claude_desktop(tmp_path):
    env = _confirm_key(tmp_path)
    codex_path = str(tmp_path / "config.toml")
    claude_path = str(tmp_path / "claude_desktop_config.json")

    inspected = _inspect(tmp_path, env, client="codex", config_path=codex_path)
    result = _confirm(tmp_path, env, inspected.confirmation_token, client="claude-desktop", config_path=claude_path)

    assert result.outcome is WriteOutcome.CONFIRM_TOKEN_INVALID


def test_token_issued_for_one_path_is_refused_for_another(tmp_path):
    env = _confirm_key(tmp_path)
    path_a = str(tmp_path / "a.toml")
    path_b = str(tmp_path / "b.toml")

    inspected = _inspect(tmp_path, env, config_path=path_a)
    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=path_b)

    assert result.outcome is WriteOutcome.CONFIRM_TOKEN_INVALID
    assert not (tmp_path / "b.toml").exists()


def test_token_issued_for_one_plan_digest_is_refused_for_another(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = str(tmp_path / "config.toml")

    inspected = _inspect(tmp_path, env, config_path=config_path, plan_digest="a" * 64)
    result = _confirm(tmp_path, env, inspected.confirmation_token, config_path=config_path, plan_digest="b" * 64)

    assert result.outcome is WriteOutcome.CONFIRM_TOKEN_INVALID


def test_garbage_confirm_token_is_refused_without_crashing(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = str(tmp_path / "config.toml")
    result = _confirm(tmp_path, env, "\x00\x01 not a real token 😀", config_path=config_path)
    assert result.outcome is WriteOutcome.CONFIRM_TOKEN_INVALID


def test_empty_string_confirm_token_is_refused(tmp_path):
    env = _confirm_key(tmp_path)
    config_path = str(tmp_path / "config.toml")
    result = _confirm(tmp_path, env, "", config_path=config_path)
    assert result.outcome is WriteOutcome.CONFIRM_TOKEN_INVALID


# --- no secret leakage ----------------------------------------------------


def test_confirm_key_material_never_appears_in_any_result_field(tmp_path):
    secret_marker = "SECRET-CONFIRM-KEY-MATERIAL-1234567890"
    env = _confirm_key(tmp_path, value=secret_marker.encode())
    config_path = str(tmp_path / "config.toml")

    inspected = _inspect(tmp_path, env, config_path=config_path)
    written = _confirm(tmp_path, env, inspected.confirmation_token, config_path=config_path)

    for result in (inspected, written):
        for field in (result.detail, result.confirmation_token, result.diff, result.backup_path, result.config_path):
            if field is not None:
                assert secret_marker not in field


def test_missing_confirm_key_file_is_a_configuration_error_not_a_crash(tmp_path):
    env = {"PFSENSE_SETUP_CONFIRM_KEY_FILE": str(tmp_path / "does-not-exist")}
    config_path = str(tmp_path / "config.toml")
    result = _inspect(tmp_path, env, config_path=config_path)
    assert result.outcome is WriteOutcome.BLOCKED_CONFIGURATION_ERROR


# --- zero network contact (static proof) -----------------------------------


def test_module_imports_no_network_or_pfsense_client_machinery():
    import ast
    from pathlib import Path

    source = (Path(__file__).parents[1] / "src/pfsense_mcp/security_client_config_write.py").read_text()
    tree = ast.parse(source)
    forbidden = {"httpx", "requests", "socket", "factory", "config", "pfsense_client", "pfsense_mcp.tier1"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden, alias.name
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            root = node.module.split(".")[0]
            assert node.module not in forbidden and root not in forbidden, node.module


# --- unit-level coverage of the primitive helpers ---------------------------


def test_content_digest_absent_vs_present():
    assert _content_digest(None) == "absent"
    assert _content_digest(b"") != "absent"
    assert _content_digest(b"x") != _content_digest(b"y")


def test_derive_and_match_round_trip():
    binding = ClientConfigWriteBinding(
        client_type="codex",
        config_path="/tmp/x/config.toml",
        plan_digest=_PLAN_DIGEST,
        existing_content_digest="absent",
        proposed_content_digest=_content_digest(b"proposed"),
    )
    token = derive_confirmation_token(binding, integrity_key=b"key-material")
    from pfsense_mcp.security_client_config_write import confirmation_token_matches

    assert confirmation_token_matches(token, binding, integrity_key=b"key-material")
    assert not confirmation_token_matches(token, binding, integrity_key=b"different-key")
    assert not confirmation_token_matches("wrong", binding, integrity_key=b"key-material")
    assert not confirmation_token_matches(None, binding, integrity_key=b"key-material")


def test_resolve_config_path_codex_default_used_only_without_override():
    from pathlib import Path as _Path

    resolved = resolve_config_path(ClientType.CODEX, None)
    assert resolved == _Path("~/.codex/config.toml").expanduser()

    overridden = resolve_config_path(ClientType.CODEX, "/tmp/custom/config.toml")
    assert overridden == _Path("/tmp/custom/config.toml")


def test_find_table_span_returns_none_when_absent():
    assert _find_table_span(["[other]", "x = 1"], "[mcp_servers.pfsense]") is None


def test_merge_toml_round_trips_through_tomllib():
    import tomllib

    result = _merge_toml(None, command=_COMMAND, env_vars=_ENV_VARS)
    parsed = tomllib.loads(result.decode())
    assert parsed["mcp_servers"]["pfsense"]["command"] == _COMMAND
    assert parsed["mcp_servers"]["pfsense"]["env"]["PFSENSE_API_URL"] == _ENV_VARS["PFSENSE_API_URL"]


def test_merge_json_round_trips_through_json_loads():
    result = _merge_json(None, command=_COMMAND, env_vars=_ENV_VARS)
    parsed = json.loads(result)
    assert parsed["mcpServers"]["pfsense"]["command"] == _COMMAND
