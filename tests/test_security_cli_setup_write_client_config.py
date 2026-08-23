"""Focused tests for `pfsense-mcp-security setup write-client-config`
-- the CLI wiring around
`security_client_config_write.run_client_config_write_from_environment()`.

Mirrors `tests/test_security_cli_setup_apply.py`'s own structure:
argparse-level wiring, exit-code mapping, and human/--json formatting
are exercised with a canned result (`_canned()`); real end-to-end
scenarios (plan-digest staleness computed from a real
`generate_setup_plan()`, a real write to a `tmp_path` config file, and
a real refusal) drive the actual `main()` path with no mocking, using
only disposable temporary files -- never a real user client config.
Orchestration-level correctness (merge semantics, backups, rollback,
token binding) is covered by `tests/test_security_client_config_write.py`
and is not re-tested here."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from pfsense_mcp import security_cli
from pfsense_mcp.security_cli import main
from pfsense_mcp.security_client_config_write import WriteOutcome, WriteResult
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_setup_plan import generate_setup_plan
from pfsense_mcp.security_setup_plan_digest import compute_setup_plan_digest


def _canned(monkeypatch, result: WriteResult) -> dict[str, object]:
    captured: dict[str, object] = {}

    def fake(
        env,
        *,
        client,
        config_path_override,
        command,
        env_vars,
        plan_digest,
        confirm_token,
    ):
        captured["client"] = client
        captured["config_path_override"] = config_path_override
        captured["command"] = command
        captured["env_vars"] = env_vars
        captured["plan_digest"] = plan_digest
        captured["confirm_token"] = confirm_token
        return result

    monkeypatch.setattr(security_cli, "run_client_config_write_from_environment", fake)
    return captured


def _write_secure(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.write_bytes(value)
    path.chmod(mode)


_BASE_ARGS = [
    "setup",
    "write-client-config",
    "--client",
    "codex",
    "--config-path",
    "/tmp/does-not-matter.toml",
    "--capability-posture",
    "read_only",
    "--anchor-assurance",
    "none",
]


# --- argparse-level wiring -------------------------------------------------


def test_requires_client_capability_posture_and_anchor_assurance():
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "write-client-config"])
    assert excinfo.value.code == 2


def test_rejects_unknown_client_value():
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "setup",
                "write-client-config",
                "--client",
                "not-a-real-client",
                "--capability-posture",
                "read_only",
                "--anchor-assurance",
                "none",
            ]
        )
    assert excinfo.value.code == 2


def test_rejects_unknown_capability_posture_value():
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "setup",
                "write-client-config",
                "--client",
                "codex",
                "--capability-posture",
                "not-a-real-posture",
                "--anchor-assurance",
                "none",
            ]
        )
    assert excinfo.value.code == 2


def test_forwards_client_and_config_path_to_orchestration(monkeypatch):
    captured = _canned(monkeypatch, WriteResult(WriteOutcome.INSPECT_CURRENT, "detail"))
    main(_BASE_ARGS)
    assert captured["client"] == "codex"
    assert captured["config_path_override"] == "/tmp/does-not-matter.toml"


def test_confirm_dash_reads_token_from_stdin(monkeypatch):
    captured = _canned(monkeypatch, WriteResult(WriteOutcome.WRITE_COMPLETED, "done"))
    monkeypatch.setattr("sys.stdin", io.StringIO("token-from-stdin\n"))
    main([*_BASE_ARGS, "--confirm", "-"])
    assert captured["confirm_token"] == "token-from-stdin"


def test_omitting_confirm_forwards_none(monkeypatch):
    captured = _canned(monkeypatch, WriteResult(WriteOutcome.INSPECT_CURRENT, "detail"))
    main(_BASE_ARGS)
    assert captured["confirm_token"] is None


def test_explicit_confirm_value_forwarded_verbatim(monkeypatch):
    captured = _canned(monkeypatch, WriteResult(WriteOutcome.WRITE_COMPLETED, "done"))
    main([*_BASE_ARGS, "--confirm", "explicit-token-value"])
    assert captured["confirm_token"] == "explicit-token-value"


def test_no_env_var_fallback_for_this_subcommand(monkeypatch):
    """Deliberately narrower than `setup apply`: reusing
    `PFSENSE_SETUP_APPLY_CONFIRM_TOKEN` here would let a token meant to
    confirm a pfSense-side mutation also silently confirm an unrelated
    local file write. Setting it must have no effect on this
    subcommand."""

    captured = _canned(monkeypatch, WriteResult(WriteOutcome.INSPECT_CURRENT, "detail"))
    monkeypatch.setenv("PFSENSE_SETUP_APPLY_CONFIRM_TOKEN", "should-be-ignored")
    main(_BASE_ARGS)
    assert captured["confirm_token"] is None


# --- exit-code mapping, every outcome --------------------------------------


def test_exit_code_write_completed(monkeypatch):
    _canned(monkeypatch, WriteResult(WriteOutcome.WRITE_COMPLETED, "done"))
    assert main(_BASE_ARGS) == 0


def test_exit_code_inspect_current(monkeypatch):
    _canned(monkeypatch, WriteResult(WriteOutcome.INSPECT_CURRENT, "inspect"))
    assert main(_BASE_ARGS) == 1


def test_exit_code_confirm_token_invalid(monkeypatch):
    _canned(monkeypatch, WriteResult(WriteOutcome.CONFIRM_TOKEN_INVALID, "invalid"))
    assert main(_BASE_ARGS) == 3


def test_exit_code_blocked_configuration_error(monkeypatch):
    _canned(monkeypatch, WriteResult(WriteOutcome.BLOCKED_CONFIGURATION_ERROR, "bad config"))
    assert main(_BASE_ARGS) == 4


def test_exit_code_blocked_malformed_existing_config(monkeypatch):
    _canned(monkeypatch, WriteResult(WriteOutcome.BLOCKED_MALFORMED_EXISTING_CONFIG, "malformed"))
    assert main(_BASE_ARGS) == 5


def test_exit_code_blocked_path_unsafe(monkeypatch):
    _canned(monkeypatch, WriteResult(WriteOutcome.BLOCKED_PATH_UNSAFE, "unsafe"))
    assert main(_BASE_ARGS) == 6


def test_exit_code_write_validation_failed_rolled_back(monkeypatch):
    _canned(monkeypatch, WriteResult(WriteOutcome.WRITE_VALIDATION_FAILED_ROLLED_BACK, "rolled back"))
    assert main(_BASE_ARGS) == 7


def test_exit_code_mapping_covers_every_outcome_member():
    assert set(security_cli._CLIENT_CONFIG_WRITE_EXIT_CODES) == set(WriteOutcome)


# --- --json / human formatting ---------------------------------------------


def test_human_output_contains_outcome_detail_and_token(capsys, monkeypatch):
    _canned(
        monkeypatch,
        WriteResult(
            WriteOutcome.INSPECT_CURRENT,
            "Proposed change is ready.",
            client_type="codex",
            config_path="/tmp/does-not-matter.toml",
            confirmation_token="a" * 64,
            diff="--- a\n+++ b\n",
        ),
    )
    main(_BASE_ARGS)
    out = capsys.readouterr().out
    assert "inspect_current" in out
    assert "Proposed change is ready." in out
    assert "a" * 64 in out
    assert "codex" in out


def test_json_output_is_valid_and_deterministic(capsys, monkeypatch):
    _canned(
        monkeypatch,
        WriteResult(
            WriteOutcome.WRITE_COMPLETED,
            "done",
            client_type="codex",
            config_path="/tmp/does-not-matter.toml",
            backup_path="/tmp/does-not-matter.toml.bak",
        ),
    )
    main([*_BASE_ARGS, "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["outcome"] == "write_completed"
    assert payload["backup_path"] == "/tmp/does-not-matter.toml.bak"

    main([*_BASE_ARGS, "--json"])
    second = capsys.readouterr().out
    assert out == second


def test_json_output_never_contains_a_null_byte_or_crashes_on_odd_detail(capsys, monkeypatch):
    _canned(monkeypatch, WriteResult(WriteOutcome.BLOCKED_CONFIGURATION_ERROR, "detail with \x00 and 😀 emoji"))
    exit_code = main([*_BASE_ARGS, "--json"])
    assert exit_code == 4
    payload = json.loads(capsys.readouterr().out)
    assert "emoji" in payload["detail"]


# --- end-to-end: real environment, real plan, real tmp_path file ----------


def test_end_to_end_fresh_inspect_then_write_against_real_environment(tmp_path, monkeypatch, capsys):
    confirm_key = tmp_path / "confirm.key"
    _write_secure(confirm_key, b"real-confirm-key-material")
    monkeypatch.setenv("PFSENSE_SETUP_CONFIRM_KEY_FILE", str(confirm_key))
    monkeypatch.setenv("PFSENSE_API_URL", "https://pfsense.example.invalid")
    monkeypatch.setenv("PFSENSE_API_KEY_FILE", str(tmp_path / "irrelevant"))
    monkeypatch.setenv("PFSENSE_TLS_MODE", "strict")

    config_path = tmp_path / "config.toml"

    inspect_exit = main(
        [
            "setup",
            "write-client-config",
            "--client",
            "codex",
            "--config-path",
            str(config_path),
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--json",
        ]
    )
    assert inspect_exit == 1
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["outcome"] == "inspect_current"
    token = inspected["confirmation_token"]
    assert not config_path.exists()

    write_exit = main(
        [
            "setup",
            "write-client-config",
            "--client",
            "codex",
            "--config-path",
            str(config_path),
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--confirm",
            token,
            "--json",
        ]
    )
    assert write_exit == 0
    written = json.loads(capsys.readouterr().out)
    assert written["outcome"] == "write_completed"
    assert "[mcp_servers.pfsense]" in config_path.read_text()


def test_end_to_end_stale_plan_digest_is_refused_before_any_write(tmp_path, monkeypatch, capsys):
    confirm_key = tmp_path / "confirm.key"
    _write_secure(confirm_key, b"real-confirm-key-material")
    monkeypatch.setenv("PFSENSE_SETUP_CONFIRM_KEY_FILE", str(confirm_key))
    monkeypatch.setenv("PFSENSE_API_URL", "https://pfsense.example.invalid")
    monkeypatch.setenv("PFSENSE_API_KEY_FILE", str(tmp_path / "irrelevant"))
    monkeypatch.setenv("PFSENSE_TLS_MODE", "strict")

    config_path = tmp_path / "config.toml"
    exit_code = main(
        [
            "setup",
            "write-client-config",
            "--client",
            "codex",
            "--config-path",
            str(config_path),
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--plan-digest",
            "0" * 64,
            "--confirm",
            "irrelevant-because-stale",
        ]
    )
    assert exit_code == security_cli._CLIENT_CONFIG_WRITE_PLAN_STALE_EXIT_CODE
    assert not config_path.exists()


def test_end_to_end_correct_plan_digest_is_accepted(tmp_path, monkeypatch, capsys):
    confirm_key = tmp_path / "confirm.key"
    _write_secure(confirm_key, b"real-confirm-key-material")
    monkeypatch.setenv("PFSENSE_SETUP_CONFIRM_KEY_FILE", str(confirm_key))
    monkeypatch.setenv("PFSENSE_API_URL", "https://pfsense.example.invalid")
    monkeypatch.setenv("PFSENSE_API_KEY_FILE", str(tmp_path / "irrelevant"))
    monkeypatch.setenv("PFSENSE_TLS_MODE", "strict")

    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY,
        target_anchor_assurance=AnchorAssurance.NONE,
        target_origin=None,
        target_identity=None,
        tls_mode=None,
        env=dict(os.environ),
    )
    digest = compute_setup_plan_digest(plan)

    config_path = tmp_path / "config.toml"
    exit_code = main(
        [
            "setup",
            "write-client-config",
            "--client",
            "codex",
            "--config-path",
            str(config_path),
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--plan-digest",
            digest,
            "--json",
        ]
    )
    assert exit_code == 1
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["outcome"] == "inspect_current"


def test_end_to_end_no_secret_material_ever_printed(tmp_path, monkeypatch, capsys):
    secret_marker = "SECRET-CONFIRM-KEY-MATERIAL-XYZ"
    confirm_key = tmp_path / "confirm.key"
    _write_secure(confirm_key, secret_marker.encode())
    monkeypatch.setenv("PFSENSE_SETUP_CONFIRM_KEY_FILE", str(confirm_key))
    monkeypatch.setenv("PFSENSE_API_URL", "https://pfsense.example.invalid")
    monkeypatch.setenv("PFSENSE_API_KEY_FILE", str(tmp_path / "irrelevant"))
    monkeypatch.setenv("PFSENSE_TLS_MODE", "strict")

    config_path = tmp_path / "config.toml"
    main(
        [
            "setup",
            "write-client-config",
            "--client",
            "codex",
            "--config-path",
            str(config_path),
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--json",
        ]
    )
    out = capsys.readouterr().out
    assert secret_marker not in out
