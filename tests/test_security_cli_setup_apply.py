"""Focused tests for `pfsense-mcp-security setup apply` -- the CLI
wiring around `security_setup_apply.run_setup_apply_from_environment()`.

Most scenarios are exercised by monkeypatching
`pfsense_mcp.security_cli.run_setup_apply_from_environment` with a
canned `ApplyResult` -- this file is about argument parsing,
human/--json formatting, stdin-confirmation, and exit-code mapping, not
about re-testing orchestration logic (see `tests/test_security_setup_apply.py`
for that). One end-to-end test drives the real
`main(["setup", "apply", ...])` path against a real (but
build_pfsense_client-stubbed) environment to prove the wiring works
together, mirroring `tests/test_security_cli_recover.py`'s own
end-to-end tests."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from pfsense_mcp import security_cli
from pfsense_mcp.security_cli import main
from pfsense_mcp.security_setup_apply import ApplyOutcome, ApplyResult


def _canned(monkeypatch, result: ApplyResult) -> dict[str, object]:
    captured: dict[str, object] = {}

    def fake(
        env,
        *,
        target_capability_posture,
        target_anchor_assurance,
        target_origin=None,
        target_identity=None,
        tls_mode=None,
        plan_digest=None,
        confirm_token=None,
    ):
        captured["target_capability_posture"] = target_capability_posture
        captured["target_anchor_assurance"] = target_anchor_assurance
        captured["target_origin"] = target_origin
        captured["target_identity"] = target_identity
        captured["tls_mode"] = tls_mode
        captured["plan_digest"] = plan_digest
        captured["confirm_token"] = confirm_token
        return result

    monkeypatch.setattr(security_cli, "run_setup_apply_from_environment", fake)
    return captured


def _write_secure(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.write_bytes(value)
    path.chmod(mode)


# --- argparse-level wiring ---------------------------------------------


def test_requires_capability_posture_and_anchor_assurance():
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "apply"])
    assert excinfo.value.code == 2


def test_rejects_unknown_capability_posture_value():
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "apply", "--capability-posture", "not-a-real-posture", "--anchor-assurance", "none"])
    assert excinfo.value.code == 2


def test_rejects_unknown_anchor_assurance_value():
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "not-a-real-anchor"])
    assert excinfo.value.code == 2


def test_bare_setup_still_works_alongside_the_new_apply_subaction(monkeypatch, capsys):
    """`setup apply` must not break bare `setup`'s own existing flags --
    argparse's nested subparsers coexist with the parent's own."""

    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    exit_code = main(["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none"])
    assert exit_code == 0


# --- forwarding of every flag to the orchestration layer -----------------


def test_forwards_all_flags_to_orchestration(monkeypatch):
    captured = _canned(monkeypatch, ApplyResult(ApplyOutcome.INSPECT_PLAN_CURRENT, "detail"))

    main(
        [
            "setup",
            "apply",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "hardware_witness",
            "--target-origin",
            "https://pfsense.example",
            "--target-identity",
            "admin",
            "--tls-mode",
            "verify",
            "--plan-digest",
            "a" * 64,
            "--confirm",
            "some-token",
        ]
    )

    assert captured["target_capability_posture"] == "read_only"
    assert captured["target_anchor_assurance"] == "hardware_witness"
    assert captured["target_origin"] == "https://pfsense.example"
    assert captured["target_identity"] == "admin"
    assert captured["tls_mode"] == "verify"
    assert captured["plan_digest"] == "a" * 64
    assert captured["confirm_token"] == "some-token"


def test_confirm_dash_reads_token_from_stdin(monkeypatch):
    captured = _canned(monkeypatch, ApplyResult(ApplyOutcome.APPLY_COMPLETED, "done"))
    monkeypatch.setattr("sys.stdin", io.StringIO("token-from-stdin\n"))

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none", "--confirm", "-"])

    assert captured["confirm_token"] == "token-from-stdin"


def test_omitting_confirm_forwards_none(monkeypatch):
    captured = _canned(monkeypatch, ApplyResult(ApplyOutcome.INSPECT_PLAN_CURRENT, "detail"))

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"])

    assert captured["confirm_token"] is None


# --- Slice 7: PFSENSE_SETUP_APPLY_CONFIRM_TOKEN env-var fallback ------------
#
# A purely additive way to supply --confirm's value that keeps it out of
# argv/`ps`/shell history -- the standard CI-secret-injection convention,
# complementing --confirm - (stdin) for pipelines where piping between
# steps is awkward. Never required, never consulted when --confirm was
# given explicitly (including "-"), never weakens any existing gate.


def test_confirm_env_var_used_when_flag_omitted_entirely(monkeypatch):
    captured = _canned(monkeypatch, ApplyResult(ApplyOutcome.APPLY_COMPLETED, "done"))
    monkeypatch.setenv("PFSENSE_SETUP_APPLY_CONFIRM_TOKEN", "token-from-env")

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"])

    assert captured["confirm_token"] == "token-from-env"


def test_explicit_confirm_flag_wins_over_env_var(monkeypatch):
    captured = _canned(monkeypatch, ApplyResult(ApplyOutcome.APPLY_COMPLETED, "done"))
    monkeypatch.setenv("PFSENSE_SETUP_APPLY_CONFIRM_TOKEN", "token-from-env-should-be-ignored")

    main(
        [
            "setup",
            "apply",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--confirm",
            "token-from-flag",
        ]
    )

    assert captured["confirm_token"] == "token-from-flag"


def test_confirm_dash_stdin_wins_over_env_var(monkeypatch):
    captured = _canned(monkeypatch, ApplyResult(ApplyOutcome.APPLY_COMPLETED, "done"))
    monkeypatch.setenv("PFSENSE_SETUP_APPLY_CONFIRM_TOKEN", "token-from-env-should-be-ignored")
    monkeypatch.setattr("sys.stdin", io.StringIO("token-from-stdin\n"))

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none", "--confirm", "-"])

    assert captured["confirm_token"] == "token-from-stdin"


def test_empty_confirm_env_var_is_treated_as_absent(monkeypatch):
    captured = _canned(monkeypatch, ApplyResult(ApplyOutcome.INSPECT_PLAN_CURRENT, "detail"))
    monkeypatch.setenv("PFSENSE_SETUP_APPLY_CONFIRM_TOKEN", "")

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"])

    assert captured["confirm_token"] is None


def test_whitespace_only_confirm_env_var_is_treated_as_absent(monkeypatch):
    captured = _canned(monkeypatch, ApplyResult(ApplyOutcome.INSPECT_PLAN_CURRENT, "detail"))
    monkeypatch.setenv("PFSENSE_SETUP_APPLY_CONFIRM_TOKEN", "   ")

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"])

    assert captured["confirm_token"] is None


def test_confirm_env_var_absent_and_flag_omitted_still_inspects(monkeypatch):
    monkeypatch.delenv("PFSENSE_SETUP_APPLY_CONFIRM_TOKEN", raising=False)
    captured = _canned(monkeypatch, ApplyResult(ApplyOutcome.INSPECT_PLAN_CURRENT, "detail"))

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"])

    assert captured["confirm_token"] is None


def test_wrong_confirm_env_var_value_is_refused_exactly_like_a_wrong_flag_value(tmp_path, monkeypatch):
    """End-to-end (not canned): a wrong token supplied only via the env
    var must be refused by the real orchestration layer exactly like a
    wrong --confirm flag value would be -- proves the env-var path does
    not bypass token verification, only how the value arrives."""

    def _write_secure(path, value):
        path.write_bytes(value)
        path.chmod(0o600)

    confirm_key = tmp_path / "confirm.key"
    _write_secure(confirm_key, b"real-confirm-key-material")
    monkeypatch.setenv("PFSENSE_SETUP_CONFIRM_KEY_FILE", str(confirm_key))

    inspect_exit = main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"])
    assert inspect_exit == 1

    monkeypatch.setenv("PFSENSE_SETUP_APPLY_CONFIRM_TOKEN", "0" * 64)
    exit_code = main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"])
    assert exit_code == 3


# --- exit-code mapping, every outcome -------------------------------------


def test_exit_code_apply_completed(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.APPLY_COMPLETED, "done"))
    assert main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"]) == 0


def test_exit_code_inspect_plan_current(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.INSPECT_PLAN_CURRENT, "inspect"))
    assert main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"]) == 1


def test_exit_code_plan_stale(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.PLAN_STALE, "stale"))
    assert main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"]) == 2


def test_exit_code_confirm_token_invalid(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.CONFIRM_TOKEN_INVALID, "invalid"))
    assert main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"]) == 3


def test_exit_code_blocked_configuration_error(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.BLOCKED_CONFIGURATION_ERROR, "blocked"))
    assert main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"]) == 5


def test_exit_code_bootstrap_already_complete(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.BOOTSTRAP_ALREADY_COMPLETE, "already complete"))
    assert main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none"]) == 0


def test_exit_code_bootstrap_completed(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.BOOTSTRAP_COMPLETED, "completed"))
    assert main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none"]) == 0


def test_exit_code_bootstrap_lock_contention(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.BOOTSTRAP_LOCK_CONTENTION, "lock held"))
    assert main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none"]) == 8


def test_exit_code_bootstrap_recovery_required(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED, "recovery required"))
    assert main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none"]) == 9


def test_exit_code_bootstrap_corrupt_local_state(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.BOOTSTRAP_CORRUPT_LOCAL_STATE, "corrupt"))
    assert main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none"]) == 10


def test_exit_code_bootstrap_preflight_derivation_failed(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.BOOTSTRAP_PREFLIGHT_DERIVATION_FAILED, "derivation failed"))
    assert main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none"]) == 11


def test_exit_code_bootstrap_provisioning_failed(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.BOOTSTRAP_PROVISIONING_FAILED, "provisioning failed"))
    assert main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none"]) == 12


def test_exit_code_connectivity_failed(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.CONNECTIVITY_FAILED, "failed"))
    assert main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"]) == 6


def test_exit_code_doctor_not_ready(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.DOCTOR_NOT_READY, "not ready", doctor_ready=False))
    assert main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "hardware_witness"]) == 7


# --- human vs JSON output --------------------------------------------------


def test_human_output_contains_outcome_detail_digest_and_token(capsys, monkeypatch):
    _canned(
        monkeypatch,
        ApplyResult(
            ApplyOutcome.INSPECT_PLAN_CURRENT,
            "Plan is current.",
            plan_digest="a" * 64,
            confirmation_token="b" * 64,
        ),
    )

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"])

    out = capsys.readouterr().out
    assert "inspect_plan_current" in out
    assert "Plan is current." in out
    assert f"Plan digest: {'a' * 64}" in out
    assert f"Confirmation token: {'b' * 64}" in out


def test_human_output_contains_inline_recovery_detail_and_the_exact_recover_command(capsys, monkeypatch):
    _canned(
        monkeypatch,
        ApplyResult(
            ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED,
            "a prior operation needs attention",
            plan_digest="a" * 64,
            recovery_outcome="recovery_needed",
            recovery_action="revoke_orphan_key",
            recovery_confirmation_token="c" * 64,
        ),
    )

    main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none"])

    out = capsys.readouterr().out
    assert "bootstrap_recovery_required" in out
    assert "Inline recovery inspection outcome: recovery_needed" in out
    assert "Recovery action needed: revoke_orphan_key" in out
    assert f"Recovery confirmation token: {'c' * 64}" in out
    assert f"pfsense-mcp-security recover --execute revoke_orphan_key --confirm {'c' * 64}" in out


def test_json_output_includes_recovery_fields(capsys, monkeypatch):
    _canned(
        monkeypatch,
        ApplyResult(
            ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED,
            "detail",
            plan_digest="a" * 64,
            recovery_outcome="blocked_candidate_not_identifiable",
            recovery_action=None,
            recovery_confirmation_token=None,
        ),
    )

    main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["recovery_outcome"] == "blocked_candidate_not_identifiable"
    assert payload["recovery_action"] is None
    assert payload["recovery_confirmation_token"] is None


def test_json_output_is_valid_and_deterministic(capsys, monkeypatch):
    _canned(
        monkeypatch,
        ApplyResult(
            ApplyOutcome.APPLY_COMPLETED,
            "done",
            plan_digest="a" * 64,
            confirmation_token=None,
            doctor_ready=True,
        ),
    )

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "outcome": "apply_completed",
        "detail": "done",
        "plan_digest": "a" * 64,
        "confirmation_token": None,
        "doctor_ready": True,
        "recovery_outcome": None,
        "recovery_action": None,
        "recovery_confirmation_token": None,
    }


# --- end-to-end: real environment, only the network call stubbed ---------


def test_end_to_end_inspect_then_apply_against_a_real_environment(tmp_path, monkeypatch, capsys):
    confirm_key = tmp_path / "confirm.key"
    _write_secure(confirm_key, b"real-confirm-key-material")
    api_key = tmp_path / "api.key"
    _write_secure(api_key, b"real-api-key-material")

    monkeypatch.setenv("PFSENSE_SETUP_CONFIRM_KEY_FILE", str(confirm_key))
    monkeypatch.setenv("PFSENSE_API_URL", "https://pfsense.example")
    monkeypatch.setenv("PFSENSE_IDENTITY", "admin")
    monkeypatch.setenv("PFSENSE_API_KEY_FILE", str(api_key))

    class _FakeTransport:
        def close(self):
            pass

    class _FakeClient:
        def get_system_status(self, *, include_identifying_metadata=False):
            return object()

    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.build_pfsense_client",
        lambda config, api_key: (_FakeTransport(), _FakeClient()),
    )

    inspect_exit = main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"])
    inspect_payload = json.loads(capsys.readouterr().out)
    assert inspect_exit == 1
    assert inspect_payload["outcome"] == "inspect_plan_current"
    digest = inspect_payload["plan_digest"]
    token = inspect_payload["confirmation_token"]
    assert digest and token

    apply_exit = main(
        [
            "setup",
            "apply",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--plan-digest",
            digest,
            "--confirm",
            token,
            "--json",
        ]
    )
    apply_payload = json.loads(capsys.readouterr().out)
    assert apply_exit == 0
    assert apply_payload["outcome"] == "apply_completed"


def test_end_to_end_next_step_output_prints_the_exact_usable_apply_command(monkeypatch, capsys):
    """The `setup` (non-apply) happy path's own "Next step" output must
    name the real `setup apply` command, not vague future wording --
    this is the exact behavior the design report's own UX requirement
    asks for."""

    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    main(["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none"])
    out = capsys.readouterr().out
    assert "pfsense-mcp-security setup apply" in out
    assert "--capability-posture read_only" in out
    assert "--plan-digest" in out
