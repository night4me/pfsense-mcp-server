"""Slice 7 automation-hardening tests for `pfsense-mcp-security setup
apply` -- proves the specific properties the design report's own §20
item 7 and this run's own automation-hardening checklist name, that
are not already covered by `tests/test_security_cli_setup_apply.py`
(exit-code mapping, JSON/human formatting, the `--confirm -`/env-var
mechanisms), `tests/test_security_setup_apply.py`/
`tests/test_security_setup_apply_write_protected.py`/
`tests/test_security_setup_apply_inline_recovery.py` (orchestration-
level staleness/token/posture/RECOVERY_REQUIRED/redaction proofs), or
`tests/test_security_bootstrap_orchestration.py`/
`tests/test_security_recovery_orchestration.py` (crash-safety, lock/
journal semantics, no-auto-retry -- all unchanged, untouched by this
slice, not re-tested here).

Most of the fourteen properties this run's own checklist names already
hold by construction from Slices 2-4; this file adds targeted,
non-duplicative proof for the ones that were not yet specifically
exercised at the CLI surface: zero stdin dependency unless `--confirm
-` is explicit, at-most-once composition of each orchestration
function per invocation (no blind retry inside the CLI layer itself),
malformed free-text `--plan-digest`/`--confirm` values never reaching
an unhandled exception, and byte-for-byte deterministic repeated
`--json` output."""

from __future__ import annotations

import io
import json

from pfsense_mcp import security_cli
from pfsense_mcp.security_cli import main
from pfsense_mcp.security_setup_apply import ApplyOutcome, ApplyResult


def _canned(monkeypatch, result: ApplyResult) -> list[dict[str, object]]:
    """Mirrors `test_security_cli_setup_apply.py`'s own `_canned()`,
    but records every call (a list, not a single dict) so tests can
    assert an exact call *count*, not just the most recent call's
    arguments."""

    calls: list[dict[str, object]] = []

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
        calls.append(
            {
                "target_capability_posture": target_capability_posture,
                "target_anchor_assurance": target_anchor_assurance,
                "target_origin": target_origin,
                "target_identity": target_identity,
                "tls_mode": tls_mode,
                "plan_digest": plan_digest,
                "confirm_token": confirm_token,
            }
        )
        return result

    monkeypatch.setattr(security_cli, "run_setup_apply_from_environment", fake)
    return calls


# --- property 1/2: deterministic, no interactive prompt dependency ---------


def _install_hostile_stdin(monkeypatch):
    """A stdin that raises the moment anything reads from it -- proves
    `setup apply` never blocks on or consumes stdin unless `--confirm
    -` was explicitly requested."""

    class _HostileStdin(io.StringIO):
        def readline(self, *args, **kwargs):
            raise AssertionError("setup apply must never read stdin unless --confirm - was given")

        def read(self, *args, **kwargs):
            raise AssertionError("setup apply must never read stdin unless --confirm - was given")

    monkeypatch.setattr("sys.stdin", _HostileStdin())


def test_inspect_mode_never_touches_stdin(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.INSPECT_PLAN_CURRENT, "detail"))
    _install_hostile_stdin(monkeypatch)

    exit_code = main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"])

    assert exit_code == 1


def test_explicit_confirm_flag_never_touches_stdin(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.APPLY_COMPLETED, "done"))
    _install_hostile_stdin(monkeypatch)

    exit_code = main(
        [
            "setup",
            "apply",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--confirm",
            "explicit-token",
        ]
    )

    assert exit_code == 0


def test_env_var_confirm_never_touches_stdin(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.APPLY_COMPLETED, "done"))
    _install_hostile_stdin(monkeypatch)
    monkeypatch.setenv("PFSENSE_SETUP_APPLY_CONFIRM_TOKEN", "token-from-env")

    exit_code = main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none"])

    assert exit_code == 0


def test_confirm_dash_is_the_only_path_that_reads_stdin(monkeypatch):
    calls = _canned(monkeypatch, ApplyResult(ApplyOutcome.APPLY_COMPLETED, "done"))
    monkeypatch.setattr("sys.stdin", io.StringIO("real-stdin-token\n"))

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none", "--confirm", "-"])

    assert calls[-1]["confirm_token"] == "real-stdin-token"


# --- property 9: no blind retry (at most one orchestration call per --------
# --- CLI invocation, for every outcome, success or failure) ----------------


def test_orchestration_is_composed_exactly_once_on_success(monkeypatch):
    calls = _canned(monkeypatch, ApplyResult(ApplyOutcome.APPLY_COMPLETED, "done"))

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none", "--confirm", "t"])

    assert len(calls) == 1


def test_orchestration_is_composed_exactly_once_on_bootstrap_failure(monkeypatch):
    calls = _canned(monkeypatch, ApplyResult(ApplyOutcome.BOOTSTRAP_PROVISIONING_FAILED, "failed"))

    main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none", "--confirm", "t"])

    assert len(calls) == 1


def test_orchestration_is_composed_exactly_once_on_recovery_required(monkeypatch):
    calls = _canned(monkeypatch, ApplyResult(ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED, "blocked"))

    main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none", "--confirm", "t"])

    assert len(calls) == 1


def test_two_separate_cli_invocations_each_compose_exactly_once_no_automatic_loop(monkeypatch):
    """A caller re-running the command twice (e.g. a CI retry step) is
    two independent, single-call invocations -- proves there is no
    hidden retry loop inside `_run_setup_apply()` itself."""

    calls = _canned(monkeypatch, ApplyResult(ApplyOutcome.BOOTSTRAP_LOCK_CONTENTION, "locked"))

    main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none", "--confirm", "t"])
    main(["setup", "apply", "--capability-posture", "write_protected", "--anchor-assurance", "none", "--confirm", "t"])

    assert len(calls) == 2


# --- malformed machine input never reaches an unhandled exception ----------


def test_malformed_plan_digest_free_text_does_not_crash(monkeypatch):
    calls = _canned(monkeypatch, ApplyResult(ApplyOutcome.PLAN_STALE, "stale", plan_digest="a" * 64))

    exit_code = main(
        [
            "setup",
            "apply",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--plan-digest",
            "not-hex-at-all!!! \x00\x01",
            "--confirm",
            "t",
        ]
    )

    assert exit_code == 2
    assert calls[-1]["plan_digest"] == "not-hex-at-all!!! \x00\x01"


def test_malformed_confirm_free_text_does_not_crash(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.CONFIRM_TOKEN_INVALID, "invalid"))

    exit_code = main(
        [
            "setup",
            "apply",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--confirm",
            "\x00\x01\x02 not a real token 😀",
        ]
    )

    assert exit_code == 3


def test_empty_string_plan_digest_does_not_crash(monkeypatch):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.PLAN_STALE, "stale"))

    exit_code = main(
        [
            "setup",
            "apply",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--plan-digest",
            "",
            "--confirm",
            "t",
        ]
    )

    assert exit_code == 2


# --- JSON output stability (byte-for-byte deterministic repeats) -----------


def test_json_output_is_byte_identical_across_repeated_invocations(monkeypatch, capsys):
    _canned(
        monkeypatch,
        ApplyResult(
            ApplyOutcome.BOOTSTRAP_COMPLETED,
            "provisioned",
            plan_digest="a" * 64,
            doctor_ready=True,
        ),
    )

    main(
        [
            "setup",
            "apply",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "none",
            "--confirm",
            "t",
            "--json",
        ]
    )
    first = capsys.readouterr().out

    main(
        [
            "setup",
            "apply",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "none",
            "--confirm",
            "t",
            "--json",
        ]
    )
    second = capsys.readouterr().out

    assert first == second
    assert json.loads(first) == json.loads(second)


def test_json_output_key_order_is_deterministic(monkeypatch, capsys):
    _canned(monkeypatch, ApplyResult(ApplyOutcome.APPLY_COMPLETED, "done", plan_digest="a" * 64))

    main(["setup", "apply", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"])
    out = capsys.readouterr().out

    lines = [line for line in out.splitlines() if ":" in line]
    keys = [line.split(":", 1)[0].strip().strip('"') for line in lines]
    assert keys == sorted(keys)
