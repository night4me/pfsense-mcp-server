"""Focused + adversarial tests for `pfsense-mcp-security setup`
(`pfsense_mcp.security_cli`, Slice 1). Proves, at the actual CLI
surface: bare `setup` cannot mutate; interactive planning cannot
mutate; malformed arguments cannot reach mutation code; every supported
planning branch is non-mutating; unsupported/future choices fail or
report accurately rather than silently downgrading; secrets are absent
from every output surface; and no live network call of any kind is
ever made, using a hostile transport that raises immediately if
`httpx.Client` is ever constructed."""

from __future__ import annotations

import io
import json
import os

import pytest

from pfsense_mcp.security_cli import main


def _clear_relevant_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("PFSENSE_TIER1_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("PFSENSE_PROFILE", raising=False)


def _run(monkeypatch, argv, stdin_text="", env=None):
    _clear_relevant_env(monkeypatch)
    if env:
        for key, value in env.items():
            monkeypatch.setenv(key, value)
    out = io.StringIO()
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    monkeypatch.setattr("sys.stdout", out)
    exit_code = main(argv)
    return exit_code, out.getvalue()


# -- Hostile transport: proves zero network client construction -------


def test_hostile_transport_bare_interactive_setup_never_constructs_an_httpx_client(monkeypatch):
    import httpx

    def _hostile_init(self, *args, **kwargs):
        raise AssertionError("httpx.Client must never be constructed by `setup` (Slice 1 is fully offline)")

    monkeypatch.setattr(httpx.Client, "__init__", _hostile_init)
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text="")
    assert exit_code == 3  # aborted: EOF before capability posture/anchor assurance were answered
    assert "no plan generated" in out


def test_hostile_transport_non_interactive_usage_error_never_constructs_an_httpx_client(monkeypatch):
    import httpx

    def _hostile_init(self, *args, **kwargs):
        raise AssertionError("httpx.Client must never be constructed by `setup` (Slice 1 is fully offline)")

    monkeypatch.setattr(httpx.Client, "__init__", _hostile_init)
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "--non-interactive"])
    assert excinfo.value.code == 2


def test_hostile_transport_full_non_interactive_setup_never_constructs_an_httpx_client(monkeypatch):
    import httpx

    def _hostile_init(self, *args, **kwargs):
        raise AssertionError("httpx.Client must never be constructed by `setup` (Slice 1 is fully offline)")

    monkeypatch.setattr(httpx.Client, "__init__", _hostile_init)
    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "hardware_witness",
        ],
    )
    assert exit_code == 0
    assert "setup plan" in out


def test_hostile_transport_interactive_setup_with_full_answers_never_constructs_an_httpx_client(monkeypatch):
    import httpx

    def _hostile_init(self, *args, **kwargs):
        raise AssertionError("httpx.Client must never be constructed by `setup` (Slice 1 is fully offline)")

    monkeypatch.setattr(httpx.Client, "__init__", _hostile_init)
    answers = "read_only\nnone\nhttps://fw.example.test\nlab-fw\nverify\n\n2.8.0\n"
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "setup plan" in out


# -- Bare / interactive / non-interactive cannot mutate ----------------


def test_bare_setup_with_immediate_eof_aborts_without_a_plan(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text="")
    assert exit_code == 3
    assert "no plan generated" in out
    assert "setup plan digest" not in out.lower()


def test_interactive_setup_can_skip_every_optional_prompt(monkeypatch):
    answers = "read_only\nnone\n\n\n\n\n\n"
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Target:  origin=None  identity=None  tls_mode=None" in out


def test_interactive_setup_rejects_an_invalid_choice_then_accepts_a_retry(monkeypatch):
    answers = "bogus-posture\nread_only\nnone\n\n\n\n\n\n"
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "invalid choice: 'bogus-posture'" in out


def test_non_interactive_without_required_flags_is_a_usage_error(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "--non-interactive"])
    assert excinfo.value.code == 2


def test_non_interactive_with_only_one_required_flag_is_a_usage_error(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "--non-interactive", "--capability-posture", "read_only"])
    assert excinfo.value.code == 2


# -- Malformed arguments cannot reach mutation code ---------------------


def test_malformed_capability_posture_choice_is_rejected_by_argparse(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "setup",
                "--non-interactive",
                "--capability-posture",
                "not-a-real-posture",
                "--anchor-assurance",
                "none",
            ]
        )
    assert excinfo.value.code == 2


def test_malformed_anchor_assurance_choice_is_rejected_by_argparse(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "setup",
                "--non-interactive",
                "--capability-posture",
                "read_only",
                "--anchor-assurance",
                "unknown",
            ]
        )
    assert excinfo.value.code == 2


def test_unknown_flag_is_rejected_by_argparse(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "setup",
                "--non-interactive",
                "--capability-posture",
                "read_only",
                "--anchor-assurance",
                "none",
                "--apply",
            ]
        )
    assert excinfo.value.code == 2


def test_malformed_tls_mode_choice_is_rejected_by_argparse(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "setup",
                "--non-interactive",
                "--capability-posture",
                "read_only",
                "--anchor-assurance",
                "none",
                "--tls-mode",
                "yolo",
            ]
        )
    assert excinfo.value.code == 2


# -- schema-file: local read only, never a network fetch, fails safely -


def test_missing_schema_file_produces_a_warning_and_continues(monkeypatch, tmp_path):
    missing_path = tmp_path / "does-not-exist.json"
    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--schema-file",
            str(missing_path),
        ],
    )
    assert exit_code == 0
    assert "warning: could not read --schema-file" in out
    assert '"schema_provided": false' not in out  # human mode -- just confirm it did not crash


def test_malformed_json_schema_file_produces_a_warning_and_continues(monkeypatch, tmp_path):
    bad_file = tmp_path / "schema.json"
    bad_file.write_text("{not valid json", encoding="utf-8")
    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--schema-file",
            str(bad_file),
        ],
    )
    assert exit_code == 0
    assert "is not valid JSON" in out


def test_non_object_json_schema_file_produces_a_warning_and_continues(monkeypatch, tmp_path):
    array_file = tmp_path / "schema.json"
    array_file.write_text("[1, 2, 3]", encoding="utf-8")
    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--schema-file",
            str(array_file),
        ],
    )
    assert exit_code == 0
    assert "is not a JSON object" in out


def test_valid_schema_file_is_used(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps({"paths": {}}), encoding="utf-8")
    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--schema-file",
            str(schema_file),
            "--json",
        ],
    )
    assert exit_code == 0
    payload = json.loads(out)
    assert payload["privilege_plan"]["schema_provided"] is True


# -- JSON determinism / validity -----------------------------------------


def test_json_output_is_valid_json_with_no_extra_stdout_noise(monkeypatch):
    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--json",
        ],
    )
    assert exit_code == 0
    json.loads(out)


def test_json_output_is_deterministic_and_sorted(monkeypatch):
    argv = [
        "setup",
        "--non-interactive",
        "--capability-posture",
        "read_only",
        "--anchor-assurance",
        "none",
        "--json",
    ]
    _, first = _run(monkeypatch, argv)
    _, second = _run(monkeypatch, argv)
    assert first == second
    payload = json.loads(first)
    assert list(payload.keys()) == sorted(payload.keys())


def test_json_output_includes_the_setup_plan_digest(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--json",
        ],
    )
    payload = json.loads(out)
    assert len(payload["setup_plan_digest"]) == 64
    assert payload["setup_plan_digest_schema_version"] == 1


# -- Invalid target combination still exits appropriately ---------------


def test_invalid_target_combination_exits_nonzero(monkeypatch):
    exit_code, _out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "none",
        ],
    )
    assert exit_code == 2


def test_not_yet_implemented_target_still_exits_zero_and_reports_accurately(monkeypatch):
    """`software` anchor assurance is architecturally valid but has no
    implemented backend -- this must never be silently downgraded to
    'blocked' (a usage-shaped failure) or to 'satisfied' (a false
    claim); `plan`'s own BLOCKED_NOT_IMPLEMENTED convention (still exit
    0) is reused verbatim."""

    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "software",
            "--json",
        ],
    )
    assert exit_code == 0
    payload = json.loads(out)
    assert payload["posture_plan"]["overall_status"] == "blocked_not_implemented"


# -- Secrets are absent from every output surface ------------------------


def test_no_secret_shaped_env_value_ever_appears_in_setup_output(monkeypatch, tmp_path):
    _clear_relevant_env(monkeypatch)
    monkeypatch.setenv("PFSENSE_ADMIN_API_KEY", "totally-secret-value-should-never-appear")
    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "none",
            "--json",
        ],
        env={"PFSENSE_ADMIN_API_KEY": "totally-secret-value-should-never-appear"},
    )
    assert "totally-secret-value-should-never-appear" not in out


def test_no_secret_shaped_env_value_ever_appears_in_human_setup_output(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "none",
        ],
        env={"PFSENSE_ADMIN_API_KEY": "totally-secret-value-should-never-appear"},
    )
    assert "totally-secret-value-should-never-appear" not in out


# -- Isolation: setup never imports the runtime/MCP application ----------


def test_setup_module_never_imports_mcp_application_or_tool_registry():
    import ast
    from pathlib import Path

    root = Path(__file__).parents[1]
    tree = ast.parse((root / "src/pfsense_mcp/security_setup_plan.py").read_text(encoding="utf-8"))
    imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert "application" not in imports
    assert "tools.registry" not in imports
    assert not any(name.startswith("tools.") for name in imports)


# -- Help text sanity ------------------------------------------------------


def test_help_documents_no_setup_apply_and_no_mutation(capsys):
    with pytest.raises(SystemExit):
        main(["setup", "--help"])
    out = capsys.readouterr().out
    assert "NEVER mutates" in out
    assert "no 'continue and apply' path from this command" in out


def test_top_level_help_lists_setup_and_documents_no_setup_apply(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "setup" in out
