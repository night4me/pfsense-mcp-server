"""Focused tests for `pfsense_mcp.security_cli` -- the actual
`pfsense-mcp-security` entrypoint. Exercises the CLI surface (argument
parsing, human/--json output, exit codes) against the real environment
and against monkeypatched discovery results, without touching the
network or any TPM/pfSense state.
"""

from __future__ import annotations

import json
import os

import pytest

from pfsense_mcp.security_cli import main


def _clear_relevant_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("PFSENSE_TIER1_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("PFSENSE_PROFILE", raising=False)


def test_discover_default_environment_human_output(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    exit_code = main(["discover"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Capability posture: read_only" in out
    assert "Anchor assurance:    none" in out
    assert "read-only discovery only" in out


def test_discover_json_output_is_valid_and_deterministic(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    exit_code_first = main(["discover", "--json"])
    first_stdout = capsys.readouterr().out
    exit_code_second = main(["discover", "--json"])
    second_stdout = capsys.readouterr().out

    assert exit_code_first == 0
    assert exit_code_second == 0
    assert first_stdout == second_stdout  # byte-identical -- deterministic

    payload = json.loads(first_stdout)
    assert payload["capability_posture"]["value"] == "read_only"
    assert payload["anchor_assurance"]["value"] == "none"
    assert payload["anchor_assurance"]["evidence_state"] == "unconfigured"
    assert isinstance(payload["notes"], list) and payload["notes"]

    # sort_keys=True -- assert the raw text is actually alphabetically
    # sorted at the top level, not just semantically equal after parsing.
    assert list(payload.keys()) == sorted(payload.keys())


def test_discover_json_is_valid_json_with_no_extra_stdout_noise(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    main(["discover", "--json"])
    out = capsys.readouterr().out
    json.loads(out)  # raises if anything besides the JSON document was printed


def test_mismatch_state_exits_with_nonzero_status(monkeypatch, capsys):
    import pfsense_mcp.security_cli as module
    from pfsense_mcp.security_discovery import (
        AnchorAssurance,
        AnchorAssuranceDiscovery,
        AnchorEvidenceState,
        CapabilityPosture,
        CapabilityPostureDiscovery,
        SecurityPostureDiscovery,
    )

    fake_discovery = SecurityPostureDiscovery(
        capability_posture=CapabilityPostureDiscovery(
            value=CapabilityPosture.READ_ONLY,
            configured_profile_name="auditor",
            configured_profile_valid=True,
            write_capabilities_active=0,
            write_capabilities_total=3,
            allow_list_entries=(),
            evidence=(),
        ),
        anchor_assurance=AnchorAssuranceDiscovery(
            value=AnchorAssurance.HARDWARE_WITNESS,
            evidence_state=AnchorEvidenceState.PROVISIONED_MISMATCH,
            store_configured=True,
            store_exists=True,
            seeded=True,
            complete=True,
            handle="0x01500000",
            baseline=2,
            provisioned_at="2026-08-10T15:10:16Z",
            witness_configured=True,
            witness_reachable=True,
            witness_value=7,
            witness_matches_baseline=False,
            evidence=("mismatch",),
        ),
    )
    monkeypatch.setattr(module, "discover_security_posture", lambda env: fake_discovery)

    exit_code = main(["discover"])

    assert exit_code == 2
    assert "WARNING" in capsys.readouterr().out


def test_no_subcommand_exits_nonzero():
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2


def test_discover_help_documents_the_exit_code_contract(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["discover", "--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "Exit codes" in out
    assert "provisioned_mismatch" in out


def test_help_exits_zero():
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0


# ---------------------------------------------------------------------------
# `plan` subcommand
# ---------------------------------------------------------------------------


def test_plan_default_environment_human_output(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    exit_code = main(["plan", "--capability-posture", "read_only", "--anchor-assurance", "none"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "analysis only -- not authorization" in out
    assert "Overall status:       already_satisfied" in out
    assert "NOT authorization to execute" in out


def test_plan_json_output_is_valid_and_deterministic(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    main(["plan", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"])
    first_stdout = capsys.readouterr().out
    main(["plan", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"])
    second_stdout = capsys.readouterr().out

    assert first_stdout == second_stdout
    payload = json.loads(first_stdout)
    assert payload["overall_status"] == "already_satisfied"
    assert payload["safe_to_proceed"] is True
    assert payload["target"] == {"capability_posture": "read_only", "anchor_assurance": "none"}
    assert list(payload.keys()) == sorted(payload.keys())
    assert isinstance(payload["steps"], list) and payload["steps"]
    for step in payload["steps"]:
        assert list(step.keys()) == sorted(step.keys())


def test_plan_invalid_combination_exits_nonzero(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    exit_code = main(["plan", "--capability-posture", "write_protected", "--anchor-assurance", "none"])

    assert exit_code == 2
    out = capsys.readouterr().out
    assert "invalid_combination" in out


def test_plan_rejects_unknown_anchor_assurance_as_a_cli_choice():
    with pytest.raises(SystemExit) as excinfo:
        main(["plan", "--capability-posture", "read_only", "--anchor-assurance", "unknown"])
    assert excinfo.value.code == 2


def test_plan_requires_both_target_flags():
    with pytest.raises(SystemExit) as excinfo:
        main(["plan", "--capability-posture", "read_only"])
    assert excinfo.value.code == 2


def test_plan_help_documents_exit_codes_and_non_authorization(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["plan", "--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "Exit codes" in out
    assert "not execution authorization" in out
    assert "no subsequent 'apply this plan' command exists" in out


def test_plan_mismatch_state_exits_with_nonzero_status(monkeypatch, capsys):
    import pfsense_mcp.security_cli as module
    from pfsense_mcp.security_discovery import (
        AnchorAssurance,
        AnchorAssuranceDiscovery,
        AnchorEvidenceState,
        CapabilityPosture,
        CapabilityPostureDiscovery,
        SecurityPostureDiscovery,
    )

    fake_discovery = SecurityPostureDiscovery(
        capability_posture=CapabilityPostureDiscovery(
            value=CapabilityPosture.READ_ONLY,
            configured_profile_name="auditor",
            configured_profile_valid=True,
            write_capabilities_active=0,
            write_capabilities_total=3,
            allow_list_entries=(),
            evidence=(),
        ),
        anchor_assurance=AnchorAssuranceDiscovery(
            value=AnchorAssurance.HARDWARE_WITNESS,
            evidence_state=AnchorEvidenceState.PROVISIONED_MISMATCH,
            store_configured=True,
            store_exists=True,
            seeded=True,
            complete=True,
            handle="0x01500000",
            baseline=2,
            provisioned_at="2026-08-10T15:10:16Z",
            witness_configured=True,
            witness_reachable=True,
            witness_value=7,
            witness_matches_baseline=False,
            evidence=("mismatch",),
        ),
    )
    import pfsense_mcp.security_plan as plan_module

    monkeypatch.setattr(plan_module, "discover_security_posture", lambda env=None: fake_discovery)

    exit_code = module.main(["plan", "--capability-posture", "read_only", "--anchor-assurance", "hardware_witness"])

    assert exit_code == 2
    out = capsys.readouterr().out
    assert "blocked_anomaly_detected" in out


def test_plan_indeterminate_current_state_exits_with_nonzero_status(tmp_path, capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    malformed = store_dir / "anchor.sqlite3"
    malformed.write_bytes(b"not a sqlite database")
    os.chmod(malformed, 0o600)
    key_dir = tmp_path / "key"
    key_dir.mkdir(mode=0o700)
    key_file = key_dir / "integrity.json"
    key_file.write_text('{"key_id": "x", "epoch": 0, "material_hex": "' + "ab" * 32 + '"}')
    os.chmod(key_file, 0o600)
    monkeypatch.setenv("PFSENSE_TIER1_STORE_PATH", str(malformed))
    monkeypatch.setenv("PFSENSE_TIER1_STORE_KEY_FILE", str(key_file))

    exit_code = main(["plan", "--capability-posture", "read_only", "--anchor-assurance", "hardware_witness"])

    assert exit_code == 2
    out = capsys.readouterr().out
    assert "blocked_indeterminate_current_state" in out
