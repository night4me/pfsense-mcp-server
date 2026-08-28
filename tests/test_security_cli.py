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


def test_plan_human_output_clarifies_safe_to_proceed_is_not_authorization(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    main(["plan", "--capability-posture", "read_only", "--anchor-assurance", "none"])

    out = capsys.readouterr().out
    assert "Safe to proceed:      True" in out
    assert "not authorization or execution readiness" in out


def test_plan_help_clarifies_safe_to_proceed_meaning(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["plan", "--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "'Safe to proceed' means only" in out
    assert "never authorization, approval, execution-readiness" in out


def test_plan_human_output_shows_plan_digest_clearly(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    main(["plan", "--capability-posture", "read_only", "--anchor-assurance", "none"])

    out = capsys.readouterr().out
    assert "Plan digest (schema v1):" in out
    assert "(plan identity only -- not authorization)" in out
    digest_line = next(line for line in out.splitlines() if line.startswith("Plan digest"))
    digest = digest_line.split(": ", 1)[1].split("  ", 1)[0]
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")


def test_plan_json_output_includes_deterministic_plan_digest(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    main(["plan", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"])
    first = json.loads(capsys.readouterr().out)
    main(["plan", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"])
    second = json.loads(capsys.readouterr().out)

    assert first["plan_digest"] == second["plan_digest"]
    assert len(first["plan_digest"]) == 64
    assert first["plan_digest_schema_version"] == 1


def test_plan_digest_differs_for_a_different_target(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    main(["plan", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"])
    read_only_payload = json.loads(capsys.readouterr().out)
    main(["plan", "--capability-posture", "write_protected", "--anchor-assurance", "software", "--json"])
    write_protected_payload = json.loads(capsys.readouterr().out)

    assert read_only_payload["plan_digest"] != write_protected_payload["plan_digest"]


def test_plan_help_documents_plan_digest_meaning(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["plan", "--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "'Plan digest' is a deterministic identity value" in out
    assert "never authorization, a" in out


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


def test_doctor_default_environment_is_not_ready_human_output(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    exit_code = main(["doctor"])

    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Overall: NOT READY" in out
    assert "NOT CONFIGURED" in out
    assert "Diagnostic only" in out


def test_doctor_read_only_output_explains_the_checks_do_not_apply_to_it(capsys, monkeypatch):
    # v1.0 Product/UX arc: doctor's checks are entirely about the
    # optional write_protected ceremony -- a read-only user (the
    # default) should never read "NOT READY" as a problem with their
    # own access.
    _clear_relevant_env(monkeypatch)

    exit_code = main(["doctor"])

    assert exit_code == 1
    out = capsys.readouterr().out
    assert "read-only access" in out
    assert "do not affect your read-only access" in out
    assert "Overall: NOT READY" in out  # underlying computation unchanged


def test_doctor_write_protected_output_has_no_read_only_reassurance(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)
    monkeypatch.setenv("PFSENSE_PROFILE", "write_protected")

    exit_code = main(["doctor"])

    assert exit_code == 1
    out = capsys.readouterr().out
    assert "do not affect your read-only access" not in out


def test_doctor_json_output_includes_capability_posture(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    main(["doctor", "--json"])
    out = capsys.readouterr().out

    payload = json.loads(out)
    assert payload["capability_posture"] == "read_only"


def test_doctor_json_output_is_valid_and_deterministic(capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)

    exit_code_first = main(["doctor", "--json"])
    first_stdout = capsys.readouterr().out
    exit_code_second = main(["doctor", "--json"])
    second_stdout = capsys.readouterr().out

    assert exit_code_first == 1
    assert exit_code_second == 1
    assert first_stdout == second_stdout

    payload = json.loads(first_stdout)
    assert payload["ready"] is False
    assert len(payload["checks"]) == 5
    assert all(check["status"] == "not_configured" for check in payload["checks"])


def test_doctor_ready_when_artifact_paths_clean_and_witness_verified(tmp_path, capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)
    from tests.test_security_discovery import _WITNESS_ENV, _FakeAnchor, _patch_witness_anchor, _provisioned_store_env

    exchange_dir = tmp_path / "exchange"
    exchange_dir.mkdir()
    monkeypatch.setenv("PFSENSE_TIER1_AUTHORIZATION_INBOX_FILE", str(exchange_dir / "authorization-signed.bin"))
    monkeypatch.setenv("PFSENSE_TIER1_CONFIRMATION_PENDING_FILE", str(exchange_dir / "confirmation-pending.bin"))
    monkeypatch.setenv("PFSENSE_TIER1_CONFIRMATION_SIGNED_FILE", str(exchange_dir / "confirmation-signed.bin"))
    monkeypatch.setenv("PFSENSE_TIER1_AUTHORIZATION_PREVIEW_FILE", str(exchange_dir / "authorization-preview.bin"))

    store_env = _provisioned_store_env(tmp_path, value=2, handle="0x01500000")
    for key, value in {**store_env, **_WITNESS_ENV}.items():
        monkeypatch.setenv(key, value)
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    exit_code = main(["doctor"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Overall: READY" in out
    assert "FAIL" not in out


def test_doctor_stale_artifact_is_not_ready_and_reports_the_path(tmp_path, capsys, monkeypatch):
    _clear_relevant_env(monkeypatch)
    exchange_dir = tmp_path / "exchange"
    exchange_dir.mkdir()
    stale_path = exchange_dir / "confirmation-signed.bin"
    stale_path.write_bytes(b"leftover")
    monkeypatch.setenv("PFSENSE_TIER1_AUTHORIZATION_INBOX_FILE", str(exchange_dir / "authorization-signed.bin"))
    monkeypatch.setenv("PFSENSE_TIER1_CONFIRMATION_PENDING_FILE", str(exchange_dir / "confirmation-pending.bin"))
    monkeypatch.setenv("PFSENSE_TIER1_CONFIRMATION_SIGNED_FILE", str(stale_path))
    monkeypatch.setenv("PFSENSE_TIER1_AUTHORIZATION_PREVIEW_FILE", str(exchange_dir / "authorization-preview.bin"))

    exit_code = main(["doctor"])

    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Overall: NOT READY" in out
    assert str(stale_path) in out
    assert stale_path.read_bytes() == b"leftover"  # doctor never touches it


def test_doctor_never_writes_to_the_configured_artifact_paths(tmp_path, monkeypatch):
    _clear_relevant_env(monkeypatch)
    exchange_dir = tmp_path / "exchange"
    exchange_dir.mkdir()
    paths = {
        "PFSENSE_TIER1_AUTHORIZATION_INBOX_FILE": exchange_dir / "authorization-signed.bin",
        "PFSENSE_TIER1_CONFIRMATION_PENDING_FILE": exchange_dir / "confirmation-pending.bin",
        "PFSENSE_TIER1_CONFIRMATION_SIGNED_FILE": exchange_dir / "confirmation-signed.bin",
        "PFSENSE_TIER1_AUTHORIZATION_PREVIEW_FILE": exchange_dir / "authorization-preview.bin",
    }
    for name, path in paths.items():
        monkeypatch.setenv(name, str(path))

    main(["doctor"])

    assert not any(path.exists() for path in paths.values())
