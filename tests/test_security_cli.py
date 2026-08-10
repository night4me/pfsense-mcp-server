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
