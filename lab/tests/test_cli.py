from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from lab import cli
from pfsense_mcp.models.firewall import FirewallRule
from pfsense_mcp.models.firewall_alias import FirewallAlias
from pfsense_mcp.models.firewall_nat_port_forward import FirewallNatPortForward


def test_evidence_env_reports_presence_without_values(monkeypatch, capsys):
    for name in (
        "PFSENSE_LAB_API_URL",
        "PFSENSE_LAB_IDENTITY",
        "PFSENSE_LAB_API_KEY_FILE",
        "PFSENSE_LAB_CANDIDATE",
        "PFSENSE_LAB_ATTESTATION_FILE",
    ):
        monkeypatch.setenv(name, "sensitive-value")
    assert cli.main(["evidence-env"]) == 0
    output = capsys.readouterr().out
    assert "sensitive-value" not in output
    result = json.loads(output)
    assert all(result["configured"].values())
    assert result["preflight_ready"] is False


def test_invalid_config_fails_before_transport_construction(monkeypatch, capsys):
    monkeypatch.delenv("PFSENSE_LAB_API_URL", raising=False)
    constructed = False

    class _ForbiddenTransport:
        def __init__(self, *args, **kwargs):
            nonlocal constructed
            constructed = True

    monkeypatch.setattr(cli, "HttpTransport", _ForbiddenTransport)
    assert cli.main(["preflight"]) == 2
    assert constructed is False
    status = json.loads(capsys.readouterr().err)
    assert status["lab_provenance"] == "FAIL"
    assert status["combined_disposable_lab_safety_gate"] == "FAIL"


def test_invalid_attestation_fails_before_transport_construction(monkeypatch, tmp_path, capsys):
    key = tmp_path / "lab.key"
    key.write_text("secret")
    key.chmod(0o600)
    attestation = tmp_path / "attestation.json"
    attestation.write_text("not json")
    attestation.chmod(0o600)
    env = {
        "PFSENSE_LAB_API_URL": "https://candidate.lab.invalid",
        "PFSENSE_LAB_IDENTITY": "lab-cli",
        "PFSENSE_LAB_API_KEY_FILE": str(key),
        "PFSENSE_LAB_CANDIDATE": "LAB_CLI_ALIAS",
        "PFSENSE_LAB_ATTESTATION_FILE": str(attestation),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    constructed = False

    class _ForbiddenTransport:
        def __init__(self, *args, **kwargs):
            nonlocal constructed
            constructed = True

    monkeypatch.setattr(cli, "HttpTransport", _ForbiddenTransport)
    assert cli.main(["dry-run"]) == 2
    assert constructed is False
    status = json.loads(capsys.readouterr().err)
    assert status["lab_provenance"] == "PASS"
    assert status["credential_availability"] == "PASS"
    assert status["operator_attestation"] == "INVALID"
    assert "secret" not in json.dumps(status)


def test_valid_dry_run_uses_only_read_client_methods(monkeypatch, tmp_path, capsys):
    key = tmp_path / "lab.key"
    key.write_text("secret-not-for-output")
    key.chmod(0o600)
    issued = datetime.now(timezone.utc)
    attestation = tmp_path / "attestation.json"
    attestation.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "lab_identity": "lab-cli",
                "candidate": "LAB_CLI_ALIAS",
                "issued_at": issued.isoformat().replace("+00:00", "Z"),
                "expires_at": (issued + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "target_is_disposable_lab": True,
                "candidate_is_synthetic_test_only": True,
                "verified_no_operational_references": True,
                "operator_checked_surfaces": [
                    "routing",
                    "vpn",
                    "services",
                    "firewall_policy",
                    "nat",
                    "other_operational_configuration",
                ],
            }
        )
    )
    attestation.chmod(0o600)
    env = {
        "PFSENSE_LAB_API_URL": "https://candidate.lab.invalid",
        "PFSENSE_LAB_IDENTITY": "lab-cli",
        "PFSENSE_LAB_API_KEY_FILE": str(key),
        "PFSENSE_LAB_CANDIDATE": "LAB_CLI_ALIAS",
        "PFSENSE_LAB_ATTESTATION_FILE": str(attestation),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    class _Transport:
        def __init__(self, *args, **kwargs):
            self.closed = False

        def close(self):
            self.closed = True

    class _ReadClient:
        def __init__(self, _rest):
            self.calls: list[str] = []

        def get_firewall_aliases(self, **kwargs):
            self.calls.append("GET aliases")
            return [
                FirewallAlias(
                    descr="synthetic", id=3, name="LAB_CLI_ALIAS", type="host", address=["192.0.2.3"], detail=[""]
                )
            ]

        def get_firewall_rules(self, **kwargs):
            self.calls.append("GET rules")
            return [FirewallRule.model_construct(source="any", destination="any")]

        def get_firewall_nat_port_forwards(self, **kwargs):
            self.calls.append("GET nat")
            return [FirewallNatPortForward.model_construct(source="any", destination="wanip", target="192.0.2.3")]

    monkeypatch.setattr(cli, "HttpTransport", _Transport)
    monkeypatch.setattr(cli, "PfSenseClient", _ReadClient)
    assert cli.main(["dry-run", "--test-case-id", "case-01"]) == 0
    output = capsys.readouterr().out
    assert '"sent":false' in output
    assert "secret-not-for-output" not in output
