from __future__ import annotations

import ast
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from lab.config import LabConfig, LabConfigError, load_lab_key_material, normalize_lab_candidate
from lab.safety import (
    ATTESTATION_SCHEMA_VERSION,
    LabSafetyError,
    load_lab_attestation,
    render_dry_run,
    render_evidence,
    run_read_only_preflight,
)
from pfsense_mcp.models.firewall import FirewallRule
from pfsense_mcp.models.firewall_alias import FirewallAlias
from pfsense_mcp.models.firewall_nat_port_forward import FirewallNatPortForward

NOW = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)
CANDIDATE = "LAB_ADR026_ALIAS"


def _config(tmp_path: Path) -> LabConfig:
    return LabConfig(
        base_url="https://alias-evidence.lab.invalid",
        identity="lab-adr026",
        key_file=tmp_path / "lab.key",
        candidate=CANDIDATE,
        attestation_file=tmp_path / "attestation.json",
    )


def _attestation_data(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "lab_identity": "lab-adr026",
        "candidate": CANDIDATE,
        "issued_at": "2026-08-11T11:55:00Z",
        "expires_at": "2026-08-11T12:05:00Z",
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
    value.update(changes)
    return value


def _load(tmp_path: Path, value: dict[str, object] | None = None, *, now: datetime = NOW):
    config = _config(tmp_path)
    return load_lab_attestation(config, now=now, reader=lambda _path: _attestation_data() if value is None else value)


def _alias(name: str = CANDIDATE) -> FirewallAlias:
    return FirewallAlias(descr="synthetic", id=7, name=name, type="host", address=["192.0.2.9"], detail=[""])


def _rule(source: str = "any", destination: str = "any") -> FirewallRule:
    return FirewallRule.model_construct(source=source, destination=destination)


def _nat(source: str = "any", destination: str = "wanip", target: str = "192.0.2.9") -> FirewallNatPortForward:
    return FirewallNatPortForward.model_construct(source=source, destination=destination, target=target)


class _Client:
    def __init__(self) -> None:
        self.aliases: list[FirewallAlias] = [_alias()]
        self.rules: list[FirewallRule] = [_rule()]
        self.nat: list[FirewallNatPortForward] = [_nat()]
        self.calls: list[str] = []
        self.failure: str | None = None

    def get_firewall_aliases(self, *, include_identifying_metadata: bool = False, limit: int = 100):
        self.calls.append("aliases")
        if self.failure == "aliases":
            raise RuntimeError("sensitive backend detail")
        assert include_identifying_metadata is True
        assert limit == 500
        return self.aliases

    def get_firewall_rules(self, *, include_identifying_metadata: bool = False):
        self.calls.append("rules")
        if self.failure == "rules":
            raise RuntimeError("sensitive backend detail")
        assert include_identifying_metadata is True
        return self.rules

    def get_firewall_nat_port_forwards(self, *, include_identifying_metadata: bool = False, limit: int = 100):
        self.calls.append("nat")
        if self.failure == "nat":
            raise RuntimeError("sensitive backend detail")
        assert include_identifying_metadata is True
        assert limit == 500
        return self.nat


def test_valid_exact_attestation(tmp_path):
    attestation = _load(tmp_path)
    assert attestation.candidate == CANDIDATE
    assert attestation.expires_at == NOW + timedelta(minutes=5)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"schema_version": 2}, "schema"),
        ({"lab_identity": "another-lab"}, "identity"),
        ({"candidate": "LAB_OTHER_ALIAS"}, "candidate"),
        ({"candidate": "LAB_ADR026"}, "candidate"),
        ({"candidate": "*"}, "candidate"),
        ({"issued_at": "bad"}, "issued_at"),
        ({"issued_at": None}, "issued_at"),
        ({"issued_at": "2026-08-11T12:01:00Z"}, "future"),
        ({"expires_at": "2026-08-11T11:59:59Z"}, "expired"),
        ({"expires_at": "bad"}, "expires_at"),
        ({"target_is_disposable_lab": False}, "statement"),
        ({"candidate_is_synthetic_test_only": False}, "statement"),
        ({"verified_no_operational_references": False}, "statement"),
        ({"operator_checked_surfaces": ["routing"]}, "surface"),
    ],
)
def test_attestation_rejects_invalid_or_nonmatching_data(tmp_path, changes, message):
    with pytest.raises(LabSafetyError, match=message):
        _load(tmp_path, _attestation_data(**changes))


def test_attestation_rejects_missing_field(tmp_path):
    value = _attestation_data()
    del value["issued_at"]
    with pytest.raises(LabSafetyError, match="fields"):
        _load(tmp_path, value)


def test_attestation_rejects_extra_field(tmp_path):
    with pytest.raises(LabSafetyError, match="fields"):
        _load(tmp_path, _attestation_data(unexpected=True))


def test_attestation_rejects_validity_longer_than_ten_minutes(tmp_path):
    with pytest.raises(LabSafetyError, match="10 minutes"):
        _load(tmp_path, _attestation_data(expires_at="2026-08-11T12:06:00Z"))


def test_secure_attestation_file_rejects_missing_and_malformed_documents(tmp_path):
    config = _config(tmp_path)
    with pytest.raises(LabSafetyError, match="opened"):
        load_lab_attestation(config, now=NOW)
    config.attestation_file.write_text("not-json")
    config.attestation_file.chmod(0o600)
    with pytest.raises(LabSafetyError, match="JSON"):
        load_lab_attestation(config, now=NOW)


def test_secure_attestation_file_loads_valid_json(tmp_path):
    config = _config(tmp_path)
    config.attestation_file.write_text(json.dumps(_attestation_data()))
    config.attestation_file.chmod(0o600)
    assert load_lab_attestation(config, now=NOW).lab_identity == config.identity


def test_candidate_normalization_is_exact_and_no_wildcards():
    assert normalize_lab_candidate(CANDIDATE) == CANDIDATE
    for invalid in ("", "*", "LAB_*", "prefix", " LAB_ALIAS", "LAB-ALIAS", "TEST_"):
        with pytest.raises(LabConfigError):
            normalize_lab_candidate(invalid)


def test_changed_candidate_requires_new_attestation(tmp_path):
    config = _config(tmp_path)
    changed = LabConfig(
        base_url=config.base_url,
        identity=config.identity,
        key_file=config.key_file,
        candidate="LAB_CHANGED_ALIAS",
        attestation_file=config.attestation_file,
    )
    with pytest.raises(LabSafetyError, match="candidate"):
        load_lab_attestation(changed, now=NOW, reader=lambda _path: _attestation_data())


def test_clean_automatic_checks_and_valid_attestation_pass(tmp_path):
    client = _Client()
    report = run_read_only_preflight(_config(tmp_path), client=client, attestation=_load(tmp_path), now=lambda: NOW)
    assert report.passed is True
    assert client.calls == ["aliases", "rules", "nat"]
    assert [check.surface for check in report.dependency_checks] == ["firewall_rules", "nat_port_forwards"]
    assert all(check.complete and not check.references_found for check in report.dependency_checks)


@pytest.mark.parametrize(
    ("surface", "field"),
    [("rule", "source"), ("rule", "destination"), ("nat", "source"), ("nat", "destination"), ("nat", "target")],
)
def test_positive_automatic_dependency_overrides_valid_attestation(tmp_path, surface, field):
    client = _Client()
    if surface == "rule":
        values = {"source": "any", "destination": "any", field: f"!{CANDIDATE}"}
        client.rules = [_rule(**values)]
    else:
        values = {"source": "any", "destination": "wanip", "target": "192.0.2.9", field: CANDIDATE}
        client.nat = [_nat(**values)]
    with pytest.raises(LabSafetyError, match="reference"):
        run_read_only_preflight(_config(tmp_path), client=client, attestation=_load(tmp_path), now=lambda: NOW)


@pytest.mark.parametrize("surface", ["rules", "nat"])
def test_dependency_query_failure_overrides_valid_attestation(tmp_path, surface):
    client = _Client()
    client.failure = surface
    with pytest.raises(LabSafetyError, match="query failed") as raised:
        run_read_only_preflight(_config(tmp_path), client=client, attestation=_load(tmp_path), now=lambda: NOW)
    assert "sensitive backend detail" not in str(raised.value)


def test_malformed_dependency_result_overrides_valid_attestation(tmp_path):
    client = _Client()
    client.rules = [object()]  # type: ignore[list-item]
    with pytest.raises(LabSafetyError, match="malformed"):
        run_read_only_preflight(_config(tmp_path), client=client, attestation=_load(tmp_path), now=lambda: NOW)


def test_bounded_enumeration_fails_closed(tmp_path):
    client = _Client()
    client.nat = [_nat()] * 500
    with pytest.raises(LabSafetyError, match="incomplete"):
        run_read_only_preflight(_config(tmp_path), client=client, attestation=_load(tmp_path), now=lambda: NOW)


@pytest.mark.parametrize(
    "aliases", [[], [_alias(), _alias()], [FirewallAlias(descr="x", id=1, name=CANDIDATE, type="host")]]
)
def test_candidate_resolution_rejects_zero_duplicate_or_incomplete(tmp_path, aliases):
    client = _Client()
    client.aliases = aliases
    with pytest.raises(LabSafetyError):
        run_read_only_preflight(_config(tmp_path), client=client, attestation=_load(tmp_path), now=lambda: NOW)


def test_expired_attestation_never_reaches_network_client(tmp_path):
    with pytest.raises(LabSafetyError, match="expired"):
        _load(tmp_path, now=NOW + timedelta(minutes=6))


def test_attestation_expiring_during_checks_fails_closed(tmp_path):
    client = _Client()
    times = iter((NOW, NOW + timedelta(minutes=6)))
    with pytest.raises(LabSafetyError, match="expired during"):
        run_read_only_preflight(_config(tmp_path), client=client, attestation=_load(tmp_path), now=lambda: next(times))


def test_dry_run_and_evidence_are_sanitized_and_do_not_send(tmp_path):
    client = _Client()
    report = run_read_only_preflight(_config(tmp_path), client=client, attestation=_load(tmp_path), now=lambda: NOW)
    dry_run = json.loads(render_dry_run(report, test_case_id="case-01"))
    evidence = json.loads(render_evidence("preflight", report))
    assert dry_run["operation"]["sent"] is False
    assert dry_run["operation"]["method"] == "PATCH"
    assert evidence["combined_disposable_lab_safety_gate"] == "PASS"
    assert evidence["global_dependency_proof"] is False
    assert client.calls == ["aliases", "rules", "nat"]
    serialized = render_evidence("preflight", report)
    assert "192.0.2.9" not in serialized
    assert "address" not in serialized


def test_key_secret_never_appears_in_config_repr_exception_or_evidence(tmp_path):
    secret = "lab-super-secret-value"
    config = _config(tmp_path)
    config.key_file.write_text(secret)
    config.key_file.chmod(0o600)
    assert load_lab_key_material(config.key_file) == secret
    assert secret not in repr(config)
    client = _Client()
    report = run_read_only_preflight(config, client=client, attestation=_load(tmp_path), now=lambda: NOW)
    assert secret not in render_evidence("preflight", report)


def test_lab_safety_isolation_from_production_write_and_authorization_modules():
    root = Path(__file__).parents[1]
    forbidden = {
        "pfsense_mcp.application",
        "pfsense_mcp.server",
        "pfsense_mcp.write_endpoints",
        "pfsense_mcp.write_api_client",
        "pfsense_mcp.security_authorization",
        "pfsense_mcp.tier1.execution_coordinator",
        "pfsense_mcp.tier1.executor",
        "pfsense_mcp.tier1.state_machine",
        "pfsense_mcp.tier1.store",
    }
    for module in (root / "config.py", root / "safety.py", root / "cli.py"):
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imports |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        assert imports.isdisjoint(forbidden)


def test_production_package_does_not_import_lab_modules():
    source_root = Path(__file__).parents[2] / "src" / "pfsense_mcp"
    for module in source_root.rglob("*.py"):
        assert "from lab" not in module.read_text(encoding="utf-8")
        assert "import lab" not in module.read_text(encoding="utf-8")
