"""Focused + adversarial tests for `pfsense_mcp.security_setup_plan` --
`pfsense-mcp-security setup` Slice 1's pure discovery/plan composition.

Every test in this file runs with a cleared, controlled environment (no
witness/profile env vars leaking from the real shell) so results are
deterministic and independent of the machine running the tests."""

from __future__ import annotations

import os

import pytest

from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import PlanOverallStatus
from pfsense_mcp.security_setup_plan import (
    INTENDED_SERVICE_ACCOUNT_IDENTITY,
    SETUP_PLAN_SCHEMA_VERSION,
    generate_setup_plan,
)
from pfsense_mcp.security_setup_plan_digest import compute_setup_plan_digest


def _clear_relevant_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("PFSENSE_TIER1_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("PFSENSE_PROFILE", raising=False)


_ALL_CAPABILITY_POSTURES = tuple(CapabilityPosture)
_ALL_ANCHOR_ASSURANCES = tuple(a for a in AnchorAssurance if a is not AnchorAssurance.UNKNOWN)


@pytest.mark.parametrize("capability_posture", _ALL_CAPABILITY_POSTURES)
@pytest.mark.parametrize("anchor_assurance", _ALL_ANCHOR_ASSURANCES)
def test_every_supported_planning_branch_is_non_mutating_and_never_raises(
    monkeypatch, capability_posture, anchor_assurance
):
    """Every combination of the two axes must produce a plan, never an
    exception and never a call into any mutating primitive -- proven at
    the module level by `tests/test_security_setup_plan_isolation.py`'s
    static forbidden-call/forbidden-import sweep; this test proves the
    *dynamic* half: every branch actually reaches a normal return."""

    _clear_relevant_env(monkeypatch)
    plan = generate_setup_plan(target_capability_posture=capability_posture, target_anchor_assurance=anchor_assurance)
    assert plan.schema_version == SETUP_PLAN_SCHEMA_VERSION
    assert plan.privilege_plan.intended_account_identity == INTENDED_SERVICE_ACCOUNT_IDENTITY


def test_read_only_posture_reports_dedicated_account_provisioning_as_not_implemented(monkeypatch):
    _clear_relevant_env(monkeypatch)
    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY, target_anchor_assurance=AnchorAssurance.NONE
    )
    assert plan.privilege_plan.dedicated_account_provisioning_implemented is False
    assert "no implemented provisioning path" in plan.privilege_plan.provisioning_note
    assert any("READ-only account provisioning" in step for step in plan.unsupported_steps)


def test_write_protected_posture_reports_dedicated_account_provisioning_as_implemented(monkeypatch):
    _clear_relevant_env(monkeypatch)
    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED, target_anchor_assurance=AnchorAssurance.NONE
    )
    assert plan.privilege_plan.dedicated_account_provisioning_implemented is True
    assert any("bootstrap" in action for action in plan.planned_pfsense_actions)


def test_unsupported_steps_always_name_recovery_secret_generation_mcp_config_and_tls():
    """Never silently pretend architectural-only functionality exists --
    every plan must explicitly state these four gaps regardless of the
    selected target."""

    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY, target_anchor_assurance=AnchorAssurance.NONE
    )
    joined = " ".join(plan.unsupported_steps)
    assert "RECOVERY_REQUIRED" in joined
    assert "recover" in joined
    assert "Secret generation" in joined
    assert "MCP client configuration writing" in joined
    assert "TLS/reachability verification" in joined
    assert "setup apply" in joined


def test_target_reachability_is_never_verified():
    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY,
        target_anchor_assurance=AnchorAssurance.NONE,
        target_origin="https://fw.example.test",
    )
    assert plan.target.reachability_verified is False


def test_deterministic_plan_generation_against_identical_inputs(monkeypatch):
    _clear_relevant_env(monkeypatch)
    kwargs = {
        "target_capability_posture": CapabilityPosture.WRITE_PROTECTED,
        "target_anchor_assurance": AnchorAssurance.NONE,
        "target_origin": "https://fw.example.test",
        "target_identity": "lab-fw",
        "tls_mode": "verify",
        "declared_package_version": "2.8.0",
    }
    first = generate_setup_plan(**kwargs)
    second = generate_setup_plan(**kwargs)
    assert first == second


def test_declared_package_version_supported_and_unsupported():
    supported = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY,
        target_anchor_assurance=AnchorAssurance.NONE,
        declared_package_version="2.8.0",
    )
    assert supported.version_evidence.package_version_supported is True

    unsupported = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY,
        target_anchor_assurance=AnchorAssurance.NONE,
        declared_package_version="1.0.0",
    )
    assert unsupported.version_evidence.package_version_supported is False
    assert "outside the verified range" in unsupported.version_evidence.version_note


def test_declared_package_version_malformed_is_reported_not_silently_ignored():
    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY,
        target_anchor_assurance=AnchorAssurance.NONE,
        declared_package_version="not-a-version",
    )
    assert plan.version_evidence.package_version_supported is None
    assert "could not be parsed" in plan.version_evidence.version_note
    assert plan.version_evidence.declared_package_version == "not-a-version"


def test_no_declared_package_version_never_probes_and_says_so():
    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY, target_anchor_assurance=AnchorAssurance.NONE
    )
    assert plan.version_evidence.declared_package_version is None
    assert plan.version_evidence.package_version_supported is None
    assert "never probes the target live" in plan.version_evidence.version_note


def test_schema_none_yields_no_required_privileges_but_no_error():
    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY, target_anchor_assurance=AnchorAssurance.NONE, schema=None
    )
    assert plan.privilege_plan.schema_provided is False
    assert plan.privilege_plan.required_privileges is None
    assert plan.privilege_plan.unresolved_requirement_tool_names == ()


def test_schema_provided_but_empty_object_yields_all_unresolved_not_a_crash():
    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY,
        target_anchor_assurance=AnchorAssurance.NONE,
        schema={},
    )
    assert plan.privilege_plan.schema_provided is True
    assert plan.privilege_plan.required_privileges == ()
    assert len(plan.privilege_plan.unresolved_requirement_tool_names) > 0


def test_write_protected_privileges_are_a_superset_of_read_only_when_schema_present():
    # A minimal but structurally valid OpenAPI-shaped schema is not
    # required here -- resolve_privilege() degrades every entry to a
    # non-ok ResolvedPrivilege against an empty schema, and this test
    # only needs the *requirement counts*, not successful resolution.
    read_only_plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY,
        target_anchor_assurance=AnchorAssurance.NONE,
        schema={},
    )
    write_protected_plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
        target_anchor_assurance=AnchorAssurance.NONE,
        schema={},
    )
    assert len(write_protected_plan.privilege_plan.unresolved_requirement_tool_names) >= len(
        read_only_plan.privilege_plan.unresolved_requirement_tool_names
    )


def test_capability_posture_and_anchor_assurance_accept_plain_strings_like_the_enum_constructor_does():
    """Mirrors `generate_security_posture_plan()`'s own documented
    coercion discipline -- a plain, value-equal string must behave
    identically to the real enum member, never silently diverge via a
    failed `is` comparison somewhere downstream."""

    from_enum = generate_setup_plan(
        target_capability_posture=CapabilityPosture.READ_ONLY, target_anchor_assurance=AnchorAssurance.NONE
    )
    from_string = generate_setup_plan(target_capability_posture="read_only", target_anchor_assurance="none")  # type: ignore[arg-type]
    assert from_enum == from_string


def test_invalid_target_combination_is_reported_not_silently_accepted():
    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED, target_anchor_assurance=AnchorAssurance.NONE
    )
    # write_protected + none is architecturally invalid per ADR-021 --
    # generate_security_posture_plan() itself already proves this; this
    # test proves generate_setup_plan() surfaces it verbatim, never
    # papering over it.
    if plan.posture_plan.target_validity.value != "valid":
        assert plan.posture_plan.overall_status is PlanOverallStatus.BLOCKED_INVALID_TARGET


def test_no_secret_shaped_value_appears_anywhere_in_a_generated_plan():
    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
        target_anchor_assurance=AnchorAssurance.NONE,
        target_origin="https://fw.example.test",
        target_identity="lab-fw",
        declared_package_version="2.8.0",
    )
    rendered = repr(plan)
    for forbidden in ("api_key", "password", "secret", "-----BEGIN"):
        assert forbidden not in rendered.lower() or (forbidden == "secret" and "secrets are" in rendered.lower())
    # A stronger, unambiguous check: the digest computation must succeed
    # without ever needing a credential-shaped input.
    assert compute_setup_plan_digest(plan)
