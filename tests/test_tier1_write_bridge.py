"""Regression and adversarial tests for `pfsense_mcp.tier1_write_bridge`
-- the narrow W3 Slice 4 wiring boundary between the MCP-reachable
alias-description WRITE product surface and `pfsense_mcp.tier1`.

Construction-only tests (`can_construct_write_runtime()`) reuse
`tests.tier1.test_production_runtime`'s established `_full_env()`
environment-construction helper -- safe, because `build_production_runtime()`
itself performs no network I/O, only object construction.
`request_alias_description_change()`'s own flow tests instead mock
`build_production_runtime()` to return a synthetic runtime double: a
REAL, fully-configured runtime's `request_alias_description_change()`
would call the preparer's `read_client.get_firewall_aliases()` --  a real
network call against whatever pfSense URL is configured -- which no test
in this file may ever trigger ("must be offline/mock-based", "no live
pfSense mutation is authorized"). The full authorize/confirm/execute flow
itself is already thoroughly covered offline by
`tests/tier1/test_slice3_composition.py`; this file's job is narrower --
prove the bridge wires to that already-tested flow correctly and projects
its result correctly, nothing more.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from pydantic import ValidationError

import pfsense_mcp.security_plan as security_plan
from pfsense_mcp import tier1_write_bridge
from pfsense_mcp.models.write_outcome import AliasDescriptionWriteResult
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import generate_security_posture_plan
from pfsense_mcp.security_plan_digest import compute_plan_digest
from pfsense_mcp.tier1.production_runtime import ProductionAliasDescriptionRuntime, ProductOutcome, ProductOutcomeState
from tests.tier1.test_production_runtime import _full_env


def test_can_construct_write_runtime_false_when_unconfigured():
    assert tier1_write_bridge.can_construct_write_runtime() is False


def test_can_construct_write_runtime_false_on_partial_configuration(monkeypatch, tmp_path):
    env = _full_env(tmp_path)
    del env["PFSENSE_TIER1_STORE_KEY_FILE"]
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    # Partial configuration raises Tier1ConfigurationError inside
    # build_production_runtime() -- the probe must catch it and report
    # False, never propagate.
    assert tier1_write_bridge.can_construct_write_runtime() is False


def test_can_construct_write_runtime_true_when_fully_configured(monkeypatch, tmp_path):
    env = _full_env(tmp_path)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    assert tier1_write_bridge.can_construct_write_runtime() is True


def test_can_construct_write_runtime_never_raises_on_genuine_construction_error(monkeypatch):
    def _raise(_env=None):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(tier1_write_bridge, "build_production_runtime", _raise)

    assert tier1_write_bridge.can_construct_write_runtime() is False


def test_request_alias_description_change_refused_when_unconfigured():
    result = tier1_write_bridge.request_alias_description_change(alias_name="LAB_ALIAS_TEST", description="after")
    assert result == AliasDescriptionWriteResult(state="refused")


@pytest.mark.parametrize(
    "outcome_state,expected",
    [
        (ProductOutcomeState.REQUESTED, "requested"),
        (ProductOutcomeState.AWAITING_CONFIRMATION, "awaiting_confirmation"),
        (ProductOutcomeState.VERIFIED, "verified"),
        (ProductOutcomeState.RECONCILIATION_REQUIRED, "reconciliation_required"),
        (ProductOutcomeState.REFUSED, "refused"),
    ],
)
def test_request_alias_description_change_projects_every_outcome_state(monkeypatch, outcome_state, expected):
    runtime = Mock(spec=ProductionAliasDescriptionRuntime)
    runtime.request_alias_description_change.return_value = ProductOutcome(outcome_state, contract_id="opaque-id")
    monkeypatch.setattr(tier1_write_bridge, "build_production_runtime", lambda env=None: runtime)

    result = tier1_write_bridge.request_alias_description_change(alias_name="LAB_ALIAS_TEST", description="after")

    assert result == AliasDescriptionWriteResult(state=expected)
    # No contract_id, or any other internal detail, ever leaks -- the
    # bridge's own result type structurally cannot carry it (see
    # test_result_type_exposes_only_state_field below), but assert here
    # too against the concrete synthetic value used in this test.
    assert "opaque-id" not in result.model_dump_json()


def test_request_alias_description_change_calls_the_composed_runtime_with_the_documented_expectation(monkeypatch):
    runtime = Mock(spec=ProductionAliasDescriptionRuntime)
    runtime.request_alias_description_change.return_value = ProductOutcome(ProductOutcomeState.REQUESTED)
    monkeypatch.setattr(tier1_write_bridge, "build_production_runtime", lambda env=None: runtime)

    tier1_write_bridge.request_alias_description_change(alias_name="LAB_ALIAS_TEST", description="new description")

    runtime.request_alias_description_change.assert_called_once()
    _request, kwargs = runtime.request_alias_description_change.call_args
    request = _request[0]
    assert request.alias_name == "LAB_ALIAS_TEST"
    assert request.description == "new description"
    assert kwargs["target_capability_posture"] is CapabilityPosture.WRITE_PROTECTED
    assert kwargs["target_anchor_assurance"] is AnchorAssurance.HARDWARE_WITNESS
    assert kwargs["requested_step_id"] == "capability_posture.milestone_9_activation"
    expected_plan = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS)
    assert kwargs["requested_plan_digest"] == compute_plan_digest(expected_plan)
    assert kwargs["now"].tzinfo is not None


def test_bridge_never_caches_or_reuses_a_runtime_across_calls(monkeypatch):
    build_calls = []
    runtime = Mock(spec=ProductionAliasDescriptionRuntime)
    runtime.request_alias_description_change.return_value = ProductOutcome(ProductOutcomeState.REQUESTED)

    def _build(env=None):
        build_calls.append(1)
        return runtime

    monkeypatch.setattr(tier1_write_bridge, "build_production_runtime", _build)

    tier1_write_bridge.can_construct_write_runtime()
    tier1_write_bridge.request_alias_description_change(alias_name="LAB_ALIAS_TEST", description="after")

    assert len(build_calls) == 2  # one fresh construction per call, never reused


def test_result_type_exposes_only_state_field():
    assert set(AliasDescriptionWriteResult.model_fields) == {"state"}
    result = AliasDescriptionWriteResult(state="verified")
    assert result.model_dump() == {"state": "verified"}
    with pytest.raises(ValidationError):
        AliasDescriptionWriteResult(state="verified", contract_id="should-not-be-accepted")  # type: ignore[call-arg]


def test_result_type_rejects_unknown_state_values():
    with pytest.raises(ValidationError):
        AliasDescriptionWriteResult(state="not-a-real-state")  # type: ignore[arg-type]


def test_projection_is_exhaustive_over_every_product_outcome_state():
    assert set(tier1_write_bridge._PROJECTION) == set(ProductOutcomeState)


def test_plan_expectation_matches_the_documented_derivation():
    plan = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS)
    expected_digest = compute_plan_digest(plan)
    assert tier1_write_bridge._requested_plan_digest() == expected_digest
    assert tier1_write_bridge._REQUESTED_STEP_ID == "capability_posture.milestone_9_activation"


def test_bridge_constants_are_sourced_from_security_plan_not_private_duplicates():
    """Pre-Slice-5 duplication-removal refactor: the bridge's plan/step
    expectation must be the exact same object `security_plan.py` exports,
    never a second, independently-typed literal."""

    assert (
        tier1_write_bridge._TARGET_CAPABILITY_POSTURE is security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE
    )
    assert tier1_write_bridge._TARGET_ANCHOR_ASSURANCE is security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE
    assert tier1_write_bridge._REQUESTED_STEP_ID is security_plan.ALIAS_DESCRIPTION_WRITE_STEP_ID
