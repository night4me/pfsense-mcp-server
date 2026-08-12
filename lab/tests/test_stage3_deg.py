import json
from dataclasses import replace

import pytest

from lab.fault_proxy import FAULT_DELIVERY, FaultScenario, UpstreamDelivery
from lab.stage3_deg import (
    CANDIDATE,
    ORIGINAL_DESCRIPTION,
    SCENARIOS,
    SEMANTIC_UNIT,
    EvidenceStage,
    LiveStatus,
    OfflineRestartHarness,
    ReadBackClassification,
    ScenarioDefinition,
    ScenarioEvidence,
    ScenarioId,
    classify_read_back,
    main,
    sanitized_plan,
    scenario_plan,
)
from pfsense_mcp.tier1.state_machine import RecoveryState

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64


def test_registry_covers_exactly_d1_through_g10():
    assert set(SCENARIOS) == set(ScenarioId)
    assert len(SCENARIOS) == 26
    assert {definition.stage for definition in SCENARIOS.values()} == set(EvidenceStage)


def test_runner_authority_is_closed_to_one_candidate_and_semantic_unit():
    assert CANDIDATE == "LAB_ALIAS_TEST"
    assert SEMANTIC_UNIT == "set_firewall_alias_description_v1"
    assert ORIGINAL_DESCRIPTION == "Disposable LAB-T1 synthetic test alias"
    assert all(not hasattr(definition, "endpoint") for definition in SCENARIOS.values())
    assert all(not hasattr(definition, "payload") for definition in SCENARIOS.values())


@pytest.mark.parametrize("definition", SCENARIOS.values(), ids=lambda value: value.scenario_id.value)
def test_every_scenario_requires_exact_a_restoration(definition):
    assert definition.exact_final_state_requirement == "exact-authoritative-A"
    assert definition.repetition_target >= 1


def test_definition_rejects_missing_restoration_semantics():
    definition = scenario_plan(ScenarioId.D1)
    with pytest.raises(ValueError, match="exact authoritative A"):
        replace(definition, exact_final_state_requirement="")


@pytest.mark.parametrize("value", [-1, 3, True])
def test_definition_rejects_invalid_send_accounting(value):
    definition = scenario_plan(ScenarioId.D1)
    with pytest.raises(ValueError, match="send counts"):
        replace(definition, expected_forward_sends=value)


def test_d1_and_d2_are_zero_executor_forward_send_plans():
    for scenario_id in (ScenarioId.D1, ScenarioId.D2):
        definition = scenario_plan(scenario_id)
        assert definition.expected_orchestration_sends == 2
        assert definition.expected_forward_sends == 0
        assert definition.expected_state is RecoveryState.FAILED


def test_d3_d4_d5_are_zero_executor_rollback_send_plans():
    for scenario_id in (ScenarioId.D3, ScenarioId.D4, ScenarioId.D5):
        definition = scenario_plan(scenario_id)
        assert definition.expected_orchestration_sends == 2
        assert definition.expected_forward_sends == 1
        assert definition.expected_rollback_sends == 0
        assert definition.expected_state is RecoveryState.ROLLBACK_FAILED


def test_d5_locator_equality_cannot_override_fingerprint_conflict():
    definition = scenario_plan(ScenarioId.D5)
    assert "stable-locator" in definition.orchestration_action
    assert "does-not-override" in definition.expected_reconciliation


def test_d6_is_explicitly_blocked_at_sealed_boundary():
    definition = scenario_plan(ScenarioId.D6)
    assert definition.live_status is LiveStatus.BLOCKED
    assert "no-deterministic-hook" in definition.expected_reconciliation


def test_fault_delivery_semantics_are_explicit_not_timing_inferences():
    assert FAULT_DELIVERY == {
        FaultScenario.CONNECTION_RESET_DURING_UPLOAD: UpstreamDelivery.PROVEN_NOT_DELIVERED,
        FaultScenario.RESPONSE_DROPPED_AFTER_COMMIT: UpstreamDelivery.PROVEN_DELIVERED,
        FaultScenario.TIMEOUT_DURING_RESPONSE: UpstreamDelivery.POSSIBLY_DELIVERED,
        FaultScenario.TIMEOUT_DURING_READBACK: UpstreamDelivery.PROVEN_NOT_DELIVERED,
    }


@pytest.mark.parametrize(
    ("live", "expected"),
    [
        (_B, ReadBackClassification.DEFINITELY_APPLIED),
        (_A, ReadBackClassification.DEFINITELY_NOT_APPLIED),
        (_C, ReadBackClassification.AMBIGUOUS),
    ],
)
def test_authoritative_read_back_classification(live, expected):
    assert classify_read_back(live_fingerprint=live, a_fingerprint=_A, b_fingerprint=_B) is expected


@pytest.mark.parametrize("bad", ["", "a" * 63, 7, None])
def test_read_back_classifier_rejects_malformed_fingerprint(bad):
    with pytest.raises(ValueError, match="canonical digests"):
        classify_read_back(live_fingerprint=bad, a_fingerprint=_A, b_fingerprint=_B)


def test_read_back_classifier_refuses_indistinguishable_a_and_b():
    with pytest.raises(ValueError, match="distinct"):
        classify_read_back(live_fingerprint=_A, a_fingerprint=_A, b_fingerprint=_A)


def test_evidence_requires_exact_predeclared_send_counts():
    definition = scenario_plan(ScenarioId.E1)
    with pytest.raises(ValueError, match="observed sends"):
        ScenarioEvidence(definition, 0, 2, 0, ReadBackClassification.DEFINITELY_APPLIED, True)


def test_evidence_requires_authoritative_read_back_when_declared():
    definition = scenario_plan(ScenarioId.E1)
    with pytest.raises(ValueError, match="read-back"):
        ScenarioEvidence(definition, 0, 1, 0, None, True)


def test_evidence_requires_exact_a_restoration():
    definition = scenario_plan(ScenarioId.E1)
    with pytest.raises(ValueError, match="restoration"):
        ScenarioEvidence(definition, 0, 1, 0, ReadBackClassification.DEFINITELY_APPLIED, False)


def test_evidence_output_is_secret_free_and_exception_message_is_impossible():
    definition = scenario_plan(ScenarioId.E1)
    evidence = ScenarioEvidence(
        definition, 0, 1, 0, ReadBackClassification.DEFINITELY_APPLIED, True, "TransportTimeoutError"
    )
    report = evidence.sanitized()
    assert report["exception_class"] == "TransportTimeoutError"
    assert set(report) == {
        "scenario_id",
        "stage",
        "orchestration_sends",
        "executor_forward_sends",
        "executor_rollback_sends",
        "read_back_classification",
        "expected_state",
        "final_state",
        "exception_class",
    }
    with pytest.raises(ValueError, match="sanitized"):
        replace(evidence, exception_class="TransportTimeoutError: secret detail")


def test_applied_and_non_applied_reconciliation_bindings_remain_distinct():
    applied = scenario_plan(ScenarioId.E8)
    not_applied = scenario_plan(ScenarioId.E9)
    assert "exact-B-and-locator" in applied.expected_reconciliation
    assert "no-applied-only-bindings" in not_applied.expected_reconciliation
    assert applied.expected_state is RecoveryState.RECONCILIATION
    assert not_applied.expected_state is RecoveryState.FAILED


def test_ambiguous_outcome_cannot_auto_progress():
    definition = scenario_plan(ScenarioId.E10)
    assert definition.expected_state is RecoveryState.RECONCILIATION
    assert "human" in definition.expected_reconciliation
    assert definition.expected_forward_sends == definition.expected_rollback_sends == 0


@pytest.mark.parametrize("scenario_id", [ScenarioId.G1, ScenarioId.G3, ScenarioId.G4, ScenarioId.G5])
def test_restart_uncertainty_plans_forbid_resend(scenario_id):
    definition = scenario_plan(scenario_id)
    assert "no-resend" in definition.expected_reconciliation
    assert definition.expected_forward_sends == definition.expected_rollback_sends == 0


def test_verified_b_restart_preserves_recovery_bindings_and_only_rolls_back_once():
    definition = scenario_plan(ScenarioId.G2)
    assert "A-B-locator" in definition.expected_reconciliation
    assert definition.expected_forward_sends == 0
    assert definition.expected_rollback_sends == 1
    assert definition.expected_state is RecoveryState.ROLLED_BACK


@pytest.mark.parametrize("scenario_id", [ScenarioId.G6, ScenarioId.G7, ScenarioId.G8, ScenarioId.G9, ScenarioId.G10])
def test_integrity_and_projection_restart_cases_are_offline_only(scenario_id):
    definition = scenario_plan(scenario_id)
    assert definition.live_status is LiveStatus.OFFLINE_ONLY
    assert not definition.requires_fresh_attestation


def test_projection_is_never_a_scenario_field_or_persisted_value():
    fields = set(ScenarioDefinition.__dataclass_fields__)
    assert "transport_projection" not in fields
    assert "resolved_transport_target" not in fields


def test_sanitized_plan_is_explicitly_not_live_verified():
    report = sanitized_plan(scenario_plan(ScenarioId.E1))
    assert report["empirical_status"] == "NOT_YET_LIVE_VERIFIED"
    assert "orchestration_action" not in report
    assert "expected_reconciliation" not in report


def test_offline_cli_emits_only_closed_plan(capsys):
    assert main(["plan", "--scenario", ScenarioId.D1.value]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["candidate"] == CANDIDATE
    assert output["semantic_unit"] == SEMANTIC_UNIT
    assert [plan["scenario_id"] for plan in output["plans"]] == [ScenarioId.D1.value]
    assert output["plans"][0]["empirical_status"] == "NOT_YET_LIVE_VERIFIED"


def test_offline_cli_has_no_execute_command():
    with pytest.raises(SystemExit):
        main(["execute", "--scenario", ScenarioId.D1.value])


def test_restart_harness_reconstructs_no_process_local_projection(tmp_path):
    directory = tmp_path / "restart"
    directory.mkdir(mode=0o700)
    harness = OfflineRestartHarness(directory / "contracts.sqlite3", b"r" * 32, "stage3-restart")

    observed = harness.reconstruct_process_object(lambda store: (store, object()))

    assert observed[0].interrupted() == ()
    fields = set(OfflineRestartHarness.__dataclass_fields__)
    assert "transport_projection" not in fields
    assert "adapter" not in fields
    assert "write_client" not in fields
