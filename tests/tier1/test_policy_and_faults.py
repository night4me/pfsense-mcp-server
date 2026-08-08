from __future__ import annotations

import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.tier1.errors import MutationPolicyError
from pfsense_mcp.tier1.faults import EffectKnowledge, MutationBoundary, classify_fault
from pfsense_mcp.tier1.policy import INACTIVE_TIER1_POLICY, MutationPolicy, MutationRule
from pfsense_mcp.tier1.state_machine import RecoveryState


def test_inactive_policy_refuses_every_request():
    with pytest.raises(MutationPolicyError):
        INACTIVE_TIER1_POLICY.authorize(
            capability=Capability.ALIAS_WRITE,
            endpoint_symbol="SYNTHETIC_ENDPOINT",
            http_method="PATCH",
        )


def test_policy_requires_exact_capability_endpoint_and_method():
    policy = MutationPolicy(frozenset({MutationRule(Capability.ALIAS_WRITE, "SYNTHETIC_ENDPOINT", "PATCH")}))
    policy.authorize(
        capability=Capability.ALIAS_WRITE,
        endpoint_symbol="SYNTHETIC_ENDPOINT",
        http_method="PATCH",
    )
    for request in (
        (Capability.FIREWALL_WRITE, "SYNTHETIC_ENDPOINT", "PATCH"),
        (Capability.ALIAS_WRITE, "OTHER", "PATCH"),
        (Capability.ALIAS_WRITE, "SYNTHETIC_ENDPOINT", "DELETE"),
    ):
        with pytest.raises(MutationPolicyError):
            policy.authorize(capability=request[0], endpoint_symbol=request[1], http_method=request[2])


@pytest.mark.parametrize(
    "rule",
    [
        lambda: MutationRule(Capability.SYSTEM_READ, "SYNTHETIC_ENDPOINT", "PATCH"),
        lambda: MutationRule(Capability.ALIAS_WRITE, "unsafe/endpoint", "PATCH"),
        lambda: MutationRule(Capability.ALIAS_WRITE, "SYNTHETIC_ENDPOINT", "GET"),
    ],
)
def test_invalid_policy_rules_fail_at_construction(rule):
    with pytest.raises(MutationPolicyError):
        rule()


def test_policy_container_must_be_immutable():
    with pytest.raises(MutationPolicyError, match="immutable"):
        MutationPolicy(set())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("boundary", "knowledge", "state", "manual"),
    [
        (MutationBoundary.BEFORE_SEND, EffectKnowledge.PROVEN_NONE, RecoveryState.FAILED, False),
        (MutationBoundary.DURING_SEND, EffectKnowledge.AMBIGUOUS, RecoveryState.RECONCILIATION, True),
        (MutationBoundary.AFTER_SEND, EffectKnowledge.AMBIGUOUS, RecoveryState.RECONCILIATION, True),
        (MutationBoundary.DURING_ROLLBACK, EffectKnowledge.AMBIGUOUS, RecoveryState.RECONCILIATION, True),
        (MutationBoundary.AFTER_SEND, EffectKnowledge.VERIFIED_SUCCESS, RecoveryState.VERIFIED, False),
    ],
)
def test_faults_never_retry_and_preserve_outcome_uncertainty(boundary, knowledge, state, manual):
    decision = classify_fault(boundary, knowledge)
    assert decision.target_state == state
    assert decision.manual_reconciliation is manual
    assert decision.automatic_retry is False
