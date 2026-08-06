import dataclasses

import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.write_types import ContractStatus, DryRunResult, ExecutionResult, MutationPlan, RollbackResult


def test_mutation_plan_is_frozen():
    plan = MutationPlan(
        capability=Capability.FIREWALL_WRITE,
        endpoint_symbol="EXAMPLE",
        http_method="POST",
        payload={"key": "value"},
        description="example",
    )
    assert plan.capability == Capability.FIREWALL_WRITE
    with pytest.raises(dataclasses.FrozenInstanceError):
        plan.http_method = "GET"


def test_dry_run_result_construction():
    result = DryRunResult(allowed=False, reasons=("not allow-listed",), predicted_diff=None)
    assert result.allowed is False
    assert result.reasons == ("not allow-listed",)
    assert result.predicted_diff is None


def test_execution_result_construction():
    result = ExecutionResult(contract_id="abc123", status_code=200, committed_at_utc="2026-01-01T00:00:00+00:00")
    assert result.contract_id == "abc123"
    assert result.status_code == 200


def test_rollback_result_construction():
    result = RollbackResult(contract_id="abc123", success=True, detail="reverted")
    assert result.success is True


def test_contract_status_values():
    assert ContractStatus.OPEN.value == "open"
    assert ContractStatus.COMMITTED.value == "committed"
    assert ContractStatus.ROLLED_BACK.value == "rolled_back"
    assert ContractStatus.EXPIRED.value == "expired"
