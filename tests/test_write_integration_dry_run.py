"""Integration test: the full PfSenseWriteClient -> WriteApiClient ->
RecoveryContractStore -> RollbackExecutor flow against MockTransport,
using one synthetic, test-only MutationPlan/RollbackPlan pair — never a
real pfSense endpoint. WriteEndpoints stays empty for the whole real
test suite; this file monkeypatches in exactly one throwaway entry to
exercise the full lifecycle end to end."""

import json

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.capabilities import Capability
from pfsense_mcp.errors import WriteNotAllowedError
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.pfsense_write_client import PfSenseWriteClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.transport.mock import MockTransport
from pfsense_mcp.write_api_client import WriteApiClient
from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints
from pfsense_mcp.write_types import ContractStatus, MutationPlan, RollbackResult


class _SyntheticRollbackPlan:
    def __init__(self, endpoint_symbol: str) -> None:
        self._endpoint_symbol = endpoint_symbol

    def execute(self, write_client: WriteApiClient) -> RollbackResult:
        # A real rollback would issue its own MutationPlan restoring the
        # captured pre_state_snapshot. This synthetic double just proves
        # the executor invokes it and records the outcome.
        return RollbackResult(contract_id="unused", success=True, detail="synthetic revert executed")


def _build_write_client():
    transport = MockTransport()
    write_rest_client = WriteApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    read_rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    read_client = PfSenseClient(read_rest_client)
    write_client = PfSenseWriteClient(write_rest_client, read_client)
    return write_client, transport


def test_dry_run_is_refused_by_default_since_write_endpoints_is_empty():
    write_client, transport = _build_write_client()
    plan = MutationPlan(
        capability=Capability.FIREWALL_WRITE,
        endpoint_symbol="SYNTHETIC_TEST_ENDPOINT",
        http_method="POST",
        payload={"disabled": True},
        description="integration test plan",
    )

    result = write_client.dry_run(plan)

    assert result.allowed is False
    assert transport.calls == []


def test_full_dry_run_prepare_execute_rollback_lifecycle(monkeypatch):
    monkeypatch.setattr(
        WriteEndpoints,
        "SYNTHETIC_TEST_ENDPOINT",
        WriteEndpointInfo(
            path_suffix="/synthetic/test",
            http_method="POST",
            verified=True,
            min_api_version=ApiVersion.V2,
            reversible=True,
            dry_run_supported=True,
        ),
        raising=False,
    )
    write_client, transport = _build_write_client()
    transport.register("POST", "/api/v2/synthetic/test", status_code=200, text=json.dumps({"applied": True}))

    plan = MutationPlan(
        capability=Capability.FIREWALL_WRITE,
        endpoint_symbol="SYNTHETIC_TEST_ENDPOINT",
        http_method="POST",
        payload={"disabled": True},
        description="integration test plan",
    )

    # 1. dry-run: allowed, computes a predicted diff, zero network calls.
    dry_run_result = write_client.dry_run(plan, current_state={"disabled": False})
    assert dry_run_result.allowed is True
    assert dry_run_result.predicted_diff == {"disabled": {"from": False, "to": True}}
    assert transport.calls == []

    # 2. prepare a Recovery Contract from an (already-captured) snapshot.
    contract = write_client.prepare_recovery_contract(
        plan,
        pre_state_snapshot={"disabled": False},
        rollback_plan=_SyntheticRollbackPlan(plan.endpoint_symbol),
    )
    assert contract.status == ContractStatus.OPEN

    # 3. refused without confirm=True, still zero network calls.
    with pytest.raises(WriteNotAllowedError):
        write_client.execute(plan, contract, confirm=False)
    assert transport.calls == []

    # 4. confirmed execution issues exactly the one allow-listed call.
    execution_result = write_client.execute(plan, contract, confirm=True)
    assert execution_result.status_code == 200
    assert transport.calls == [("POST", "/api/v2/synthetic/test")]
    committed_contract = write_client._contract_store.get(contract.contract_id)
    assert committed_contract.status == ContractStatus.COMMITTED

    # 5. rollback invokes the synthetic plan and marks the contract rolled back.
    rollback_result = write_client.rollback(committed_contract)
    assert rollback_result.success is True
    assert write_client._contract_store.get(contract.contract_id).status == ContractStatus.ROLLED_BACK
