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


class _FakeRollbackPlan:
    def execute(self, write_client):
        return RollbackResult(contract_id="unused", success=True, detail="reverted")


def _write_client():
    transport = MockTransport()
    write_rest_client = WriteApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    read_rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    read_client = PfSenseClient(read_rest_client)
    return PfSenseWriteClient(write_rest_client, read_client), transport


def _plan(endpoint_symbol="TEST_ONLY_ENDPOINT"):
    return MutationPlan(
        capability=Capability.FIREWALL_WRITE,
        endpoint_symbol=endpoint_symbol,
        http_method="POST",
        payload={"disabled": True},
        description="test plan",
    )


def test_prepare_recovery_contract_creates_an_open_contract():
    client, _transport = _write_client()

    contract = client.prepare_recovery_contract(
        _plan(), pre_state_snapshot={"disabled": False}, rollback_plan=_FakeRollbackPlan()
    )

    assert contract.status == ContractStatus.OPEN
    assert contract.pre_state_snapshot == {"disabled": False}


def test_execute_refuses_without_confirm():
    client, transport = _write_client()
    contract = client.prepare_recovery_contract(_plan(), pre_state_snapshot={}, rollback_plan=_FakeRollbackPlan())

    with pytest.raises(WriteNotAllowedError):
        client.execute(_plan(), contract, confirm=False)

    assert transport.calls == []


def test_execute_with_confirm_and_allow_listed_endpoint_commits(monkeypatch):
    monkeypatch.setattr(
        WriteEndpoints,
        "TEST_ONLY_ENDPOINT",
        WriteEndpointInfo(
            path_suffix="/example",
            http_method="POST",
            verified=True,
            min_api_version=ApiVersion.V2,
            reversible=True,
            dry_run_supported=True,
        ),
        raising=False,
    )
    client, transport = _write_client()
    transport.register("POST", "/api/v2/example", status_code=200, text="{}")
    contract = client.prepare_recovery_contract(_plan(), pre_state_snapshot={}, rollback_plan=_FakeRollbackPlan())

    result = client.execute(_plan(), contract, confirm=True)

    assert result.contract_id == contract.contract_id
    assert client._contract_store.get(contract.contract_id).status == ContractStatus.COMMITTED


def test_rollback_delegates_to_the_rollback_executor(monkeypatch):
    monkeypatch.setattr(
        WriteEndpoints,
        "TEST_ONLY_ENDPOINT",
        WriteEndpointInfo(
            path_suffix="/example",
            http_method="POST",
            verified=True,
            min_api_version=ApiVersion.V2,
            reversible=True,
            dry_run_supported=True,
        ),
        raising=False,
    )
    client, transport = _write_client()
    transport.register("POST", "/api/v2/example", status_code=200, text="{}")
    contract = client.prepare_recovery_contract(_plan(), pre_state_snapshot={}, rollback_plan=_FakeRollbackPlan())
    client.execute(_plan(), contract, confirm=True)
    committed_contract = client._contract_store.get(contract.contract_id)

    result = client.rollback(committed_contract)

    assert result.success is True
