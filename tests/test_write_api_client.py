import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.capabilities import Capability
from pfsense_mcp.errors import WriteNotAllowedError
from pfsense_mcp.recovery import RecoveryContractStore
from pfsense_mcp.transport.mock import MockTransport
from pfsense_mcp.write_api_client import WriteApiClient
from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints
from pfsense_mcp.write_types import ContractStatus, MutationPlan


class _FakeRollbackPlan:
    def execute(self, write_client):
        raise AssertionError("not exercised in these tests")


def _client():
    transport = MockTransport()
    client = WriteApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return client, transport


def _plan(endpoint_symbol="NOT_ALLOW_LISTED", http_method="POST"):
    return MutationPlan(
        capability=Capability.FIREWALL_WRITE,
        endpoint_symbol=endpoint_symbol,
        http_method=http_method,
        payload={"disabled": True},
        description="test plan",
    )


def test_dry_run_refuses_unknown_endpoint():
    client, transport = _client()

    result = client.dry_run(_plan())

    assert result.allowed is False
    assert "not in the write allow-list" in result.reasons[0]
    assert result.predicted_diff is None
    assert transport.calls == []


def test_dry_run_never_calls_transport_even_with_current_state():
    client, transport = _client()

    client.dry_run(_plan(), current_state={"disabled": False})

    assert transport.calls == []


def test_execute_refuses_unknown_endpoint_before_any_network_call():
    client, transport = _client()

    with pytest.raises(WriteNotAllowedError):
        client.execute(_plan(), contract=None)

    assert transport.calls == []


def test_execute_refuses_missing_contract_for_an_allow_listed_endpoint(monkeypatch):
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
    client, transport = _client()

    with pytest.raises(WriteNotAllowedError):
        client.execute(_plan(endpoint_symbol="TEST_ONLY_ENDPOINT"), contract=None)

    assert transport.calls == []


def test_execute_refuses_a_non_open_contract(monkeypatch):
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
    client, transport = _client()
    store = RecoveryContractStore()
    contract = store.create(
        capability=Capability.FIREWALL_WRITE,
        endpoint_symbol="TEST_ONLY_ENDPOINT",
        pre_state_snapshot={},
        rollback_plan=_FakeRollbackPlan(),
    )
    store.mark_committed(contract.contract_id)
    committed_contract = store.get(contract.contract_id)
    assert committed_contract.status == ContractStatus.COMMITTED

    with pytest.raises(WriteNotAllowedError):
        client.execute(_plan(endpoint_symbol="TEST_ONLY_ENDPOINT"), contract=committed_contract)

    assert transport.calls == []


def test_execute_succeeds_for_an_allow_listed_endpoint_with_an_open_contract(monkeypatch):
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
    client, transport = _client()
    transport.register("POST", "/api/v2/example", status_code=200, text="{}")
    store = RecoveryContractStore()
    contract = store.create(
        capability=Capability.FIREWALL_WRITE,
        endpoint_symbol="TEST_ONLY_ENDPOINT",
        pre_state_snapshot={},
        rollback_plan=_FakeRollbackPlan(),
    )

    result = client.execute(_plan(endpoint_symbol="TEST_ONLY_ENDPOINT"), contract=contract)

    assert result.contract_id == contract.contract_id
    assert result.status_code == 200
    assert transport.calls == [("POST", "/api/v2/example")]


def test_send_for_tier1_refuses_unknown_endpoint_before_any_network_call():
    client, transport = _client()

    with pytest.raises(WriteNotAllowedError, match="not in the write allow-list"):
        client.send_for_tier1(endpoint_symbol="NOT_ALLOW_LISTED", http_method="PATCH", body=b"{}")

    assert transport.calls == []


def test_send_for_tier1_requires_no_tier0_contract(monkeypatch):
    """The one behavioral difference from execute(): no contract
    parameter exists at all, since Tier 1's caller has already done its
    own contract validation before ever calling this method."""

    monkeypatch.setattr(
        WriteEndpoints,
        "TEST_ONLY_ENDPOINT",
        WriteEndpointInfo(
            path_suffix="/example",
            http_method="PATCH",
            verified=True,
            min_api_version=ApiVersion.V2,
            reversible=True,
            dry_run_supported=True,
        ),
        raising=False,
    )
    client, transport = _client()
    transport.register("PATCH", "/api/v2/example", status_code=200, text='{"ok": true}')

    response = client.send_for_tier1(endpoint_symbol="TEST_ONLY_ENDPOINT", http_method="PATCH", body=b'{"descr":"x"}')

    assert response.status_code == 200
    assert transport.calls == [("PATCH", "/api/v2/example")]
    assert transport.request_bodies == [b'{"descr":"x"}']


def test_send_for_tier1_refuses_unverified_endpoint(monkeypatch):
    monkeypatch.setattr(
        WriteEndpoints,
        "TEST_ONLY_ENDPOINT",
        WriteEndpointInfo(
            path_suffix="/example",
            http_method="PATCH",
            verified=False,
            min_api_version=ApiVersion.V2,
            reversible=True,
            dry_run_supported=True,
        ),
        raising=False,
    )
    client, transport = _client()

    with pytest.raises(WriteNotAllowedError, match="not verified"):
        client.send_for_tier1(endpoint_symbol="TEST_ONLY_ENDPOINT", http_method="PATCH", body=b"{}")

    assert transport.calls == []


def test_send_for_tier1_refuses_method_mismatch(monkeypatch):
    monkeypatch.setattr(
        WriteEndpoints,
        "TEST_ONLY_ENDPOINT",
        WriteEndpointInfo(
            path_suffix="/example",
            http_method="PATCH",
            verified=True,
            min_api_version=ApiVersion.V2,
            reversible=True,
            dry_run_supported=True,
        ),
        raising=False,
    )
    client, transport = _client()

    with pytest.raises(WriteNotAllowedError, match="does not match the allow-listed method"):
        client.send_for_tier1(endpoint_symbol="TEST_ONLY_ENDPOINT", http_method="DELETE", body=b"{}")

    assert transport.calls == []
