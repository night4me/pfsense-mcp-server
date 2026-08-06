from datetime import datetime, timedelta, timezone

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.recovery import RecoveryContractStore
from pfsense_mcp.write_types import ContractStatus, RollbackResult


class _FakeRollbackPlan:
    def execute(self, write_client):
        return RollbackResult(contract_id="unused", success=True, detail="fake rollback")


def _make_store_and_contract(ttl=timedelta(minutes=5)):
    store = RecoveryContractStore()
    contract = store.create(
        capability=Capability.FIREWALL_WRITE,
        endpoint_symbol="EXAMPLE",
        pre_state_snapshot={"disabled": False},
        rollback_plan=_FakeRollbackPlan(),
        ttl=ttl,
    )
    return store, contract


def test_create_returns_open_contract():
    store, contract = _make_store_and_contract()
    assert contract.status == ContractStatus.OPEN
    assert contract.capability == Capability.FIREWALL_WRITE
    assert contract.endpoint_symbol == "EXAMPLE"
    assert contract.pre_state_snapshot == {"disabled": False}


def test_get_returns_the_same_contract():
    store, contract = _make_store_and_contract()
    fetched = store.get(contract.contract_id)
    assert fetched is not None
    assert fetched.contract_id == contract.contract_id


def test_get_returns_none_for_unknown_id():
    store = RecoveryContractStore()
    assert store.get("does-not-exist") is None


def test_get_marks_an_expired_open_contract_as_expired():
    store, contract = _make_store_and_contract(ttl=timedelta(seconds=-1))
    fetched = store.get(contract.contract_id)
    assert fetched is not None
    assert fetched.status == ContractStatus.EXPIRED


def test_mark_committed_transitions_status():
    store, contract = _make_store_and_contract()
    updated = store.mark_committed(contract.contract_id)
    assert updated is not None
    assert updated.status == ContractStatus.COMMITTED
    assert store.get(contract.contract_id).status == ContractStatus.COMMITTED


def test_mark_rolled_back_transitions_status():
    store, contract = _make_store_and_contract()
    store.mark_committed(contract.contract_id)
    updated = store.mark_rolled_back(contract.contract_id)
    assert updated is not None
    assert updated.status == ContractStatus.ROLLED_BACK


def test_mark_committed_on_unknown_id_returns_none():
    store = RecoveryContractStore()
    assert store.mark_committed("does-not-exist") is None


def test_is_expired_uses_supplied_now():
    store, contract = _make_store_and_contract(ttl=timedelta(minutes=5))
    far_future = datetime.now(timezone.utc) + timedelta(hours=1)
    assert contract.is_expired(now=far_future) is True
    assert contract.is_expired(now=datetime.now(timezone.utc)) is False
