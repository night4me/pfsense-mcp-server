from pfsense_mcp.capabilities import Capability
from pfsense_mcp.recovery import RecoveryContractStore
from pfsense_mcp.rollback import RollbackExecutor
from pfsense_mcp.write_types import RollbackResult


class _SucceedingRollbackPlan:
    def execute(self, write_client):
        return RollbackResult(contract_id="unused", success=True, detail="reverted")


class _FailingRollbackPlan:
    def execute(self, write_client):
        return RollbackResult(contract_id="unused", success=False, detail="upstream refused")


def _make_committed_contract(store, plan):
    contract = store.create(
        capability=Capability.FIREWALL_WRITE,
        endpoint_symbol="EXAMPLE",
        pre_state_snapshot={},
        rollback_plan=plan,
    )
    return store.mark_committed(contract.contract_id)


def test_rollback_refuses_a_non_committed_contract():
    store = RecoveryContractStore()
    contract = store.create(
        capability=Capability.FIREWALL_WRITE,
        endpoint_symbol="EXAMPLE",
        pre_state_snapshot={},
        rollback_plan=_SucceedingRollbackPlan(),
    )
    executor = RollbackExecutor(store)

    result = executor.rollback(contract, write_client=None)

    assert result.success is False
    assert "not committed" in result.detail.lower() or "open" in result.detail.lower()


def test_rollback_invokes_the_plan_and_marks_rolled_back():
    store = RecoveryContractStore()
    contract = _make_committed_contract(store, _SucceedingRollbackPlan())
    executor = RollbackExecutor(store)

    result = executor.rollback(contract, write_client=None)

    assert result.success is True
    assert store.get(contract.contract_id).status.value == "rolled_back"


def test_rollback_does_not_mark_rolled_back_on_plan_failure():
    store = RecoveryContractStore()
    contract = _make_committed_contract(store, _FailingRollbackPlan())
    executor = RollbackExecutor(store)

    result = executor.rollback(contract, write_client=None)

    assert result.success is False
    assert store.get(contract.contract_id).status.value == "committed"
