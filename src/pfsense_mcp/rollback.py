"""Rollback framework: a protocol every recovery plan implements, plus
an executor that replays one against a committed RecoveryContract.

No concrete RollbackPlan is implemented in this build — each real write
capability supplies its own, alongside its WriteEndpoints entry, under a
separately authorized tier. This module is exercised in tests only
against a synthetic, test-only RollbackPlan double.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from .write_types import ContractStatus, RollbackResult

if TYPE_CHECKING:
    from .recovery import RecoveryContract, RecoveryContractStore
    from .write_api_client import WriteApiClient


class RollbackPlan(Protocol):
    def execute(self, write_client: "WriteApiClient") -> RollbackResult: ...


class RollbackExecutor:
    def __init__(self, store: "RecoveryContractStore") -> None:
        self._store = store

    def rollback(self, contract: "RecoveryContract", write_client: "WriteApiClient") -> RollbackResult:
        if contract.status != ContractStatus.COMMITTED:
            return RollbackResult(
                contract_id=contract.contract_id,
                success=False,
                detail=f"Recovery Contract is {contract.status.value}, not committed; refusing to roll back.",
            )

        result = contract.rollback_plan.execute(write_client)
        if result.success:
            self._store.mark_rolled_back(contract.contract_id)
        return result
