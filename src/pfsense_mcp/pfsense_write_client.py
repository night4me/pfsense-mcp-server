"""PfSenseWriteClient — domain-semantic write layer, mirroring
PfSenseClient's shape. Zero domain mutating methods exist in this
build (no create_*/update_*/delete_* methods) — only the generic
dry-run / prepare-contract / execute / rollback plumbing that a future,
separately authorized tier's real capabilities will call into.

Reuses the existing, already-verified PfSenseClient (read) instance for
any state a future capability needs to snapshot — this module adds no
new way to read pfSense.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from .errors import WriteNotAllowedError
from .pfsense_client import PfSenseClient
from .recovery import DEFAULT_CONTRACT_TTL, RecoveryContract, RecoveryContractStore
from .rollback import RollbackExecutor, RollbackPlan
from .write_api_client import WriteApiClient
from .write_types import DryRunResult, ExecutionResult, MutationPlan, RollbackResult


class PfSenseWriteClient:
    def __init__(
        self,
        write_rest_client: WriteApiClient,
        read_client: PfSenseClient,
        *,
        contract_store: RecoveryContractStore | None = None,
    ) -> None:
        self._write_rest_client = write_rest_client
        self._read_client = read_client
        self._contract_store = contract_store if contract_store is not None else RecoveryContractStore()
        self._rollback_executor = RollbackExecutor(self._contract_store)

    def dry_run(self, plan: MutationPlan, *, current_state: dict[str, Any] | None = None) -> DryRunResult:
        return self._write_rest_client.dry_run(plan, current_state=current_state)

    def prepare_recovery_contract(
        self,
        plan: MutationPlan,
        *,
        pre_state_snapshot: dict[str, Any],
        rollback_plan: RollbackPlan,
        ttl: timedelta = DEFAULT_CONTRACT_TTL,
    ) -> RecoveryContract:
        """Creates a Recovery Contract from an already-captured snapshot.

        In this build there is no real WriteEndpoints entry, so there is
        nothing to derive an automatic "which PfSenseClient method
        captures this endpoint's state" mapping from. A future tier that
        adds the first real capability supplies pre_state_snapshot
        (captured via self._read_client's existing GET methods) and a
        concrete RollbackPlan alongside that capability's WriteEndpoints
        entry.
        """
        return self._contract_store.create(
            capability=plan.capability,
            endpoint_symbol=plan.endpoint_symbol,
            pre_state_snapshot=pre_state_snapshot,
            rollback_plan=rollback_plan,
            ttl=ttl,
        )

    def execute(self, plan: MutationPlan, contract: RecoveryContract, *, confirm: bool) -> ExecutionResult:
        if not confirm:
            raise WriteNotAllowedError("Mutation refused: confirm=True was not supplied.")
        result = self._write_rest_client.execute(plan, contract)
        self._contract_store.mark_committed(contract.contract_id)
        return result

    def rollback(self, contract: RecoveryContract) -> RollbackResult:
        return self._rollback_executor.rollback(contract, self._write_rest_client)
