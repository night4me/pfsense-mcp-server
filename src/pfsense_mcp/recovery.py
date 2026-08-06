"""Recovery Contract: a snapshot of pre-mutation state plus a rollback
plan, required before any live mutation is permitted to execute.

A contract's pre_state_snapshot is captured through the existing,
already-verified PfSenseClient GET path (see pfsense_write_client.py) —
this module adds no new way to read pfSense. The snapshot is held only
in-process memory for the contract's short TTL; it is never persisted to
disk and never included in a log line (write_audit.py logs only the
contract_id and metadata, never its content), consistent with errors.py's
"no raw response body" rule.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from .capabilities import Capability
from .write_types import ContractStatus

if TYPE_CHECKING:
    from .rollback import RollbackPlan

DEFAULT_CONTRACT_TTL = timedelta(minutes=5)


@dataclass(frozen=True)
class RecoveryContract:
    contract_id: str
    capability: Capability
    endpoint_symbol: str
    created_at_utc: datetime
    expires_at_utc: datetime
    pre_state_snapshot: dict[str, Any]
    rollback_plan: "RollbackPlan"
    status: ContractStatus

    def is_expired(self, *, now: datetime | None = None) -> bool:
        current = now if now is not None else datetime.now(timezone.utc)
        return current >= self.expires_at_utc


class RecoveryContractStore:
    """In-memory only — never persisted, never serialized as a whole."""

    def __init__(self) -> None:
        self._contracts: dict[str, RecoveryContract] = {}

    def create(
        self,
        *,
        capability: Capability,
        endpoint_symbol: str,
        pre_state_snapshot: dict[str, Any],
        rollback_plan: "RollbackPlan",
        ttl: timedelta = DEFAULT_CONTRACT_TTL,
    ) -> RecoveryContract:
        now = datetime.now(timezone.utc)
        contract = RecoveryContract(
            contract_id=uuid.uuid4().hex,
            capability=capability,
            endpoint_symbol=endpoint_symbol,
            created_at_utc=now,
            expires_at_utc=now + ttl,
            pre_state_snapshot=pre_state_snapshot,
            rollback_plan=rollback_plan,
            status=ContractStatus.OPEN,
        )
        self._contracts[contract.contract_id] = contract
        return contract

    def get(self, contract_id: str) -> RecoveryContract | None:
        contract = self._contracts.get(contract_id)
        if contract is None:
            return None
        if contract.status == ContractStatus.OPEN and contract.is_expired():
            contract = replace(contract, status=ContractStatus.EXPIRED)
            self._contracts[contract_id] = contract
        return contract

    def mark_committed(self, contract_id: str) -> RecoveryContract | None:
        return self._transition(contract_id, ContractStatus.COMMITTED)

    def mark_rolled_back(self, contract_id: str) -> RecoveryContract | None:
        return self._transition(contract_id, ContractStatus.ROLLED_BACK)

    def _transition(self, contract_id: str, new_status: ContractStatus) -> RecoveryContract | None:
        contract = self._contracts.get(contract_id)
        if contract is None:
            return None
        contract = replace(contract, status=new_status)
        self._contracts[contract_id] = contract
        return contract
