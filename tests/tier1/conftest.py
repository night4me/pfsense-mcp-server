from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.tier1.canonical import DigestPurpose, digest_value
from pfsense_mcp.tier1.contract import ProtectedArtifact, RecoveryContract, derive_idempotency_key
from pfsense_mcp.tier1.state_machine import RecoveryState


@pytest.fixture
def contract_factory():
    def make(
        *,
        contract_id: str = "contract-001",
        operation_id: str = "operation-001",
        state: RecoveryState = RecoveryState.PREPARING,
        target_identity: object = None,
        target_precondition: object = None,
        lifecycle_locator: int = 7,
        intent: object = None,
        now: datetime | None = None,
    ) -> RecoveryContract:
        created = now or datetime.now(timezone.utc)
        identity = target_identity if target_identity is not None else {"name": "synthetic-target.invalid"}
        normalized_intent = intent if intent is not None else {"enabled": True}
        precondition = (
            target_precondition
            if target_precondition is not None
            else {"identity": identity, "revision": "synthetic-1"}
        )
        context = (Capability.ALIAS_WRITE.name, "SYNTHETIC_ENDPOINT", "PATCH")
        target_digest = digest_value(DigestPurpose.TARGET_IDENTITY, identity, context=(Capability.ALIAS_WRITE.name,))
        intent_digest = digest_value(DigestPurpose.INTENT, normalized_intent, context=context)
        snapshot_digest = digest_value(DigestPurpose.SNAPSHOT, {"enabled": False}, context=context)
        fingerprint = digest_value(DigestPurpose.TARGET_FINGERPRINT, precondition, context=context)
        idempotency = derive_idempotency_key(
            capability=Capability.ALIAS_WRITE,
            endpoint_symbol="SYNTHETIC_ENDPOINT",
            http_method="PATCH",
            target_identity_digest=target_digest,
            target_fingerprint=fingerprint,
            lifecycle_locator=lifecycle_locator,
            intent_digest=intent_digest,
            snapshot_digest=snapshot_digest,
            rollback_plan_version="synthetic-v1",
        )
        protected = ProtectedArtifact(key_id="test-key", algorithm="test-only", ciphertext=b"opaque")
        return RecoveryContract(
            contract_id=contract_id,
            operation_id=operation_id,
            idempotency_key=idempotency,
            capability=Capability.ALIAS_WRITE,
            endpoint_symbol="SYNTHETIC_ENDPOINT",
            http_method="PATCH",
            target_identity_digest=target_digest,
            target_fingerprint=fingerprint,
            lifecycle_locator=lifecycle_locator,
            intent_digest=intent_digest,
            snapshot_digest=snapshot_digest,
            rollback_plan_version="synthetic-v1",
            created_at=created,
            expires_at=created + timedelta(minutes=5),
            state=state,
            state_version=0,
            protected_target_identity=protected,
            protected_intent=protected,
            protected_snapshot=protected,
        )

    return make
