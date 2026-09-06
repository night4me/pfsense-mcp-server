"""Integration-level adversarial tests for the two-tier WRITE security
model (2026-09-06 owner-authorized Phase 1): the registry-authoritative
`security_class` mismatch pre-send refusal, the durable
`security_class_mismatch` audit reason, and the per-class
`ExecutionSecurityPolicy` witness-participation gate.

Deliberately independent of `test_executor.py`/`test_anti_rollback.py`'s
own private helpers -- this file builds its own minimal contract/store/
executor harness, mirroring their already-proven patterns, so this
file's own invariants stay legible without cross-file coupling.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.models.system_rest_api_settings import SystemRestApiSettings
from pfsense_mcp.tier1.canonical import DigestPurpose, digest_value
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.contract import ProtectedArtifact, RecoveryContract, derive_idempotency_key
from pfsense_mcp.tier1.crypto import ArtifactRole, build_nonce, encrypt_artifact
from pfsense_mcp.tier1.errors import AnchorUnavailableError, ContractValidationError
from pfsense_mcp.tier1.executor import MutationExecutor
from pfsense_mcp.tier1.policy import MutationPolicy, MutationRule
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore
from pfsense_mcp.tier1.write_security_class import (
    EXECUTION_POLICIES,
    HighAssuranceTier1ExecutionPolicy,
    StandardSealedExecutionPolicy,
    WriteSecurityClass,
)

_INTEGRITY_KEY = b"synthetic-test-integrity-key-32bytes!"
_ENCRYPTION_KEY = os.urandom(32)
_CAPABILITY = Capability.NTP_TIME_SERVER_PREFER_WRITE
_ENDPOINT_SYMBOL = "SYNTHETIC_NTP_ENDPOINT"
_HTTP_METHOD = "PATCH"
_CONTEXT = (_CAPABILITY.name, _ENDPOINT_SYMBOL, _HTTP_METHOD)


class _AcceptingVerifier:
    def verify(self, evidence: ConfirmationEvidence) -> bool:
        return evidence.proof == b"synthetic-valid-proof"


class _FakeAnchor:
    """In-memory anti-rollback anchor test double -- never a real TPM or
    network call. Tracks both `read`/`advance` calls so a test can prove
    *zero* witness contact occurred, not merely that the outcome looked
    right."""

    def __init__(self, value: int = 0) -> None:
        self.value = value
        self.read_calls = 0
        self.advance_calls: list[int] = []

    def read(self) -> int:
        self.read_calls += 1
        return self.value

    def advance(self, *, expected_current: int) -> int:
        if expected_current != self.value:
            raise AnchorUnavailableError("Anchor was advanced concurrently.")
        self.value += 1
        self.advance_calls.append(self.value)
        return self.value


class _StubReadClient:
    """Test double standing in at the executor's pfREST Read Only gate
    and at the adapter's `read_target()` -- tracks call counts so a test
    can prove zero network activity occurred for a refused contract."""

    def __init__(self, *, read_only: bool = False) -> None:
        self._read_only = read_only
        self.settings_calls = 0

    def get_system_restapi_settings(self, *, include_identifying_metadata: bool = False) -> SystemRestApiSettings:
        self.settings_calls += 1
        return SystemRestApiSettings(
            allow_development_packages=False,
            allow_pre_releases=False,
            allowed_interfaces=["lan"],
            auth_methods=["key"],
            enabled=True,
            expose_sensitive_fields=False,
            ha_sync=False,
            ha_sync_hosts=[],
            ha_sync_validate_certs=True,
            hateoas=False,
            jwt_exp=3600,
            keep_backup=True,
            log_level="info",
            log_successful_auth=True,
            login_protection=True,
            override_sensitive_fields=[],
            read_only=self._read_only,
            represent_interfaces_as="descr",
        )


class _RaisingWriteClient:
    """Any call at all is a test failure -- proves zero transport WRITE
    occurred for a refused contract."""

    def __getattr__(self, name: str):
        def _fail(*args: object, **kwargs: object) -> None:
            raise AssertionError(f"transport method {name!r} must never be called for a refused contract")

        return _fail


class _SyntheticAdapter:
    """Never actually reached by a mismatch-refused contract -- included
    only so `execute()`'s signature is satisfiable; its own methods
    raise if ever called, proving the mismatch check runs first."""

    endpoint_symbol = _ENDPOINT_SYMBOL
    http_method = _HTTP_METHOD
    capability = _CAPABILITY

    def read_target(self, read_client, natural_identity):
        raise AssertionError("adapter.read_target must never be called for a refused contract")

    def natural_identity(self, raw_target):
        raise AssertionError("adapter.natural_identity must never be called for a refused contract")

    def fingerprint(self, raw_target):
        raise AssertionError("adapter.fingerprint must never be called for a refused contract")


def _store(tmp_path, *, anchor=None) -> SqliteRecoveryContractStore:
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=_INTEGRITY_KEY,
        store_id="synthetic-store",
        confirmation_verifier=_AcceptingVerifier(),
        anti_rollback_anchor=anchor,
    )


def _encrypt(value, *, contract_id: str, role: ArtifactRole, counter: int) -> ProtectedArtifact:
    from pfsense_mcp.tier1.canonical import canonical_json

    nonce = build_nonce(epoch=0, counter=counter)
    return encrypt_artifact(
        key=_ENCRYPTION_KEY,
        key_id="enc-test",
        contract_id=contract_id,
        role=role,
        plaintext=canonical_json(value),
        nonce=nonce,
    )


def _build_contract(
    *, contract_id: str = "ntppref-001", security_class: WriteSecurityClass, now: datetime | None = None
) -> RecoveryContract:
    created = now or datetime.now(timezone.utc)
    identity_source = {"timeserver": "1.pool.ntp.org"}
    identity = {"timeserver": "1.pool.ntp.org"}
    precondition = {"prefer": False}
    intent = {"raw_target_hint": identity_source, "prefer": True}
    intent_payload = {"prefer": True}
    snapshot_payload = {"prefer": False}

    target_digest = digest_value(DigestPurpose.TARGET_IDENTITY, identity, context=(_CAPABILITY.name,))
    fingerprint_digest = digest_value(DigestPurpose.TARGET_FINGERPRINT, precondition, context=_CONTEXT)
    intent_digest = digest_value(DigestPurpose.INTENT, intent, context=_CONTEXT)
    snapshot_digest = digest_value(DigestPurpose.SNAPSHOT, snapshot_payload, context=_CONTEXT)
    idempotency = derive_idempotency_key(
        capability=_CAPABILITY,
        endpoint_symbol=_ENDPOINT_SYMBOL,
        http_method=_HTTP_METHOD,
        target_identity_digest=target_digest,
        target_fingerprint=fingerprint_digest,
        lifecycle_locator=7,
        intent_digest=intent_digest,
        snapshot_digest=snapshot_digest,
        rollback_plan_version="synthetic-v1",
    )
    return RecoveryContract(
        contract_id=contract_id,
        operation_id=f"{contract_id}-op",
        idempotency_key=idempotency,
        capability=_CAPABILITY,
        security_class=security_class,
        endpoint_symbol=_ENDPOINT_SYMBOL,
        http_method=_HTTP_METHOD,
        target_identity_digest=target_digest,
        target_fingerprint=fingerprint_digest,
        lifecycle_locator=7,
        intent_digest=intent_digest,
        snapshot_digest=snapshot_digest,
        rollback_plan_version="synthetic-v1",
        created_at=created,
        expires_at=created + timedelta(minutes=5),
        state=RecoveryState.PREPARING,
        state_version=0,
        protected_target_identity=_encrypt(
            identity_source, contract_id=contract_id, role=ArtifactRole.TARGET_IDENTITY, counter=1
        ),
        protected_intent=_encrypt(intent_payload, contract_id=contract_id, role=ArtifactRole.INTENT, counter=2),
        protected_snapshot=_encrypt(snapshot_payload, contract_id=contract_id, role=ArtifactRole.SNAPSHOT, counter=3),
    )


def _confirm(store: SqliteRecoveryContractStore, contract: RecoveryContract) -> RecoveryContract:
    store.create(contract)
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    evidence = ConfirmationEvidence(
        authority_id="synthetic-owner",
        algorithm="test-verifier",
        nonce="nonce-001",
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        target_identity_digest=contract.target_identity_digest,
        target_fingerprint=contract.target_fingerprint,
        intent_digest=contract.intent_digest,
        expires_at=contract.expires_at,
        issued_at=contract.created_at,
        proof=b"synthetic-valid-proof",
    )
    return store.confirm(contract.contract_id, evidence=evidence, expected_version=prepared.state_version)


def _executor(store, *, anchor=None, capability_security_classes) -> MutationExecutor:
    return MutationExecutor(
        store=store,
        write_client=_RaisingWriteClient(),
        read_client=_StubReadClient(),
        policy=MutationPolicy(frozenset({MutationRule(_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD)})),
        anti_rollback_anchor=anchor,
        encryption_key=_ENCRYPTION_KEY,
        capability_security_classes=capability_security_classes,
    )


# ---------------------------------------------------------------------------
# 1. security_class mismatch: fail closed, zero network, zero witness,
#    durable MAC-protected audit reason
# ---------------------------------------------------------------------------


def test_persisted_standard_cannot_downgrade_registry_high(tmp_path):
    """Registry says HIGH; contract's own persisted field claims STANDARD.
    The registry must win -- outcome is a deterministic refusal, never a
    downgraded (STANDARD) execution."""

    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    _confirm(store, contract)
    read_client = _StubReadClient()
    write_client = _RaisingWriteClient()
    executor = MutationExecutor(
        store=store,
        write_client=write_client,
        read_client=read_client,
        policy=MutationPolicy(frozenset({MutationRule(_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD)})),
        anti_rollback_anchor=anchor,
        encryption_key=_ENCRYPTION_KEY,
        capability_security_classes={_CAPABILITY: WriteSecurityClass.HIGH_ASSURANCE_TIER1},
    )

    outcome = executor.execute(contract.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    assert store.load(contract.contract_id).state is RecoveryState.FAILED
    assert read_client.settings_calls == 0
    assert anchor.read_calls == 0
    assert anchor.advance_calls == []
    events = store.audit_events(contract.contract_id)
    assert events[-1]["event_type"] == "security_class_mismatch"
    assert events[-1]["previous_state"] == RecoveryState.PREPARED.value
    assert events[-1]["current_state"] == RecoveryState.FAILED.value


def test_persisted_high_cannot_alter_registry_selected_standard(tmp_path):
    """Registry says STANDARD; contract's own persisted field claims
    HIGH. The registry must win -- outcome is a deterministic refusal,
    never an upgraded (HIGH, witness-consuming) execution and never a
    silent STANDARD execution either."""

    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1)
    _confirm(store, contract)
    read_client = _StubReadClient()
    executor = MutationExecutor(
        store=store,
        write_client=_RaisingWriteClient(),
        read_client=read_client,
        policy=MutationPolicy(frozenset({MutationRule(_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD)})),
        anti_rollback_anchor=anchor,
        encryption_key=_ENCRYPTION_KEY,
        capability_security_classes={_CAPABILITY: WriteSecurityClass.STANDARD_SEALED_WRITE},
    )

    outcome = executor.execute(contract.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    assert read_client.settings_calls == 0
    assert anchor.read_calls == 0
    assert anchor.advance_calls == []
    events = store.audit_events(contract.contract_id)
    assert events[-1]["event_type"] == "security_class_mismatch"


def test_mismatch_never_becomes_reconciliation(tmp_path):
    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    _confirm(store, contract)
    executor = _executor(
        store, anchor=anchor, capability_security_classes={_CAPABILITY: WriteSecurityClass.HIGH_ASSURANCE_TIER1}
    )

    outcome = executor.execute(contract.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is not RecoveryState.RECONCILIATION
    assert store.load(contract.contract_id).state is not RecoveryState.RECONCILIATION


def test_unregistered_capability_is_refused_not_silently_permitted(tmp_path):
    """A capability entirely absent from the registry mapping must also
    fail closed, not default to any class."""

    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1)
    _confirm(store, contract)
    executor = _executor(
        store,
        anchor=anchor,
        capability_security_classes={Capability.ALIAS_WRITE: WriteSecurityClass.HIGH_ASSURANCE_TIER1},
    )

    outcome = executor.execute(contract.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    events = store.audit_events(contract.contract_id)
    assert events[-1]["event_type"] == "security_class_mismatch"


# ---------------------------------------------------------------------------
# 2. Execution policy selection: STANDARD never touches the witness,
#    HIGH still does (regression proof)
# ---------------------------------------------------------------------------


def test_standard_execution_policy_performs_zero_witness_contact():
    policy = StandardSealedExecutionPolicy()
    assert policy.participates_in_witness() is False
    assert policy.security_class == WriteSecurityClass.STANDARD_SEALED_WRITE


def test_high_assurance_execution_policy_participates_in_witness():
    policy = HighAssuranceTier1ExecutionPolicy()
    assert policy.participates_in_witness() is True
    assert policy.security_class == WriteSecurityClass.HIGH_ASSURANCE_TIER1


def test_execution_policies_mapping_is_closed_and_exhaustive():
    assert set(EXECUTION_POLICIES) == set(WriteSecurityClass)


def test_transition_to_executing_with_standard_policy_never_touches_the_anchor(tmp_path):
    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)

    executing = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
        execution_policy=StandardSealedExecutionPolicy(),
    )

    assert executing.state is RecoveryState.EXECUTING
    assert anchor.read_calls == 0
    assert anchor.advance_calls == []


def test_transition_to_executing_with_high_assurance_policy_still_advances_the_anchor(tmp_path):
    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1)
    confirmed = _confirm(store, contract)

    executing = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
        execution_policy=HighAssuranceTier1ExecutionPolicy(),
    )

    assert executing.state is RecoveryState.EXECUTING
    assert anchor.read_calls == 1
    assert anchor.advance_calls == [1]


def test_transition_to_executing_without_execution_policy_fails_closed(tmp_path):
    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1)
    confirmed = _confirm(store, contract)

    with pytest.raises(ContractValidationError, match="explicit execution security policy"):
        store.transition(
            contract.contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=confirmed.state_version,
            target_state=RecoveryState.EXECUTING,
        )
    assert anchor.read_calls == 0
    assert anchor.advance_calls == []


def test_transition_event_type_defaults_to_state_transition(tmp_path):
    store = _store(tmp_path)
    contract = _build_contract(security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1)
    store.create(contract)

    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )

    events = store.audit_events(contract.contract_id)
    assert events[-1]["event_type"] == "state_transition"
    assert prepared.state is RecoveryState.PREPARED


def test_transition_rejects_empty_event_type(tmp_path):
    store = _store(tmp_path)
    contract = _build_contract(security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1)
    store.create(contract)

    with pytest.raises(ContractValidationError, match="transition event type is invalid"):
        store.transition(
            contract.contract_id,
            expected_state=RecoveryState.PREPARING,
            expected_version=0,
            target_state=RecoveryState.PREPARED,
            event_type="",
        )


# ---------------------------------------------------------------------------
# 3. Construction-time fail-closed invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_class", ["standard_sealed_write", "high_assurance_tier1", 1, None])
def test_recovery_contract_rejects_a_non_enum_security_class(bad_class):
    with pytest.raises(ContractValidationError):
        _build_contract(security_class=bad_class)  # type: ignore[arg-type]


def test_mutation_executor_rejects_empty_capability_security_classes(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ContractValidationError, match="capability security class registry is invalid"):
        MutationExecutor(
            store=store,
            write_client=_RaisingWriteClient(),
            read_client=_StubReadClient(),
            policy=MutationPolicy(frozenset({MutationRule(_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD)})),
            anti_rollback_anchor=None,
            encryption_key=_ENCRYPTION_KEY,
            capability_security_classes={},
        )


def test_mutation_executor_rejects_a_malformed_capability_security_classes_mapping(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(ContractValidationError, match="capability security class registry is invalid"):
        MutationExecutor(
            store=store,
            write_client=_RaisingWriteClient(),
            read_client=_StubReadClient(),
            policy=MutationPolicy(frozenset({MutationRule(_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD)})),
            anti_rollback_anchor=None,
            encryption_key=_ENCRYPTION_KEY,
            capability_security_classes={"not-a-capability": WriteSecurityClass.HIGH_ASSURANCE_TIER1},  # type: ignore[dict-item]
        )
