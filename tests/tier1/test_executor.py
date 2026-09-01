from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import BaseModel

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.capabilities import Capability
from pfsense_mcp.errors import WriteNotAllowedError
from pfsense_mcp.tier1.canonical import DigestPurpose, canonical_json, digest_value
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.contract import ProtectedArtifact, RecoveryContract, derive_idempotency_key
from pfsense_mcp.tier1.crypto import ArtifactRole, build_nonce, encrypt_artifact
from pfsense_mcp.tier1.errors import (
    ContractBindingError,
    ContractConflictError,
    ContractNotFoundError,
    ContractValidationError,
)
from pfsense_mcp.tier1.executor import MutationExecutor, ResolvedTransportTarget
from pfsense_mcp.tier1.policy import MutationPolicy, MutationPolicyError, MutationRule
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore
from pfsense_mcp.transport.mock import MockTransport
from pfsense_mcp.write_api_client import TransportConnectionError, TransportTimeoutError, WriteApiClient
from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints

_INTEGRITY_KEY = b"synthetic-test-integrity-key-32bytes!"
_ENCRYPTION_KEY = os.urandom(32)
_CAPABILITY = Capability.ALIAS_WRITE
_ENDPOINT_SYMBOL = "SYNTHETIC_ENDPOINT"
_HTTP_METHOD = "PATCH"
_CONTEXT = (_CAPABILITY.name, _ENDPOINT_SYMBOL, _HTTP_METHOD)


class _SyntheticRequest(BaseModel):
    id: int
    descr: str


class _SyntheticAdapter:
    """Test-only CapabilityAdapter -- never a real capability adapter,
    per sealed_executor.md's Required tests guidance. Every method is a
    thin, overridable stub so each test can drive exactly one executor
    decision point."""

    capability = _CAPABILITY
    endpoint_symbol = _ENDPOINT_SYMBOL
    http_method = _HTTP_METHOD

    def __init__(
        self,
        *,
        reads,
        semantically_verified: bool = True,
        rollback_verified: bool = True,
        read_error: Exception | None = None,
        read_error_on_call: int = 0,
    ) -> None:
        self._reads = list(reads)
        self._read_index = 0
        self._read_error = read_error
        self._read_error_on_call = read_error_on_call
        self._semantically_verified = semantically_verified
        self._rollback_verified = rollback_verified
        self.read_calls: list[object] = []

    def read_target(self, read_client, natural_identity):
        self.read_calls.append(natural_identity)
        call_index = len(self.read_calls) - 1
        if self._read_error is not None and call_index == self._read_error_on_call:
            raise self._read_error
        index = min(self._read_index, len(self._reads) - 1)
        value = dict(self._reads[index])
        value.setdefault("id", 7)
        self._read_index += 1
        return value

    def natural_identity(self, raw_target):
        return {"name": raw_target["name"]}

    def fingerprint(self, raw_target):
        return {"descr": raw_target["descr"], "revision": raw_target["revision"]}

    def transport_locator(self, raw_target):
        return raw_target["id"]

    def build_request(self, intent, target):
        return _SyntheticRequest(id=target.numeric_locator, descr=intent["descr"])

    def parse_response(self, raw_response):
        return {"status_code": raw_response.status_code}

    def is_semantically_verified(self, pre, post, intent):
        return self._semantically_verified and post["descr"] == intent["descr"] and post["revision"] == pre["revision"]

    def build_rollback_request(self, pre, target):
        return _SyntheticRequest(id=target.numeric_locator, descr=pre["descr"])

    def is_rollback_verified(self, pre, post_rollback):
        return self._rollback_verified and pre == {
            "descr": post_rollback["descr"],
            "revision": post_rollback["revision"],
        }


class _AdapterMissingSemanticVerification:
    """ADR-036 W0 gap 4/10: a `CapabilityAdapter`-shaped object that omits
    `is_semantically_verified` entirely -- not merely one that implements
    it and returns `False` (see `_SyntheticAdapter(semantically_verified=
    False)` above), but one that never defines the method at all. Proves
    the executor cannot accept transport success as mutation success for
    an adapter that skips this required contract member; structural
    typing (`Protocol`, mypy-only) doesn't stop a caller who ignores
    type-checking from wiring one in at runtime. Deliberately does NOT
    subclass `_SyntheticAdapter`, so nothing is inherited."""

    capability = _CAPABILITY
    endpoint_symbol = _ENDPOINT_SYMBOL
    http_method = _HTTP_METHOD

    def __init__(self, *, reads) -> None:
        self._reads = list(reads)
        self._read_index = 0
        self.read_calls: list[object] = []

    def read_target(self, read_client, natural_identity):
        self.read_calls.append(natural_identity)
        index = min(self._read_index, len(self._reads) - 1)
        value = dict(self._reads[index])
        value.setdefault("id", 7)
        self._read_index += 1
        return value

    def natural_identity(self, raw_target):
        return {"name": raw_target["name"]}

    def fingerprint(self, raw_target):
        return {"descr": raw_target["descr"], "revision": raw_target["revision"]}

    def transport_locator(self, raw_target):
        return raw_target["id"]

    def build_request(self, intent, target):
        return _SyntheticRequest(id=target.numeric_locator, descr=intent["descr"])

    def parse_response(self, raw_response):
        return {"status_code": raw_response.status_code}

    # Deliberately no is_semantically_verified: that is the point of this test double.


class _RaisingWriteClient:
    """Stands in for WriteApiClient in tests that only need to drive
    MutationExecutor._send()'s exception classification -- never a real
    write client, and never wired to any transport."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.calls = 0

    def send_for_tier1(self, *, endpoint_symbol, http_method, body):
        self.calls += 1
        raise self._exc


class _AcceptingVerifier:
    def verify(self, evidence):
        return evidence.proof == b"synthetic-valid-proof"


def _store(tmp_path):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=_INTEGRITY_KEY,
        store_id="synthetic-store",
        confirmation_verifier=_AcceptingVerifier(),
    )


def _encrypt(payload: object, *, contract_id: str, role: ArtifactRole, counter: int) -> ProtectedArtifact:
    nonce = build_nonce(epoch=0, counter=counter)
    return encrypt_artifact(
        key=_ENCRYPTION_KEY,
        key_id="enc-0001",
        contract_id=contract_id,
        role=role,
        plaintext=canonical_json(payload),
        nonce=nonce,
    )


def _identity_source(*, revision: str = "synthetic-1", descr: str = "original-description") -> dict:
    return {"name": "synthetic-target.invalid", "revision": revision, "descr": descr}


def _build_contract(
    *,
    contract_id: str = "contract-001",
    now: datetime | None = None,
    revision: str = "synthetic-1",
    descr: str = "updated-description",
    original_descr: str = "original-description",
) -> tuple[RecoveryContract, dict]:
    created = now or datetime.now(timezone.utc)
    identity_source = _identity_source(revision=revision, descr=original_descr)
    identity = {"name": identity_source["name"]}
    precondition = {"descr": identity_source["descr"], "revision": identity_source["revision"]}
    intent = {"raw_target_hint": identity_source, "descr": descr}
    intent_payload = {"descr": descr}
    snapshot_payload = {"descr": original_descr, "revision": revision}

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

    contract = RecoveryContract(
        contract_id=contract_id,
        operation_id="operation-001",
        idempotency_key=idempotency,
        capability=_CAPABILITY,
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
    return contract, intent


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


def _verified(store: SqliteRecoveryContractStore, contract: RecoveryContract) -> RecoveryContract:
    confirmed = _confirm(store, contract)
    executing = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    verified_fingerprint = digest_value(
        DigestPurpose.TARGET_FINGERPRINT,
        {"descr": "updated-description", "revision": "synthetic-1"},
        context=_CONTEXT,
    )
    return store.mark_execution_verified(
        contract.contract_id,
        expected_version=executing.state_version,
        verified_target_fingerprint=verified_fingerprint,
        verified_lifecycle_locator=executing.lifecycle_locator,
    )


def _forward_reconciliation(store: SqliteRecoveryContractStore, contract: RecoveryContract) -> RecoveryContract:
    confirmed = _confirm(store, contract)
    executing = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    return store.transition(
        contract.contract_id,
        expected_state=RecoveryState.EXECUTING,
        expected_version=executing.state_version,
        target_state=RecoveryState.RECONCILIATION,
    )


def _rollback_reconciliation(store: SqliteRecoveryContractStore, contract: RecoveryContract) -> RecoveryContract:
    verified = _verified(store, contract)
    rolling_back = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.VERIFIED,
        expected_version=verified.state_version,
        target_state=RecoveryState.ROLLING_BACK,
    )
    return store.transition(
        contract.contract_id,
        expected_state=RecoveryState.ROLLING_BACK,
        expected_version=rolling_back.state_version,
        target_state=RecoveryState.RECONCILIATION,
    )


def _policy() -> MutationPolicy:
    return MutationPolicy(frozenset({MutationRule(_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD)}))


def _write_client(monkeypatch, *, verified: bool = True, http_method: str = _HTTP_METHOD):
    monkeypatch.setattr(
        WriteEndpoints,
        _ENDPOINT_SYMBOL,
        WriteEndpointInfo(
            path_suffix="/synthetic",
            http_method=http_method,
            verified=verified,
            min_api_version=ApiVersion.V2,
            reversible=True,
            dry_run_supported=True,
        ),
        raising=False,
    )
    transport = MockTransport()
    client = WriteApiClient(transport, identity="test-executor", api_version=ApiVersion.V2)
    return client, transport


def _executor(store, write_client, *, clock=None) -> MutationExecutor:
    kwargs = {} if clock is None else {"clock": clock}
    return MutationExecutor(
        store=store,
        write_client=write_client,
        read_client=object(),
        policy=_policy(),
        anti_rollback_anchor=None,
        encryption_key=_ENCRYPTION_KEY,
        **kwargs,
    )


def test_reconciliation_observation_is_fresh_read_only_and_minimal(tmp_path):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    reconciled = _forward_reconciliation(store, contract)
    write_client = _RaisingWriteClient(RuntimeError("mutation must not be called"))
    executor = _executor(store, write_client)
    adapter = _SyntheticAdapter(
        reads=[
            {
                "name": "synthetic-target.invalid",
                "revision": "synthetic-1",
                "descr": "updated-description",
            }
        ]
    )
    events_before = store.audit_events(contract.contract_id)

    observed = executor.observe_reconciliation_target(contract.contract_id, adapter=adapter)

    assert observed.contract_id == contract.contract_id
    assert observed.operation_id == contract.operation_id
    assert observed.state_version == reconciled.state_version
    assert observed.uncertainty_origin is RecoveryState.EXECUTING
    assert observed.target_fingerprint == digest_value(
        DigestPurpose.TARGET_FINGERPRINT,
        {"descr": "updated-description", "revision": "synthetic-1"},
        context=_CONTEXT,
    )
    assert observed.lifecycle_locator == 7
    assert adapter.read_calls == [_identity_source()]
    assert write_client.calls == 0
    assert store.load(contract.contract_id) == reconciled
    assert store.audit_events(contract.contract_id) == events_before
    assert set(observed.__dataclass_fields__) == {
        "contract_id",
        "operation_id",
        "state_version",
        "uncertainty_origin",
        "target_fingerprint",
        "lifecycle_locator",
    }


def test_reconciliation_observation_preserves_rollback_origin(tmp_path):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    reconciled = _rollback_reconciliation(store, contract)
    write_client = _RaisingWriteClient(RuntimeError("mutation must not be called"))
    executor = _executor(store, write_client)

    observed = executor.observe_reconciliation_target(
        contract.contract_id,
        adapter=_SyntheticAdapter(
            reads=[
                {
                    "name": "synthetic-target.invalid",
                    "revision": "synthetic-1",
                    "descr": "updated-description",
                }
            ]
        ),
    )

    assert observed.uncertainty_origin is RecoveryState.ROLLING_BACK
    assert observed.state_version == reconciled.state_version
    assert write_client.calls == 0


@pytest.mark.parametrize(
    ("raw_target", "read_error"),
    [
        pytest.param(
            None,
            LookupError("missing authoritative target"),
            id="missing-target",
        ),
        pytest.param(
            None,
            LookupError("ambiguous authoritative target"),
            id="ambiguous-target",
        ),
        pytest.param(
            {"name": "substituted.invalid", "revision": "synthetic-1", "descr": "updated-description"},
            None,
            id="identity-mismatch",
        ),
        pytest.param(
            {
                "name": "synthetic-target.invalid",
                "revision": "synthetic-1",
                "descr": "updated-description",
                "id": 8,
            },
            None,
            id="locator-drift",
        ),
        pytest.param(
            {"name": "synthetic-target.invalid", "descr": "updated-description"},
            None,
            id="malformed-fingerprint",
        ),
        pytest.param(None, RuntimeError("sensitive transport detail"), id="read-transport-failure"),
    ],
)
def test_reconciliation_observation_failures_are_zero_send_zero_transition(tmp_path, raw_target, read_error):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    reconciled = _forward_reconciliation(store, contract)
    write_client = _RaisingWriteClient(RuntimeError("mutation must not be called"))
    executor = _executor(store, write_client)
    adapter = _SyntheticAdapter(
        reads=[] if raw_target is None else [raw_target],
        read_error=read_error,
    )
    events_before = store.audit_events(contract.contract_id)

    with pytest.raises(
        ContractValidationError,
        match="Authoritative reconciliation target observation failed",
    ) as caught:
        executor.observe_reconciliation_target(contract.contract_id, adapter=adapter)

    assert "sensitive transport detail" not in str(caught.value)
    assert len(adapter.read_calls) == 1
    assert write_client.calls == 0
    assert store.load(contract.contract_id) == reconciled
    assert store.audit_events(contract.contract_id) == events_before


def test_reconciliation_observation_refuses_wrong_state_and_binding(tmp_path):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    store.create(contract)
    write_client = _RaisingWriteClient(RuntimeError("mutation must not be called"))
    executor = _executor(store, write_client)
    adapter = _SyntheticAdapter(reads=[])

    with pytest.raises(ContractConflictError, match="not in RECONCILIATION"):
        executor.observe_reconciliation_target(contract.contract_id, adapter=adapter)
    with pytest.raises(ContractNotFoundError):
        executor.observe_reconciliation_target("unknown-contract", adapter=adapter)

    class _WrongEndpointAdapter(_SyntheticAdapter):
        endpoint_symbol = "OTHER_ENDPOINT"

    binding_store = _store(tmp_path / "binding")
    binding_contract, _intent = _build_contract(contract_id="contract-binding")
    reconciled = _forward_reconciliation(binding_store, binding_contract)
    binding_executor = _executor(binding_store, write_client)
    events_before = binding_store.audit_events(binding_contract.contract_id)
    with pytest.raises(ContractValidationError, match="adapter does not match"):
        binding_executor.observe_reconciliation_target(
            binding_contract.contract_id, adapter=_WrongEndpointAdapter(reads=[])
        )

    assert adapter.read_calls == []
    assert write_client.calls == 0
    assert binding_store.load(binding_contract.contract_id) == reconciled
    assert binding_store.audit_events(binding_contract.contract_id) == events_before


def test_reconciliation_observation_requires_matching_authenticated_history(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    reconciled = _forward_reconciliation(store, contract)
    write_client = _RaisingWriteClient(RuntimeError("mutation must not be called"))
    executor = _executor(store, write_client)
    events_before = store.audit_events(contract.contract_id)
    malformed_events = (*events_before[:-1], {**events_before[-1], "state_version": 999})
    monkeypatch.setattr(store, "audit_events", lambda _contract_id: malformed_events)

    with pytest.raises(ContractValidationError, match="history does not match"):
        executor.observe_reconciliation_target(contract.contract_id, adapter=_SyntheticAdapter(reads=[]))

    assert write_client.calls == 0
    assert store.load(contract.contract_id) == reconciled


def test_reconciliation_observation_after_executor_reconstruction_is_fresh(tmp_path):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    confirmed = _confirm(store, contract)
    store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    write_client = _RaisingWriteClient(RuntimeError("mutation must not be called"))

    reconstructed = _executor(store, write_client)
    adapter = _SyntheticAdapter(
        reads=[
            {
                "name": "synthetic-target.invalid",
                "revision": "synthetic-1",
                "descr": "updated-after-restart",
            }
        ]
    )
    observed = reconstructed.observe_reconciliation_target(contract.contract_id, adapter=adapter)

    assert observed.uncertainty_origin is RecoveryState.EXECUTING
    assert observed.target_fingerprint == digest_value(
        DigestPurpose.TARGET_FINGERPRINT,
        {"descr": "updated-after-restart", "revision": "synthetic-1"},
        context=_CONTEXT,
    )
    assert adapter.read_calls == [_identity_source()]
    assert write_client.calls == 0


def test_execute_happy_path_reaches_verified(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"},
        ]
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.VERIFIED
    loaded = store.load(contract.contract_id)
    assert loaded.verified_target_fingerprint == digest_value(
        DigestPurpose.TARGET_FINGERPRINT,
        {"descr": "updated-description", "revision": "synthetic-1"},
        context=_CONTEXT,
    )
    assert transport.calls == [("PATCH", "/api/v2/synthetic")]
    assert transport.request_bodies == [b'{"id":7,"descr":"updated-description"}']


def test_generic_verified_transition_cannot_omit_post_forward_fingerprint(tmp_path):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    confirmed = _confirm(store, contract)
    executing = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )

    with pytest.raises(ContractConflictError, match="post-forward fingerprint"):
        store.transition(
            contract.contract_id,
            expected_state=RecoveryState.EXECUTING,
            expected_version=executing.state_version,
            target_state=RecoveryState.VERIFIED,
        )


def test_execute_requires_prepared_state(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    store.create(contract)
    write_client, _transport = _write_client(monkeypatch)
    executor = _executor(store, write_client)

    with pytest.raises(ContractConflictError):
        executor.execute(contract.contract_id, adapter=_SyntheticAdapter(reads=[]), intent=intent)


def test_execute_refuses_when_policy_does_not_authorize(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    executor = MutationExecutor(
        store=store,
        write_client=write_client,
        read_client=object(),
        policy=MutationPolicy(frozenset()),
        anti_rollback_anchor=None,
        encryption_key=_ENCRYPTION_KEY,
    )

    with pytest.raises(MutationPolicyError):
        executor.execute(contract.contract_id, adapter=_SyntheticAdapter(reads=[]), intent=intent)

    assert transport.calls == []
    assert store.load(contract.contract_id).state == RecoveryState.PREPARED


def test_execute_refuses_binding_mismatch(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    executor = _executor(store, write_client)
    tampered_intent = {**intent, "descr": "attacker-supplied-description"}

    with pytest.raises(ContractBindingError):
        executor.execute(contract.contract_id, adapter=_SyntheticAdapter(reads=[]), intent=tampered_intent)

    assert transport.calls == []
    assert store.load(contract.contract_id).state == RecoveryState.PREPARED


def test_execute_fails_on_fingerprint_drift_before_send(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "drifted-revision", "descr": "whatever"}]
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.FAILED
    assert "fingerprint drift" in outcome.detail
    assert transport.calls == []


def test_execute_reaches_failed_when_write_not_allowed(tmp_path):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client = _RaisingWriteClient(WriteNotAllowedError("not in the write allow-list"))
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"}]
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.FAILED
    assert write_client.calls == 1


def test_execute_reaches_failed_on_connection_error(tmp_path):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client = _RaisingWriteClient(TransportConnectionError("boom"))
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"}]
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.FAILED


def test_execute_reaches_reconciliation_on_timeout(tmp_path):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client = _RaisingWriteClient(TransportTimeoutError("boom"))
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"}]
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.RECONCILIATION


def test_execute_reaches_failed_when_response_not_semantically_verified(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
        ],
        semantically_verified=False,
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.FAILED
    assert "not semantically verified" in outcome.detail


def test_execute_reaches_reconciliation_when_adapter_lacks_semantic_verification(tmp_path, monkeypatch):
    """ADR-036 W0 gap 4/10: an adapter that never implements
    `is_semantically_verified` at all cannot slip transport success
    through as mutation success. The executor's own AttributeError on
    calling the missing method is caught by `execute()`'s existing
    post-send try/except (same as any other post-send verification
    failure) and lands in RECONCILIATION -- fail-closed-ambiguous,
    never a verified/success outcome."""
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _AdapterMissingSemanticVerification(
        reads=[
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"},
        ],
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.RECONCILIATION
    assert "post-send verification failed" in outcome.detail


def test_execute_reaches_failed_on_client_error_response(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=422, text='{"error": "bad request"}')
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"}]
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.FAILED


def test_execute_reaches_reconciliation_on_server_error_response(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=500, text='{"error": "internal"}')
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"}]
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.RECONCILIATION


def test_execute_reaches_reconciliation_when_post_send_read_raises(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"}],
        read_error=RuntimeError("post-send read failed"),
        read_error_on_call=1,
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.RECONCILIATION


def test_execute_fails_when_pre_send_read_raises(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    adapter = _SyntheticAdapter(reads=[], read_error=RuntimeError("no such target"), read_error_on_call=0)
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.FAILED
    assert "no such target" not in outcome.detail
    assert "RuntimeError" in outcome.detail
    assert transport.calls == []


def test_execute_audit_trail_covers_every_transition(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"},
        ]
    )
    executor = _executor(store, write_client)

    executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    events = store.audit_events(contract.contract_id)
    observed_states = [event["current_state"] for event in events]
    # contract_created (PREPARING) -> state_transition (PREPARED) ->
    # contract_confirmed (still PREPARED, confirmation only bumps the
    # version) -> state_transition (EXECUTING) -> state_transition
    # (VERIFIED): every transition the executor drives is present, plus
    # the two _confirm() helper steps that ran before it.
    assert observed_states == [
        RecoveryState.PREPARING.value,
        RecoveryState.PREPARED.value,
        RecoveryState.PREPARED.value,
        RecoveryState.EXECUTING.value,
        RecoveryState.VERIFIED.value,
    ]
    assert [event["event_type"] for event in events] == [
        "contract_created",
        "state_transition",
        "contract_confirmed",
        "state_transition",
        "state_transition",
    ]


def test_rollback_requires_verified_state(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    _confirm(store, contract)
    write_client, _transport = _write_client(monkeypatch)
    executor = _executor(store, write_client)

    with pytest.raises(ContractConflictError):
        executor.rollback(contract.contract_id, adapter=_SyntheticAdapter(reads=[]))


def test_rollback_happy_path_reaches_rolled_back(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    _verified(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"},
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
        ]
    )
    executor = _executor(store, write_client)

    outcome = executor.rollback(contract.contract_id, adapter=adapter)

    assert outcome.state == RecoveryState.ROLLED_BACK
    assert transport.calls == [("PATCH", "/api/v2/synthetic")]
    assert transport.request_bodies == [b'{"id":7,"descr":"original-description"}']


def test_execute_uses_fresh_stable_lifecycle_locator(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[
            {"id": 7, "name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
            {"id": 7, "name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"},
        ]
    )

    outcome = _executor(store, write_client).execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.VERIFIED
    assert transport.request_bodies == [b'{"id":7,"descr":"updated-description"}']


@pytest.mark.parametrize("new_locator", [9, 10])
def test_execute_rejects_unproven_incarnation_continuity_even_with_identical_fingerprint(
    tmp_path, monkeypatch, new_locator
):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    adapter = _SyntheticAdapter(
        reads=[
            {
                "id": new_locator,
                "name": "synthetic-target.invalid",
                "revision": "synthetic-1",
                "descr": "original-description",
            }
        ]
    )

    outcome = _executor(store, write_client).execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.FAILED
    assert outcome.detail == "target incarnation continuity unproven before send"
    assert transport.calls == []


def test_execute_rejects_transport_projection_for_another_semantic_target(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    adapter = _SyntheticAdapter(
        reads=[{"id": 7, "name": "other.invalid", "revision": "synthetic-1", "descr": "original-description"}]
    )

    outcome = _executor(store, write_client).execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.FAILED
    assert outcome.detail == "target incarnation continuity unproven before send"
    assert transport.calls == []


def test_adapter_request_projection_is_stateless_and_caller_cannot_inject_locator():
    adapter = _SyntheticAdapter(reads=[])
    identity_digest = "a" * 64
    first = adapter.build_request(
        {"descr": "first"}, ResolvedTransportTarget(numeric_locator=7, target_identity_digest=identity_digest)
    )
    second = adapter.build_request(
        {"descr": "second"}, ResolvedTransportTarget(numeric_locator=9, target_identity_digest=identity_digest)
    )

    assert (first.id, second.id) == (7, 9)
    assert "locator" not in MutationExecutor.execute.__annotations__


def test_rollback_rejects_changed_lifecycle_locator_after_verified_b(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    _verified(store, contract)
    write_client, transport = _write_client(monkeypatch)
    adapter = _SyntheticAdapter(
        reads=[{"id": 9, "name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"}]
    )

    outcome = _executor(store, write_client).rollback(contract.contract_id, adapter=adapter)

    assert outcome.state == RecoveryState.ROLLBACK_FAILED
    assert outcome.detail == "target incarnation continuity unproven before rollback"
    assert transport.calls == []


def test_rollback_fails_on_unrelated_change_conflict(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    _verified(store, contract)
    write_client, transport = _write_client(monkeypatch)
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "unrelated-change", "descr": "whatever"}]
    )
    executor = _executor(store, write_client)

    outcome = executor.rollback(contract.contract_id, adapter=adapter)

    assert outcome.state == RecoveryState.ROLLBACK_FAILED
    assert "unrelated change" in outcome.detail
    assert transport.calls == []


def test_rollback_rejects_concurrent_description_change(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    _verified(store, contract)
    write_client, transport = _write_client(monkeypatch)
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "concurrent-description"}]
    )
    executor = _executor(store, write_client)

    outcome = executor.rollback(contract.contract_id, adapter=adapter)

    assert outcome.state == RecoveryState.ROLLBACK_FAILED
    assert "unrelated change" in outcome.detail
    assert transport.calls == []


def test_execute_postcondition_mismatch_does_not_seal_verified_fingerprint(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "unexpected-description"},
        ],
        semantically_verified=False,
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.FAILED
    assert store.load(contract.contract_id).verified_target_fingerprint is None


def test_execute_post_read_locator_change_enters_reconciliation(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[
            {"id": 7, "name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
            {"id": 9, "name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"},
        ]
    )

    outcome = _executor(store, write_client).execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.RECONCILIATION
    assert transport.calls == [("PATCH", "/api/v2/synthetic")]
    assert store.load(contract.contract_id).verified_target_fingerprint is None


def test_malformed_pre_send_fingerprint_fails_closed_with_zero_send(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    adapter = _SyntheticAdapter(reads=[{"id": 7, "name": "synthetic-target.invalid", "descr": "original-description"}])

    outcome = _executor(store, write_client).execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.FAILED
    assert outcome.detail == "pre-send target validation failed"
    assert transport.calls == []


def test_rollback_reaches_reconciliation_on_ambiguous_send(tmp_path):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    _verified(store, contract)
    write_client = _RaisingWriteClient(TransportTimeoutError("boom"))
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"}]
    )
    executor = _executor(store, write_client)

    outcome = executor.rollback(contract.contract_id, adapter=adapter)

    assert outcome.state == RecoveryState.RECONCILIATION


def test_rollback_fails_when_not_rollback_verified(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    _verified(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"},
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"},
        ],
        rollback_verified=False,
    )
    executor = _executor(store, write_client)

    outcome = executor.rollback(contract.contract_id, adapter=adapter)

    assert outcome.state == RecoveryState.ROLLBACK_FAILED


def test_rollback_post_read_locator_change_enters_reconciliation(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    _verified(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[
            {"id": 7, "name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"},
            {"id": 9, "name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
        ]
    )

    outcome = _executor(store, write_client).rollback(contract.contract_id, adapter=adapter)

    assert outcome.state == RecoveryState.RECONCILIATION
    assert transport.calls == [("PATCH", "/api/v2/synthetic")]


def test_malformed_pre_rollback_fingerprint_fails_closed_with_zero_send(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, _intent = _build_contract()
    _verified(store, contract)
    write_client, transport = _write_client(monkeypatch)
    adapter = _SyntheticAdapter(reads=[{"id": 7, "name": "synthetic-target.invalid", "descr": "updated-description"}])

    outcome = _executor(store, write_client).rollback(contract.contract_id, adapter=adapter)

    assert outcome.state == RecoveryState.ROLLBACK_FAILED
    assert outcome.detail == "pre-rollback target validation failed"
    assert transport.calls == []


# -- ADR-029: acceptance_context threading -------------------------------


_ACCEPTANCE_IDENTITY = "pfsense_lab1"  # AcceptanceExecutionContext.__post_init__ pins this exact value


def _acceptance_context():
    from pfsense_mcp.tier1.acceptance import AcceptanceExecutionContext

    return AcceptanceExecutionContext(
        endpoint_symbol=_ENDPOINT_SYMBOL,
        http_method=_HTTP_METHOD,
        target_identity=_ACCEPTANCE_IDENTITY,  # must match _acceptance_write_client()'s identity below
        issued_at=datetime.now(timezone.utc),
    )


def _acceptance_write_client(monkeypatch, *, verified: bool = False, acceptance_eligible: bool = True):
    monkeypatch.setattr(
        WriteEndpoints,
        _ENDPOINT_SYMBOL,
        WriteEndpointInfo(
            path_suffix="/synthetic",
            http_method=_HTTP_METHOD,
            verified=verified,
            min_api_version=ApiVersion.V2,
            reversible=True,
            dry_run_supported=True,
            acceptance_eligible=acceptance_eligible,
        ),
        raising=False,
    )
    transport = MockTransport()
    client = WriteApiClient(transport, identity=_ACCEPTANCE_IDENTITY, api_version=ApiVersion.V2)
    return client, transport


def test_execute_with_acceptance_context_reaches_verified_on_an_unverified_endpoint(tmp_path, monkeypatch):
    """The core proof: an endpoint that is verified=False (so the normal
    path refuses) can still reach VERIFIED when a valid acceptance_context
    is supplied -- because acceptance_eligible=True routes _send() to
    send_for_tier1_acceptance() instead, and every other executor check
    (PREPARED/confirmed/unexpired, policy, bindings, fingerprint,
    post-send verification) is the exact same code, unchanged."""

    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _acceptance_write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"},
        ]
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(
        contract.contract_id, adapter=adapter, intent=intent, acceptance_context=_acceptance_context()
    )

    assert outcome.state == RecoveryState.VERIFIED
    assert transport.calls == [("PATCH", "/api/v2/synthetic")]


def test_execute_without_acceptance_context_still_refuses_the_same_unverified_endpoint(tmp_path, monkeypatch):
    """Regression: omitting acceptance_context (the default, every normal
    caller) on the exact same acceptance_eligible-but-unverified endpoint
    must still refuse -- acceptance_eligible alone grants nothing without
    an explicit, valid context."""

    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _acceptance_write_client(monkeypatch)
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"}]
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.FAILED
    assert transport.calls == []


def test_execute_with_acceptance_context_refuses_second_endpoint_not_acceptance_eligible(tmp_path, monkeypatch):
    store = _store(tmp_path)
    contract, intent = _build_contract()
    _confirm(store, contract)
    write_client, transport = _acceptance_write_client(monkeypatch, acceptance_eligible=False)
    adapter = _SyntheticAdapter(
        reads=[{"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"}]
    )
    executor = _executor(store, write_client)

    outcome = executor.execute(
        contract.contract_id, adapter=adapter, intent=intent, acceptance_context=_acceptance_context()
    )

    assert outcome.state == RecoveryState.FAILED
    assert transport.calls == []


def test_execute_with_acceptance_context_still_requires_prepared_state(tmp_path, monkeypatch):
    """Proves acceptance mode cannot skip the earliest gate: a contract
    that never reached PREPARED refuses identically regardless of
    acceptance_context."""

    store = _store(tmp_path)
    contract, intent = _build_contract()
    store.create(contract)
    write_client, transport = _acceptance_write_client(monkeypatch)
    executor = _executor(store, write_client)

    with pytest.raises(ContractConflictError):
        executor.execute(
            contract.contract_id,
            adapter=_SyntheticAdapter(reads=[]),
            intent=intent,
            acceptance_context=_acceptance_context(),
        )
    assert transport.calls == []


def test_execute_with_acceptance_context_still_requires_confirmation(tmp_path, monkeypatch):
    """A PREPARED-but-unconfirmed contract refuses identically regardless
    of acceptance_context -- confirmation is checked before this
    parameter is ever consulted."""

    store = _store(tmp_path)
    contract, intent = _build_contract()
    store.create(contract)
    store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )
    write_client, transport = _acceptance_write_client(monkeypatch)
    executor = _executor(store, write_client)

    with pytest.raises(ContractConflictError):
        executor.execute(
            contract.contract_id,
            adapter=_SyntheticAdapter(reads=[]),
            intent=intent,
            acceptance_context=_acceptance_context(),
        )
    assert transport.calls == []


def test_rollback_never_accepts_an_acceptance_context():
    """Structural proof: rollback()'s signature has no acceptance_context
    parameter at all -- restoration via rollback() (not used by Slice 6's
    design, which uses a fresh forward chain instead) cannot be routed
    through the acceptance path even by mistake."""

    import inspect

    params = inspect.signature(MutationExecutor.rollback).parameters
    assert "acceptance_context" not in params


# --- MutationExecutor clock seam (ADR-034 follow-up, 2026-08-23) -----------
#
# MutationExecutor.execute() previously called contract.is_expired() with
# no `now=` argument, so its expiry check always fell through to real
# datetime.now(timezone.utc) regardless of any clock the store was given
# -- undetectable in a fast, isolated test, but nondeterministic once a
# long-running suite pushed real elapsed time past the contract's TTL
# before this specific check ran (found via two real CI failures in
# tests/tier1/test_alias_description_execution.py). MutationExecutor now
# accepts an optional `clock` constructor parameter (default: real UTC
# time, exactly matching prior behavior) and threads it into
# contract.is_expired(now=...). These tests prove that seam directly;
# test_alias_description_execution.py's own two tests are fixed
# separately by injecting the same frozen clock they already use for the
# store.


def test_default_executor_clock_reads_real_utc_wall_clock_time(tmp_path):
    # Matrix: A
    store = _store(tmp_path)
    executor = MutationExecutor(
        store=store,
        write_client=object(),
        read_client=object(),
        policy=_policy(),
        anti_rollback_anchor=None,
        encryption_key=_ENCRYPTION_KEY,
    )
    before = datetime.now(timezone.utc)
    observed = executor._now()
    after = datetime.now(timezone.utc)
    assert before <= observed <= after


def test_injected_frozen_clock_is_used_verbatim(tmp_path):
    # Matrix: B
    store = _store(tmp_path)
    frozen = datetime(2020, 1, 1, tzinfo=timezone.utc)
    executor = MutationExecutor(
        store=store,
        write_client=object(),
        read_client=object(),
        policy=_policy(),
        anti_rollback_anchor=None,
        encryption_key=_ENCRYPTION_KEY,
        clock=lambda: frozen,
    )
    assert executor._now() == frozen
    assert executor._now() != datetime.now(timezone.utc)


def test_unexpired_contract_succeeds_under_deterministic_clock(tmp_path, monkeypatch):
    # Matrix: C
    frozen = datetime.now(timezone.utc)
    store = _store(tmp_path)
    contract, intent = _build_contract(now=frozen)
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/synthetic", status_code=200, text='{"ok": true}')
    adapter = _SyntheticAdapter(
        reads=[
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "original-description"},
            {"name": "synthetic-target.invalid", "revision": "synthetic-1", "descr": "updated-description"},
        ]
    )
    # Executor clock reports a time still comfortably inside the 5-minute
    # TTL _build_contract() sets -- proves execute() actually consults
    # the injected clock (not just "no clock given"), since the default
    # real-clock path would also pass here trivially.
    executor = _executor(store, write_client, clock=lambda: contract.expires_at - timedelta(minutes=1))

    outcome = executor.execute(contract.contract_id, adapter=adapter, intent=intent)

    assert outcome.state == RecoveryState.VERIFIED


def test_expired_contract_refuses_at_execute_under_deterministic_clock(tmp_path, monkeypatch):
    # Matrix: D
    frozen = datetime.now(timezone.utc)
    store = _store(tmp_path)
    contract, intent = _build_contract(now=frozen)
    # Confirmed while still unexpired (store's own default clock is real
    # time, and confirmation happens immediately in this test, so this
    # succeeds regardless).
    _confirm(store, contract)
    write_client, transport = _write_client(monkeypatch)
    # Executor's own clock reports a time *after* expires_at -- proving
    # the expiry check now genuinely depends on the injected clock, not
    # merely on whatever real wall-clock time happens to be when the
    # test runs.
    executor = _executor(store, write_client, clock=lambda: contract.expires_at + timedelta(seconds=1))

    with pytest.raises(ContractConflictError, match="unconfirmed or expired"):
        executor.execute(contract.contract_id, adapter=_SyntheticAdapter(reads=[]), intent=intent)
    assert transport.calls == []


def test_executor_clock_rejects_non_callable():
    # Matrix: F
    with pytest.raises(ContractValidationError, match="clock is invalid"):
        MutationExecutor(
            store=object(),
            write_client=object(),
            read_client=object(),
            policy=_policy(),
            anti_rollback_anchor=None,
            encryption_key=_ENCRYPTION_KEY,
            clock="not-callable",
        )


def test_executor_now_fails_closed_on_naive_datetime(tmp_path):
    # Matrix: F
    store = _store(tmp_path)
    executor = MutationExecutor(
        store=store,
        write_client=object(),
        read_client=object(),
        policy=_policy(),
        anti_rollback_anchor=None,
        encryption_key=_ENCRYPTION_KEY,
        clock=lambda: datetime(2020, 1, 1),  # naive, no tzinfo
    )
    with pytest.raises(ContractValidationError, match="must return UTC"):
        executor._now()


def test_executor_now_fails_closed_on_non_utc_timezone(tmp_path):
    # Matrix: F
    store = _store(tmp_path)
    non_utc = timezone(timedelta(hours=5))
    executor = MutationExecutor(
        store=store,
        write_client=object(),
        read_client=object(),
        policy=_policy(),
        anti_rollback_anchor=None,
        encryption_key=_ENCRYPTION_KEY,
        clock=lambda: datetime(2020, 1, 1, tzinfo=non_utc),
    )
    with pytest.raises(ContractValidationError, match="must return UTC"):
        executor._now()
