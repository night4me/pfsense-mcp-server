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
from pfsense_mcp.tier1.errors import ContractBindingError, ContractConflictError
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


def _executor(store, write_client) -> MutationExecutor:
    return MutationExecutor(
        store=store,
        write_client=write_client,
        read_client=object(),
        policy=_policy(),
        anti_rollback_anchor=None,
        encryption_key=_ENCRYPTION_KEY,
    )


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
