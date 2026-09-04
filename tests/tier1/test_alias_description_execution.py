from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

from pfsense_mcp.models.firewall_alias import FirewallAlias
from pfsense_mcp.models.system import SystemStatus
from pfsense_mcp.models.system_ha_sync import SystemHaSync
from pfsense_mcp.models.system_rest_api_settings import SystemRestApiSettings
from pfsense_mcp.security_authorization import (
    PlanAuthorization,
    PlanAuthorizationStepBinding,
    build_plan_authorization_payload,
    build_plan_authorization_v2_payload,
    sign_plan_authorization,
    sign_plan_authorization_v2,
)
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.tier1.alias_description import (
    ADAPTER_VERSION,
    ENDPOINT_SYMBOL,
    HTTP_METHOD,
    ROLLBACK_VERSION,
    SEMANTIC_UNIT,
    AliasDescriptionAdapterV1,
    AliasDescriptionChangeV1,
    AliasDescriptionPatchV1,
    AliasDescriptionPreparerV1,
    ConfiguredApplianceTargetV1,
)
from pfsense_mcp.tier1.alias_description_execution import (
    AliasDescriptionExecutionCoreV1,
    AuthorizedAliasDescriptionExecution,
)
from pfsense_mcp.tier1.authorization_consumption_store import AuthorizationConsumptionStore
from pfsense_mcp.tier1.canonical import DigestPurpose, digest_value, frame_bytes, frame_str
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.contract import AuthorizationProvenance
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.errors import (
    BoundExecutionError,
    ContractIntegrityError,
    ContractValidationError,
    GlobalReadOnlyBlockedError,
    PreparedExecutionIntentError,
)
from pfsense_mcp.tier1.executor import ExecutionOutcome, MutationExecutor, ResolvedTransportTarget
from pfsense_mcp.tier1.key_lifecycle import KeyPurpose, KeyRecord, NonceCounter
from pfsense_mcp.tier1.policy import MutationPolicy, MutationRule
from pfsense_mcp.tier1.prepared_execution_intent import compute_execution_intent_digest
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore
from pfsense_mcp.tls import TLSMode
from pfsense_mcp.transport.base import TransportResponse, TransportTimeoutError
from tests.test_security_plan_digest import _synthetic_plan, _synthetic_step

NOW = datetime.now(timezone.utc).replace(microsecond=0)


class _ReadClient:
    def __init__(self) -> None:
        self.aliases = [
            FirewallAlias(
                id=0,
                name="LAB_ALIAS_TEST",
                type="host",
                descr="before",
                address=["192.0.2.10"],
                detail=["synthetic"],
            )
        ]
        self.netgate_id: str | None = "netgate-synthetic"
        self.pfhostid: str | None = "pfhost-synthetic"
        self.alias_reads = 0
        # Mission III: pfREST global Read Only gate -- WRITABLE by
        # default so every existing execute() test in this file keeps
        # exercising the exact same post-gate behavior as before the
        # gate existed. Toggled to True by the one test proving the
        # gate blocks a real production adapter path.
        self.pfrest_read_only = False

    def get_firewall_aliases(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallAlias]:
        assert include_identifying_metadata is True
        assert limit == 500
        self.alias_reads += 1
        return list(self.aliases)

    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus:
        assert include_identifying_metadata is True
        return SystemStatus(
            platform="synthetic",
            uptime="1 day",
            cpu_model="synthetic",
            cpu_count=1,
            cpu_usage=0.0,
            mem_usage=1,
            swap_usage=0,
            disk_usage=1,
            netgate_id=self.netgate_id,
        )

    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> SystemHaSync:
        assert include_identifying_metadata is True
        values = {name: False for name, field in SystemHaSync.model_fields.items() if field.annotation is bool}
        values.update(
            {
                "pfsyncinterface": "none",
                "pfsyncpeerip": None,
                "synchronizetoip": None,
                "pfhostid": self.pfhostid,
                "username": None,
            }
        )
        return SystemHaSync.model_validate(values)

    def get_system_restapi_settings(self, *, include_identifying_metadata: bool = False) -> SystemRestApiSettings:
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
            read_only=self.pfrest_read_only,
            represent_interfaces_as="descr",
        )


class _ConsumptionStore(AuthorizationConsumptionStore):
    def __init__(self) -> None:
        self.consumed: set[str] = set()
        self.calls = 0

    def try_consume(self, authorization_id: str) -> bool:
        self.calls += 1
        if authorization_id in self.consumed:
            return False
        self.consumed.add(authorization_id)
        return True


class _ConfirmationVerifier:
    def verify(self, evidence: ConfirmationEvidence) -> bool:
        return evidence.algorithm == "synthetic-confirmation-v1" and evidence.proof == b"valid"


class _WriteClient:
    def __init__(self, client: _ReadClient, *, restore_description: str | None = None) -> None:
        self.client = client
        self.restore_description = restore_description
        self.calls = 0

    def send_for_tier1(self, *, endpoint_symbol: str, http_method: str, body: bytes) -> TransportResponse:
        assert endpoint_symbol == ENDPOINT_SYMBOL
        assert http_method == HTTP_METHOD
        assert body
        self.calls += 1
        if self.restore_description is not None:
            self.client.aliases[0] = self.client.aliases[0].model_copy(update={"descr": self.restore_description})
        return TransportResponse(status_code=200, text="synthetic")


def _plan():
    return _synthetic_plan(
        steps=(
            _synthetic_step(
                step_id="first.write.alias.description",
                order=1,
                authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE,
            ),
        )
    )


def _target() -> ConfiguredApplianceTargetV1:
    return ConfiguredApplianceTargetV1(base_url="https://pfsense.invalid", tls_mode=TLSMode.STRICT)


def _preparer(client: _ReadClient) -> AliasDescriptionPreparerV1:
    return AliasDescriptionPreparerV1(read_client=client, configured_target=_target())


def _keypair() -> tuple[Ed25519PrivateKey, PinnedAuthoritySet]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, PinnedAuthoritySet((PinnedAuthority(authority_id="owner-v2", public_key=public),))


def _authorization(private: Ed25519PrivateKey, digest: str, **changes: object):
    values = {
        "plan": _plan(),
        "authorized_executions": (
            PlanAuthorizationStepBinding(
                step_id="first.write.alias.description",
                execution_intent_digest=digest,
            ),
        ),
        "authorization_id": "authz-v2-one",
        "authority_id": "owner-v2",
        "issued_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=4),
    }
    values.update(changes)
    return sign_plan_authorization_v2(build_plan_authorization_v2_payload(**values), private)  # type: ignore[arg-type]


def _store(tmp_path: Path) -> SqliteRecoveryContractStore:
    tmp_path.chmod(0o700)
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=b"i" * 32,
        store_id="w1-synthetic",
        clock=lambda: NOW,
        confirmation_verifier=_ConfirmationVerifier(),
    )


def _core(tmp_path: Path, client: _ReadClient):
    private, authorities = _keypair()
    store = _store(tmp_path)
    consumption = _ConsumptionStore()
    executor = Mock(spec=MutationExecutor)
    executor.execute.return_value = ExecutionOutcome("unused", RecoveryState.VERIFIED, "synthetic")
    counter_path = tmp_path / "nonce.json"
    counter = NonceCounter(counter_path, key_id="enc-w1")
    core = AliasDescriptionExecutionCoreV1(
        preparer=_preparer(client),
        authorities=authorities,
        consumption_store=consumption,
        contract_store=store,
        executor=executor,
        encryption_key=KeyRecord("enc-w1", 0, b"e" * 32, KeyPurpose.ENCRYPTION),
        nonce_counter=counter,
    )
    return core, private, store, consumption, executor


def _confirmation(contract) -> ConfirmationEvidence:
    return ConfirmationEvidence(
        authority_id="confirmation-owner",
        algorithm="synthetic-confirmation-v1",
        nonce="nonce-w1",
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        target_identity_digest=contract.target_identity_digest,
        target_fingerprint=contract.target_fingerprint,
        intent_digest=contract.intent_digest,
        expires_at=contract.expires_at,
        issued_at=NOW,
        proof=b"valid",
    )


def _authorize(core, private, request, prepared, authz=None, **changes):
    authorization = authz or _authorization(private, compute_execution_intent_digest(prepared.intent))
    values = {
        "authorized_preparation": prepared,
        "authorization": authorization,
        "requested_plan_digest": authorization.plan_digest,
        "requested_step_id": "first.write.alias.description",
        "required_risk_class": AuthorizationLevel.CONFIGURATION_CHANGE,
        "target_capability_posture": CapabilityPosture.WRITE_PROTECTED,
        "target_anchor_assurance": AnchorAssurance.HARDWARE_WITNESS,
        "now": NOW,
    }
    values.update(changes)
    return core.authorize_and_create(request, **values)


def _executor_intent(prepared) -> dict:
    state = prepared.authoritative_a
    return {
        **prepared.intent.normalized_mutation_intent,
        "raw_target_hint": {
            "name": state.name,
            "id": state.numeric_locator,
            "type": state.alias_type,
            "descr": state.descr,
            "address": list(state.address),
            "detail": list(state.detail),
        },
    }


def _sealed_executor(store, client, write_client) -> MutationExecutor:
    return MutationExecutor(
        store=store,
        write_client=write_client,
        read_client=client,
        policy=MutationPolicy(
            frozenset({MutationRule(AliasDescriptionAdapterV1.capability, ENDPOINT_SYMBOL, HTTP_METHOD)})
        ),
        anti_rollback_anchor=None,
        encryption_key=b"e" * 32,
        # Same frozen NOW the store above is already constructed with
        # (_store()'s own clock=lambda: NOW) -- without this, execute()'s
        # expiry check fell through to real wall-clock time regardless of
        # the store's clock (the exact gap ADR-034's follow-up production
        # fix closes: MutationExecutor previously called
        # contract.is_expired() with no `now=` at all). Two tests in this
        # file exercise the real (non-mocked) execute() path and were
        # intermittently failing in CI once the full suite's real elapsed
        # runtime exceeded the 4-minute contract TTL by the time they ran
        # -- this makes them fully deterministic, independent of suite
        # wall time.
        clock=lambda: NOW,
    )


def test_request_is_exactly_two_fields_and_normalizes_nfc():
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="cafe\u0301")
    assert request.model_dump() == {"alias_name": "LAB_ALIAS_TEST", "description": "café"}
    with pytest.raises(ValidationError):
        AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after", id=0)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="x" * 1025)
    with pytest.raises(ValidationError):
        AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="bad\x01")


def test_preparer_and_adapter_are_closed_description_only():
    client = _ReadClient()
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    assert prepared.intent.endpoint_symbol == ENDPOINT_SYMBOL
    assert prepared.intent.http_method == HTTP_METHOD
    assert prepared.intent.adapter_version == ADAPTER_VERSION
    assert prepared.intent.rollback_plan_version == ROLLBACK_VERSION
    assert prepared.intent.normalized_mutation_intent["operation"] == SEMANTIC_UNIT
    assert prepared.intent.target_precondition == prepared.intent.rollback_snapshot
    patch = AliasDescriptionAdapterV1().build_request(
        prepared.intent.normalized_mutation_intent,
        ResolvedTransportTarget(numeric_locator=0, target_identity_digest="a" * 64),
    )
    assert patch == AliasDescriptionPatchV1(id=0, descr="after", apply=False)
    assert set(patch.model_dump()) == {"id", "descr", "apply"}


@pytest.mark.parametrize("mode", ["missing", "duplicate", "malformed"])
def test_preparer_refuses_non_singular_or_malformed_target(mode: str):
    client = _ReadClient()
    if mode == "missing":
        client.aliases = []
    elif mode == "duplicate":
        client.aliases *= 2
    else:
        client.aliases[0] = client.aliases[0].model_copy(update={"address": None})
    with pytest.raises(PreparedExecutionIntentError):
        _preparer(client).prepare(AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after"))


def test_appliance_netgate_and_pfhostid_fallback_and_absence():
    client = _ReadClient()
    first = _preparer(client).prepare(AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after"))
    client.netgate_id = None
    second = _preparer(client).prepare(AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after"))
    assert first.appliance_target_digest != second.appliance_target_digest
    client.pfhostid = None
    with pytest.raises(PreparedExecutionIntentError, match="unavailable"):
        _preparer(client).prepare(AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after"))


def test_configured_appliance_binding_refuses_insecure_or_ambiguous_tls():
    with pytest.raises(PreparedExecutionIntentError):
        ConfiguredApplianceTargetV1(base_url="https://pfsense.invalid", tls_mode=TLSMode.INSECURE)
    with pytest.raises(PreparedExecutionIntentError):
        ConfiguredApplianceTargetV1(base_url="https://pfsense.invalid", tls_mode=TLSMode.AUTO)
    with pytest.raises(PreparedExecutionIntentError):
        ConfiguredApplianceTargetV1(
            base_url="https://other.invalid/path",
            tls_mode=TLSMode.AUTO,
            ca_certificate_digest="a" * 64,
        )


def test_valid_v2_consumes_creates_confirms_and_hands_off_once(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, consumption, executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    contract = store.load(handle.contract_id)
    assert contract.state is RecoveryState.PREPARED
    assert isinstance(contract.authorization_provenance, AuthorizationProvenance)
    assert contract.authorization_provenance.execution_intent_digest == compute_execution_intent_digest(prepared.intent)
    assert contract.expires_at == NOW + timedelta(minutes=4)
    result = core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)
    assert result.state is RecoveryState.VERIFIED
    assert consumption.calls == 1
    executor.execute.assert_called_once()
    with pytest.raises(BoundExecutionError):
        core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)
    executor.execute.assert_called_once()


def test_compute_idempotency_key_matches_what_create_contract_actually_persists(tmp_path: Path, monkeypatch):
    """W3 Slice 3's read-only idempotency-key exposure
    (`compute_idempotency_key()`) must be the exact same value
    `_create_contract()` derives and persists -- proving the two share
    one derivation (`_derive_idempotency()`), never two independently
    computed values that could drift apart."""

    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, _consumption, _executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)

    computed_before_creation = core.compute_idempotency_key(prepared)
    handle = _authorize(core, private, request, prepared)
    contract = store.load(handle.contract_id)

    assert contract.idempotency_key == computed_before_creation
    # Read-only: computing it never creates, consumes, or mutates anything.
    assert core.compute_idempotency_key(prepared) == computed_before_creation


def test_resume_prepared_reconstructs_handle_after_fresh_core_and_completes_once(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, _store, consumption, executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    contract_id = handle.contract_id

    # Simulate the original process/runtime disappearing: build a
    # completely fresh execution core (fresh _pending, fresh owner
    # token, fresh executor) against the same durable store -- exactly
    # what a later, separate call (or a real restart) produces.
    fresh_core, _fresh_private, fresh_store, fresh_consumption, fresh_executor = _core(tmp_path, client)
    assert fresh_core is not core
    assert fresh_store.load(contract_id).state is RecoveryState.PREPARED

    resumed = fresh_core.resume_prepared(contract_id, request=request, now=NOW)
    assert resumed.contract_id == contract_id
    assert isinstance(resumed, AuthorizedAliasDescriptionExecution)

    contract = fresh_store.load(contract_id)
    result = fresh_core.confirm_and_handoff(resumed, confirmation=_confirmation(contract), now=NOW)
    assert result.state is RecoveryState.VERIFIED
    fresh_executor.execute.assert_called_once()

    # Only one executor handoff is possible: neither the original core's
    # executor nor its consumption store were touched by the resumed
    # completion, and the resumed core's own consumption store (a fresh,
    # unrelated instance) was never invoked -- resume never consumes.
    executor.execute.assert_not_called()
    assert consumption.calls == 1
    assert fresh_consumption.calls == 0

    # A second confirmation attempt through the same resumed handle
    # never produces a second handoff.
    with pytest.raises(BoundExecutionError):
        fresh_core.confirm_and_handoff(resumed, confirmation=_confirmation(contract), now=NOW)
    fresh_executor.execute.assert_called_once()


def test_resume_prepared_never_consumes_or_creates_and_duplicate_resume_is_safe(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, consumption, _executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    contract_id = handle.contract_id
    before = tuple(contract.contract_id for contract in store.all_contracts())

    fresh_core, _p, fresh_store, fresh_consumption, _e = _core(tmp_path, client)
    first_resume = fresh_core.resume_prepared(contract_id, request=request, now=NOW)
    second_resume = fresh_core.resume_prepared(contract_id, request=request, now=NOW)

    assert first_resume.contract_id == second_resume.contract_id == contract_id
    # Restart/re-invocation never creates a new authorization
    # consumption or a second contract -- resume_prepared() does not
    # call try_consume()/create_authorized() at all.
    assert consumption.calls == 1  # the one real consumption from _authorize() above
    assert fresh_consumption.calls == 0
    after = tuple(contract.contract_id for contract in fresh_store.all_contracts())
    assert after == before


def test_resume_prepared_refuses_null_provenance_contract(tmp_path: Path, contract_factory, monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, _private, store, _consumption, _executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    # store.create() (never create_authorized()) is the only way to
    # persist a contract with null authorization_provenance -- create()
    # itself only accepts state=PREPARING, version=0, so reach PREPARED
    # via the same legal PREPARING->PREPARED transition production uses.
    # Resume must refuse the resulting null-provenance contract before
    # ever calling the preparer.
    contract = contract_factory(state=RecoveryState.PREPARING, now=NOW)
    assert contract.authorization_provenance is None
    store.create(contract)
    store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=0,
        target_state=RecoveryState.PREPARED,
    )

    with pytest.raises(BoundExecutionError):
        core.resume_prepared(contract.contract_id, request=request, now=NOW)


def test_resume_prepared_refuses_tampered_contract(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, _store, _consumption, _executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)

    with sqlite3.connect(tmp_path / "contracts.sqlite3") as connection:
        payload = connection.execute(
            "SELECT payload FROM contracts WHERE contract_id = ?", (handle.contract_id,)
        ).fetchone()[0]
        value = json.loads(payload)
        value["authorization_provenance"]["appliance_target_digest"] = "0" * 64
        connection.execute(
            "UPDATE contracts SET payload = ? WHERE contract_id = ?",
            (json.dumps(value, sort_keys=True, separators=(",", ":")).encode(), handle.contract_id),
        )

    fresh_core, _p, _fs, _c, _e = _core(tmp_path, client)
    with pytest.raises(BoundExecutionError):
        fresh_core.resume_prepared(handle.contract_id, request=request, now=NOW)


@pytest.mark.parametrize(
    "case",
    ["unknown-contract", "not-prepared", "wrong-request", "locator-drift", "appliance-drift", "expired"],
)
def test_resume_prepared_negative_cases_refuse_closed(tmp_path: Path, monkeypatch, case: str):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, _consumption, _executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    contract_id = handle.contract_id

    resume_request = request
    resume_now = NOW
    resume_contract_id = contract_id

    if case == "unknown-contract":
        resume_contract_id = "aliasdescr-does-not-exist"
    elif case == "not-prepared":
        # PREPARED -> EXECUTING requires prior confirmation (unrelated to
        # this test); PREPARED -> FAILED needs none and is equally
        # sufficient to prove resume refuses a non-PREPARED contract.
        store.transition(
            contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=store.load(contract_id).state_version,
            target_state=RecoveryState.FAILED,
        )
    elif case == "wrong-request":
        resume_request = AliasDescriptionChangeV1(
            alias_name="LAB_ALIAS_TEST", description="a completely different value"
        )
    elif case == "locator-drift":
        client.aliases[0] = client.aliases[0].model_copy(update={"id": 999})
    elif case == "appliance-drift":
        client.netgate_id = "a-different-netgate-id"
    elif case == "expired":
        resume_now = NOW + timedelta(minutes=10)

    fresh_core, _p, _fs, _c, _e = _core(tmp_path, client)
    with pytest.raises(BoundExecutionError):
        fresh_core.resume_prepared(resume_contract_id, request=resume_request, now=resume_now)


def test_resume_prepared_rejects_malformed_inputs(tmp_path: Path):
    client = _ReadClient()
    core, _private, _store, _consumption, _executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    with pytest.raises(BoundExecutionError):
        core.resume_prepared("", request=request, now=NOW)
    with pytest.raises(BoundExecutionError):
        core.resume_prepared("contract-1", request="not-a-request", now=NOW)  # type: ignore[arg-type]
    with pytest.raises(BoundExecutionError):
        core.resume_prepared("contract-1", request=request, now=datetime.now())  # naive, not UTC


def test_replay_is_refused_before_second_contract_or_handoff(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, consumption, executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    authz = _authorization(private, compute_execution_intent_digest(prepared.intent))
    first = _authorize(core, private, request, prepared, authz=authz)
    with pytest.raises(BoundExecutionError):
        _authorize(core, private, request, prepared, authz=authz)
    assert consumption.calls == 2
    assert tuple(contract.contract_id for contract in store.all_contracts()) == (first.contract_id,)
    executor.execute.assert_not_called()


@pytest.mark.parametrize(
    "case",
    [
        "wrong-step",
        "wrong-plan",
        "wrong-digest",
        "future",
        "expired",
        "bad-signature",
        "wrong-authority",
        "stale-description",
        "sibling-drift",
        "locator-drift",
        "changed-appliance",
        "stale-plan",
        "risk-downgrade",
    ],
)
def test_all_preconsumption_failures_leave_auth_unconsumed_and_zero_handoff(tmp_path: Path, monkeypatch, case: str):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, _store_value, consumption, executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    authz = _authorization(private, compute_execution_intent_digest(prepared.intent))
    changes = {}
    if case == "wrong-step":
        changes["requested_step_id"] = "wrong-step"
    elif case == "wrong-plan":
        changes["requested_plan_digest"] = "0" * 64
    elif case == "wrong-digest":
        authz = _authorization(private, "f" * 64)
    elif case == "future":
        authz = _authorization(
            private,
            compute_execution_intent_digest(prepared.intent),
            issued_at=NOW + timedelta(seconds=1),
            expires_at=NOW + timedelta(minutes=5),
        )
    elif case == "expired":
        authz = _authorization(
            private,
            compute_execution_intent_digest(prepared.intent),
            issued_at=NOW - timedelta(minutes=5),
            expires_at=NOW,
        )
    elif case == "bad-signature":
        authz = replace(authz, proof=b"x" * 64)
    elif case == "wrong-authority":
        authz = replace(authz, authority_id="unknown-owner")
    elif case == "stale-description":
        client.aliases[0] = client.aliases[0].model_copy(update={"descr": "concurrent"})
    elif case == "sibling-drift":
        client.aliases[0] = client.aliases[0].model_copy(update={"address": ["192.0.2.99"]})
    elif case == "locator-drift":
        client.aliases[0] = client.aliases[0].model_copy(update={"id": 1})
    elif case == "changed-appliance":
        client.netgate_id = "different-installation"
    elif case == "stale-plan":
        monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: False))
    elif case == "risk-downgrade":
        # ADR-036 W0: authz is validly signed at CONFIGURATION_CHANGE (what
        # _plan()'s synthetic step actually declares) but the step being
        # requested is independently determined to require the strictly
        # higher INTERACTIVE_HARDWARE_CONFIRMATION -- must refuse before
        # consumption exactly like every other pre-consumption gate here,
        # never silently accept a lower-friction authorization for a
        # higher-friction requirement.
        changes["required_risk_class"] = AuthorizationLevel.INTERACTIVE_HARDWARE_CONFIRMATION
    with pytest.raises(BoundExecutionError):
        _authorize(core, private, request, prepared, authz=authz, **changes)
    assert consumption.calls == 0
    executor.execute.assert_not_called()


def test_v1_authorization_is_structurally_ineligible(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, _store_value, consumption, executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    payload = build_plan_authorization_payload(
        _plan(),
        ("first.write.alias.description",),
        authorization_id="legacy-v1",
        authority_id="owner-v2",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
    )
    legacy: PlanAuthorization = sign_plan_authorization(payload, private)
    with pytest.raises(BoundExecutionError):
        core.authorize_and_create(
            request,
            authorized_preparation=prepared,
            authorization=legacy,  # type: ignore[arg-type]
            requested_plan_digest=legacy.plan_digest,
            requested_step_id="first.write.alias.description",
            required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            now=NOW,
        )
    assert consumption.calls == 0
    executor.execute.assert_not_called()


def test_post_consumption_create_failure_burns_authorization(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, consumption, executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    authz = _authorization(private, compute_execution_intent_digest(prepared.intent))
    original = store.create_authorized
    store.create_authorized = Mock(side_effect=RuntimeError("synthetic create failure"))  # type: ignore[method-assign]
    with pytest.raises(BoundExecutionError):
        _authorize(core, private, request, prepared, authz=authz)
    assert authz.authorization_id in consumption.consumed
    store.create_authorized = original  # type: ignore[method-assign]
    with pytest.raises(BoundExecutionError):
        _authorize(core, private, request, prepared, authz=authz)
    executor.execute.assert_not_called()


def test_confirmation_mismatch_and_expiry_never_handoff(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, _consumption, executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    contract = store.load(handle.contract_id)
    wrong = replace(_confirmation(contract), intent_digest="f" * 64)
    with pytest.raises(BoundExecutionError):
        core.confirm_and_handoff(handle, confirmation=wrong, now=NOW)
    with pytest.raises(BoundExecutionError):
        core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=contract.expires_at)
    executor.execute.assert_not_called()


def test_production_adapter_drift_refuses_before_executor_send(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, _consumption, _mock_executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    contract = store.load(handle.contract_id)
    store.confirm(contract.contract_id, evidence=_confirmation(contract), expected_version=contract.state_version)
    client.aliases[0] = client.aliases[0].model_copy(update={"descr": "concurrent"})
    write_client = _WriteClient(client)
    outcome = _sealed_executor(store, client, write_client).execute(
        contract.contract_id,
        adapter=AliasDescriptionAdapterV1(),
        intent=_executor_intent(prepared),
    )
    assert outcome.state is RecoveryState.FAILED
    assert write_client.calls == 0


def test_production_adapter_blocked_by_pfrest_read_only_before_executor_send(tmp_path: Path, monkeypatch):
    # Mission III: proves the gate against the real, live-shipped
    # AliasDescriptionAdapterV1/_sealed_executor wiring -- not only the
    # synthetic adapter in test_executor.py -- so a stub that defaults
    # WRITABLE cannot be masking this check for the one capability that
    # actually exists today (Phase 6 self-review item 10).
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    client.pfrest_read_only = True
    core, private, store, _consumption, _mock_executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    contract = store.load(handle.contract_id)
    store.confirm(contract.contract_id, evidence=_confirmation(contract), expected_version=contract.state_version)
    write_client = _WriteClient(client)

    with pytest.raises(GlobalReadOnlyBlockedError, match="WebConfigurator"):
        _sealed_executor(store, client, write_client).execute(
            contract.contract_id,
            adapter=AliasDescriptionAdapterV1(),
            intent=_executor_intent(prepared),
        )

    assert write_client.calls == 0
    assert store.load(contract.contract_id).state == RecoveryState.PREPARED


def test_production_adapter_rollback_conflict_refuses_and_post_expiry_recovery_remains_available(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, _consumption, _mock_executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    contract = store.load(handle.contract_id)
    confirmed = store.confirm(
        contract.contract_id,
        evidence=_confirmation(contract),
        expected_version=contract.state_version,
    )
    executing = store.transition(
        confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    client.aliases[0] = client.aliases[0].model_copy(update={"descr": "after"})
    adapter = AliasDescriptionAdapterV1()
    context = (adapter.capability.name, adapter.endpoint_symbol, adapter.http_method)
    verified_fingerprint = digest_value(
        DigestPurpose.TARGET_FINGERPRINT,
        adapter.fingerprint(adapter.read_target(client, {"alias_name": "LAB_ALIAS_TEST"})),
        context=context,
    )
    verified = store.mark_execution_verified(
        executing.contract_id,
        expected_version=executing.state_version,
        verified_target_fingerprint=verified_fingerprint,
        verified_lifecycle_locator=0,
    )

    client.aliases[0] = client.aliases[0].model_copy(update={"descr": "concurrent"})
    conflict_write = _WriteClient(client)
    conflict = _sealed_executor(store, client, conflict_write).rollback(verified.contract_id, adapter=adapter)
    assert conflict.state is RecoveryState.ROLLBACK_FAILED
    assert conflict_write.calls == 0

    # A separate verified operation proves source-authorization expiry is not
    # consulted by rollback. The authenticated VERIFIED state and B/locator
    # precondition remain the authority for safety recovery.
    second_dir = tmp_path / "second"
    second_dir.mkdir(mode=0o700)
    second_client = _ReadClient()
    second_core, second_private, second_store, _consumption2, _mock2 = _core(second_dir, second_client)
    second_prepared = _preparer(second_client).prepare(request)
    second_handle = _authorize(second_core, second_private, request, second_prepared)
    second_contract = second_store.load(second_handle.contract_id)
    second_confirmed = second_store.confirm(
        second_contract.contract_id,
        evidence=_confirmation(second_contract),
        expected_version=second_contract.state_version,
    )
    second_executing = second_store.transition(
        second_confirmed.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=second_confirmed.state_version,
        target_state=RecoveryState.EXECUTING,
    )
    second_client.aliases[0] = second_client.aliases[0].model_copy(update={"descr": "after"})
    second_verified_fingerprint = digest_value(
        DigestPurpose.TARGET_FINGERPRINT,
        adapter.fingerprint(adapter.read_target(second_client, {"alias_name": "LAB_ALIAS_TEST"})),
        context=context,
    )
    second_verified = second_store.mark_execution_verified(
        second_executing.contract_id,
        expected_version=second_executing.state_version,
        verified_target_fingerprint=second_verified_fingerprint,
        verified_lifecycle_locator=0,
    )
    assert second_verified.authorization_provenance is not None
    assert second_verified.authorization_provenance.authorization_expires_at < NOW + timedelta(hours=1)
    recovery_write = _WriteClient(second_client, restore_description="before")
    recovered = _sealed_executor(second_store, second_client, recovery_write).rollback(
        second_verified.contract_id,
        adapter=adapter,
    )
    assert recovered.state is RecoveryState.ROLLED_BACK
    assert recovery_write.calls == 1


class _TimeoutWriteClient:
    """Raises TransportTimeoutError on the exact send call the production
    adapter/executor composition makes -- proves the AMBIGUOUS/
    RECONCILIATION uncertainty classification (ADR-026 row 14) through the
    real AliasDescriptionAdapterV1, not only test_executor.py's
    _SyntheticAdapter (the only production-bound gap this row had)."""

    def __init__(self) -> None:
        self.calls = 0

    def send_for_tier1(self, *, endpoint_symbol: str, http_method: str, body: bytes) -> TransportResponse:
        assert endpoint_symbol == ENDPOINT_SYMBOL
        assert http_method == HTTP_METHOD
        assert body
        self.calls += 1
        raise TransportTimeoutError("synthetic timeout")


def test_production_adapter_send_timeout_reaches_reconciliation_not_failed_or_resend(tmp_path: Path, monkeypatch):
    """ADR-026 row 14 (authoritative uncertainty classification): a lost
    response after the real PATCH may reach the server. This must never be
    classified as a clean failure (which would license a resend) and must
    never resend -- it must land in RECONCILIATION, exactly once sent,
    through the real production adapter."""

    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, _consumption, _mock_executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    contract = store.load(handle.contract_id)
    store.confirm(contract.contract_id, evidence=_confirmation(contract), expected_version=contract.state_version)
    write_client = _TimeoutWriteClient()

    outcome = _sealed_executor(store, client, write_client).execute(
        contract.contract_id,
        adapter=AliasDescriptionAdapterV1(),
        intent=_executor_intent(prepared),
    )

    assert outcome.state is RecoveryState.RECONCILIATION
    assert write_client.calls == 1


def test_authorized_store_entry_requires_non_null_provenance(tmp_path: Path, contract_factory):
    store = _store(tmp_path)
    with pytest.raises(ContractValidationError, match="provenance"):
        store.create_authorized(contract_factory(now=NOW))


def test_schema_v6_contract_migrates_without_inferred_provenance(tmp_path: Path, contract_factory):
    store = _store(tmp_path)
    legacy = contract_factory(now=NOW)
    store.create(legacy)
    database = tmp_path / "contracts.sqlite3"
    with sqlite3.connect(database) as connection:
        payload = connection.execute(
            "SELECT payload FROM contracts WHERE contract_id = ?", (legacy.contract_id,)
        ).fetchone()[0]
        value = json.loads(payload)
        del value["authorization_provenance"]
        legacy_payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        mac = hmac.new(
            b"i" * 32,
            frame_str("w1-synthetic") + frame_bytes(legacy_payload),
            hashlib.sha256,
        ).hexdigest()
        connection.execute(
            "UPDATE contracts SET payload = ?, mac = ? WHERE contract_id = ?",
            (legacy_payload, mac, legacy.contract_id),
        )
        connection.execute("UPDATE metadata SET value = '6' WHERE key = 'schema_version'")
    reopened = _store(tmp_path)
    migrated = reopened.load(legacy.contract_id)
    assert migrated.authorization_provenance is None
    with sqlite3.connect(database) as connection:
        assert dict(connection.execute("SELECT key, value FROM metadata"))["schema_version"] == "7"
        migrated_payload = json.loads(connection.execute("SELECT payload FROM contracts").fetchone()[0])
    assert migrated_payload["authorization_provenance"] is None


def test_provenance_survives_reopen_and_hmac_tamper_fails(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, _consumption, _executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    reopened = SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=b"i" * 32,
        store_id="w1-synthetic",
        clock=lambda: NOW,
        confirmation_verifier=_ConfirmationVerifier(),
    )
    assert (
        reopened.load(handle.contract_id).authorization_provenance
        == store.load(handle.contract_id).authorization_provenance
    )
    with sqlite3.connect(tmp_path / "contracts.sqlite3") as connection:
        payload = connection.execute(
            "SELECT payload FROM contracts WHERE contract_id = ?", (handle.contract_id,)
        ).fetchone()[0]
        value = json.loads(payload)
        value["authorization_provenance"]["appliance_target_digest"] = "0" * 64
        connection.execute(
            "UPDATE contracts SET payload = ? WHERE contract_id = ?",
            (json.dumps(value, sort_keys=True, separators=(",", ":")).encode(), handle.contract_id),
        )
    with pytest.raises(ContractIntegrityError):
        reopened.load(handle.contract_id)


def test_authorization_expiry_after_legitimate_send_does_not_expire_recovery_contract():
    provenance = AuthorizationProvenance(
        schema_version=2,
        authorization_id="authz",
        authority_id="owner",
        plan_authorization_schema_version=2,
        plan_digest="a" * 64,
        step_id="step",
        execution_intent_digest="b" * 64,
        authorization_issued_at=NOW - timedelta(minutes=1),
        authorization_expires_at=NOW + timedelta(minutes=1),
        appliance_target_digest="c" * 64,
    )
    assert provenance.authorization_expires_at < NOW + timedelta(minutes=2)
    # Recovery authorization is represented by the persisted contract state;
    # no coordinator method rechecks source authorization during rollback.
    assert "authorization" not in MutationExecutor.rollback.__code__.co_names


# -- ADR-029: acceptance_context threading through confirm_and_handoff() --


def test_confirm_and_handoff_threads_acceptance_context_to_the_executor(tmp_path: Path, monkeypatch):
    """Proves confirm_and_handoff() passes acceptance_context straight
    through to MutationExecutor.execute() unchanged -- every check above
    the executor call (owner token, contract state, provenance match,
    authorization/confirmation freshness, atomic confirm()) already ran
    and is identical to test_valid_v2_consumes_creates_confirms_and_hands_off_once
    above, which passes no acceptance_context at all."""

    from pfsense_mcp.tier1.acceptance import AcceptanceExecutionContext

    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, _consumption, executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    contract = store.load(handle.contract_id)

    fake_context = AcceptanceExecutionContext(
        endpoint_symbol=ENDPOINT_SYMBOL,
        http_method=HTTP_METHOD,
        target_identity="pfsense_lab1",
        issued_at=NOW,
    )
    result = core.confirm_and_handoff(
        handle, confirmation=_confirmation(contract), now=NOW, acceptance_context=fake_context
    )

    assert result.state is RecoveryState.VERIFIED
    executor.execute.assert_called_once()
    _args, kwargs = executor.execute.call_args
    assert kwargs["acceptance_context"] is fake_context


def test_confirm_and_handoff_default_omits_acceptance_context(tmp_path: Path, monkeypatch):
    """Regression: every existing/normal caller (this file's whole
    existing suite) never passes acceptance_context -- confirm it reaches
    the executor as None by default, unchanged from before ADR-029."""

    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, store, _consumption, executor = _core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _preparer(client).prepare(request)
    handle = _authorize(core, private, request, prepared)
    contract = store.load(handle.contract_id)

    core.confirm_and_handoff(handle, confirmation=_confirmation(contract), now=NOW)

    executor.execute.assert_called_once()
    _args, kwargs = executor.execute.call_args
    assert kwargs["acceptance_context"] is None


# ---------------------------------------------------------------------------
# ADR-036 W0 gap 4: AliasDescriptionAdapterV1.is_semantically_verified()
# direct unit coverage -- docs/tier1/specs/capability_adapter_contract.md's
# I5 ("must compare every field the projection is allowed to change ...
# and every field the projection forbids from changing ... an
# implementation that only checks the changed field is incomplete by this
# contract's definition") had no direct test proving the live adapter
# actually satisfies it; only a synthetic fake adapter in
# tests/tier1/test_executor.py exercised the Protocol shape generically.
# ---------------------------------------------------------------------------


def _alias_state_dict(
    *, name="LAB_ALIAS_TEST", numeric_id=0, alias_type="host", descr="before", address=("192.0.2.10",), detail=("d",)
):
    return {
        "name": name,
        "id": numeric_id,
        "type": alias_type,
        "descr": descr,
        "address": list(address),
        "detail": list(detail),
    }


def _alias_intent_dict(*, new_description="after", alias_name="LAB_ALIAS_TEST", digest="a" * 64):
    return {
        "operation": SEMANTIC_UNIT,
        "raw_target_hint": {"alias_name": alias_name},
        "new_description": new_description,
        "appliance_target_digest": digest,
    }


def test_is_semantically_verified_true_when_only_description_changed_to_the_intended_value():
    adapter = AliasDescriptionAdapterV1()
    pre = _alias_state_dict(descr="before")
    post = _alias_state_dict(descr="after")
    intent = _alias_intent_dict(new_description="after")
    assert adapter.is_semantically_verified(pre, post, intent) is True


def test_is_semantically_verified_false_when_description_did_not_change_to_the_intended_value():
    adapter = AliasDescriptionAdapterV1()
    pre = _alias_state_dict(descr="before")
    post = _alias_state_dict(descr="something-else")
    intent = _alias_intent_dict(new_description="after")
    assert adapter.is_semantically_verified(pre, post, intent) is False


def test_is_semantically_verified_false_when_description_unchanged_despite_intent():
    """HTTP 2xx alone must never satisfy this -- a post-state identical
    to pre-state (request silently ignored/no-op'd server-side) is not
    semantic success even though the transport call itself succeeded."""

    adapter = AliasDescriptionAdapterV1()
    pre = _alias_state_dict(descr="before")
    post = _alias_state_dict(descr="before")
    intent = _alias_intent_dict(new_description="after")
    assert adapter.is_semantically_verified(pre, post, intent) is False


@pytest.mark.parametrize(
    "drifted_field,drifted_value",
    [
        ("name", "DIFFERENT_ALIAS"),
        ("alias_type", "network"),
        ("address", ("203.0.113.5",)),
        ("detail", ("unexpected",)),
    ],
)
def test_is_semantically_verified_false_when_description_correct_but_another_field_also_drifted(
    drifted_field, drifted_value
):
    """The I5 case a naive "only check the changed field" implementation
    would incorrectly accept: the intended description change did
    happen, but some other field the projection forbids touching also
    changed (an unrelated concurrent edit landed in between pre/post
    reads, or a server-side side effect). Must refuse."""

    adapter = AliasDescriptionAdapterV1()
    pre = _alias_state_dict(descr="before")
    post = _alias_state_dict(descr="after", **{drifted_field: drifted_value})
    intent = _alias_intent_dict(new_description="after")
    assert adapter.is_semantically_verified(pre, post, intent) is False
