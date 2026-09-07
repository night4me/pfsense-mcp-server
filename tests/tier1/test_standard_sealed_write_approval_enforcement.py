"""Integration-level adversarial tests for STANDARD_SEALED_WRITE owner-
approval enforcement inside `MutationExecutor.execute()` (2026-09-07
owner-authorized Phase 2). Proves the enforcement mechanism itself, not
the `SealedWriteApproval` cryptographic primitives already exhaustively
covered by `test_sealed_write_approval.py` (cross-field replay, domain
separation, malformed/corrupted-signature handling) -- this file focuses
on the integration point: does `execute()` correctly require, load, and
verify an approval for a STANDARD contract, refuse deterministically and
fail-closed when it does not, and leave HIGH_ASSURANCE_TIER1 entirely
untouched by the mechanism's existence.

Deliberately independent of `test_two_tier_write_security.py`'s own
private harness -- this file builds its own minimal contract/store/
executor/approval harness, matching that file's own stated convention
(see its module docstring) of avoiding cross-file coupling.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.models.system_rest_api_settings import SystemRestApiSettings
from pfsense_mcp.tier1.canonical import DigestPurpose, digest_value
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.contract import ProtectedArtifact, RecoveryContract, derive_idempotency_key
from pfsense_mcp.tier1.crypto import ArtifactRole, build_nonce, encrypt_artifact
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.errors import AnchorUnavailableError, ContractIntegrityError
from pfsense_mcp.tier1.executor import MutationExecutor
from pfsense_mcp.tier1.policy import MutationPolicy, MutationRule
from pfsense_mcp.tier1.sealed_write_approval import (
    STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID,
    SealedWriteApproval,
    build_sealed_write_approval_payload,
    sign_sealed_write_approval,
)
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore
from pfsense_mcp.tier1.write_security_class import WriteSecurityClass

_INTEGRITY_KEY = b"synthetic-test-integrity-key-32bytes!"
_ENCRYPTION_KEY = os.urandom(32)
_STANDARD_CAPABILITY = Capability.NTP_TIME_SERVER_PREFER_WRITE
_HIGH_CAPABILITY = Capability.SYSTEM_TIMEZONE_WRITE
_ENDPOINT_SYMBOL = "SYNTHETIC_NTP_ENDPOINT"
_HTTP_METHOD = "PATCH"
_CONTEXT = (_STANDARD_CAPABILITY.name, _ENDPOINT_SYMBOL, _HTTP_METHOD)


class _AcceptingVerifier:
    def verify(self, evidence: ConfirmationEvidence) -> bool:
        return evidence.proof == b"synthetic-valid-proof"


class _FakeAnchor:
    """Proves *zero* witness contact for a STANDARD contract, and normal
    witness participation preserved for HIGH -- never a real TPM."""

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
    """Stands in at the pfREST Read Only gate and adapter target reads --
    tracks call counts so a test can prove zero network activity."""

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
    """Any call at all is a test failure -- proves zero transport WRITE."""

    def __getattr__(self, name: str):
        def _fail(*args: object, **kwargs: object) -> None:
            raise AssertionError(f"transport method {name!r} must never be called for a refused contract")

        return _fail


class _SyntheticAdapter:
    """Never reached by an approval-refused contract -- only present so
    `execute()`'s signature is satisfiable; its own methods raise if
    ever called, proving the approval check runs before any of them."""

    endpoint_symbol = _ENDPOINT_SYMBOL
    http_method = _HTTP_METHOD
    capability = _STANDARD_CAPABILITY

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
        store_id="synthetic-approval-store",
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
    *,
    contract_id: str = "ntppref-001",
    capability: Capability = _STANDARD_CAPABILITY,
    security_class: WriteSecurityClass,
    now: datetime | None = None,
) -> RecoveryContract:
    created = now or datetime.now(timezone.utc)
    context = (capability.name, _ENDPOINT_SYMBOL, _HTTP_METHOD)
    identity_source = {"timeserver": "1.pool.ntp.org"}
    identity = {"timeserver": "1.pool.ntp.org"}
    precondition = {"prefer": False}
    intent = {"raw_target_hint": identity_source, "prefer": True}
    intent_payload = {"prefer": True}
    snapshot_payload = {"prefer": False}

    target_digest = digest_value(DigestPurpose.TARGET_IDENTITY, identity, context=(capability.name,))
    fingerprint_digest = digest_value(DigestPurpose.TARGET_FINGERPRINT, precondition, context=context)
    intent_digest = digest_value(DigestPurpose.INTENT, intent, context=context)
    snapshot_digest = digest_value(DigestPurpose.SNAPSHOT, snapshot_payload, context=context)
    idempotency = derive_idempotency_key(
        capability=capability,
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
        capability=capability,
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
    """Mirrors the real `confirm_and_handoff()` sequence: create ->
    PREPARING -> PREPARED -> confirm() (bumps state_version by exactly
    one, per `RecoveryContract.with_confirmation()`). The confirmed
    contract's `state_version` is exactly what a STANDARD approval must
    bind to -- deterministically one more than whatever an operator
    would have observed inspecting the just-PREPARED, unconfirmed
    contract, since confirmation is the only version-bumping event
    between PREPARED and `execute()` for a first attempt."""

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


_CAPABILITY_SECURITY_CLASSES = {
    _STANDARD_CAPABILITY: WriteSecurityClass.STANDARD_SEALED_WRITE,
    _HIGH_CAPABILITY: WriteSecurityClass.HIGH_ASSURANCE_TIER1,
}


class _FakeApprovalSource:
    """In-memory `StandardSealedWriteApprovalSource` test double -- never
    a real fixed-inbox file, never touches disk. Tracks `load_calls` so a
    test can prove it is never even consulted for a HIGH contract."""

    def __init__(self, approvals: dict[str, SealedWriteApproval] | None = None) -> None:
        self._approvals = dict(approvals or {})
        self.load_calls: list[str] = []

    def load(self, contract_id: str) -> SealedWriteApproval | None:
        self.load_calls.append(contract_id)
        return self._approvals.get(contract_id)


class _RaisingApprovalSource:
    def load(self, contract_id: str) -> SealedWriteApproval | None:
        raise RuntimeError("synthetic approval source failure")


def _standard_authority() -> tuple[PinnedAuthoritySet, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    authority = PinnedAuthority(authority_id=STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID, public_key=public_key)
    return PinnedAuthoritySet((authority,)), private_key


def _sign_approval(
    confirmed: RecoveryContract,
    private_key: Ed25519PrivateKey,
    *,
    authority_id: str = STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID,
    contract_id: str | None = None,
    state_version: int | None = None,
    security_class: WriteSecurityClass | None = None,
    execution_intent_digest: str | None = None,
    target_identity_digest: str | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> SealedWriteApproval:
    """Signs an approval bound to `confirmed`'s own real fields by
    default -- exactly what a real operator would read off the
    persisted, already-confirmed contract and sign against. Every
    keyword override exists only to construct one deliberately wrong
    field for an adversarial test."""

    now = datetime.now(timezone.utc)
    payload = build_sealed_write_approval_payload(
        contract_id=contract_id if contract_id is not None else confirmed.contract_id,
        state_version=state_version if state_version is not None else confirmed.state_version,
        security_class=security_class if security_class is not None else confirmed.security_class,
        execution_intent_digest=(
            execution_intent_digest if execution_intent_digest is not None else confirmed.intent_digest
        ),
        target_identity_digest=(
            target_identity_digest if target_identity_digest is not None else confirmed.target_identity_digest
        ),
        issued_at=issued_at if issued_at is not None else now,
        expires_at=expires_at if expires_at is not None else now + timedelta(minutes=10),
    )
    return sign_sealed_write_approval(payload, authority_id=authority_id, private_key=private_key)


def _standard_executor(
    store,
    *,
    anchor=None,
    approval_authorities=None,
    approval_source=None,
    capability_security_classes=None,
) -> MutationExecutor:
    return MutationExecutor(
        store=store,
        write_client=_RaisingWriteClient(),
        read_client=_StubReadClient(),
        policy=MutationPolicy(
            frozenset(
                {
                    MutationRule(_STANDARD_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD),
                    MutationRule(_HIGH_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD),
                }
            )
        ),
        anti_rollback_anchor=anchor,
        encryption_key=_ENCRYPTION_KEY,
        capability_security_classes=capability_security_classes or _CAPABILITY_SECURITY_CLASSES,
        standard_sealed_write_approval_authorities=approval_authorities,
        standard_sealed_write_approval_source=approval_source,
    )


# ---------------------------------------------------------------------------
# A. Valid approval: the STANDARD success path (Section 15)
# ---------------------------------------------------------------------------


class _FakeVerifiedRequest(BaseModel):
    prefer: bool


class _FakeSendResponse:
    status_code = 200


class _FakeWriteClient:
    """Records exactly how many times a send was attempted -- proves
    "exactly one send" (Section 15) for a genuinely successful STANDARD
    execution, never a real network call."""

    def __init__(self) -> None:
        self.send_calls = 0

    def send_for_tier1(self, *, endpoint_symbol: str, http_method: str, body: bytes) -> _FakeSendResponse:
        self.send_calls += 1
        return _FakeSendResponse()


class _FullFakeAdapter:
    """A minimally complete `CapabilityAdapter` -- enough to drive
    `execute()` all the way to `VERIFIED` without any real transport,
    matching this contract's own digest bindings exactly."""

    endpoint_symbol = _ENDPOINT_SYMBOL
    http_method = _HTTP_METHOD
    capability = _STANDARD_CAPABILITY

    def read_target(self, read_client, natural_identity):
        return {"prefer": False}

    def natural_identity(self, raw_target):
        return {"timeserver": "1.pool.ntp.org"}

    def fingerprint(self, raw_target):
        return {"prefer": False}

    def transport_locator(self, raw_target):
        return 7

    def build_request(self, intent, target):
        return _FakeVerifiedRequest(prefer=True)

    def parse_response(self, raw_response):
        return {"status": "ok"}

    def is_semantically_verified(self, pre, post, intent):
        return True


def test_valid_standard_approval_reaches_verified_with_zero_witness_contact(tmp_path):
    """Full Section 15 ordering proof: approval verified -> policy
    authorization -> writable gate (runs exactly once) -> authoritative
    read -> EXECUTING (no witness call) -> exactly one send -> reread ->
    semantic verification -> VERIFIED. No real network, no real witness,
    no real signer key anywhere in this test."""

    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, private_key = _standard_authority()
    approval = _sign_approval(confirmed, private_key)
    source = _FakeApprovalSource({confirmed.contract_id: approval})
    read_client = _StubReadClient(read_only=False)
    write_client = _FakeWriteClient()
    executor = MutationExecutor(
        store=store,
        write_client=write_client,
        read_client=read_client,
        policy=MutationPolicy(frozenset({MutationRule(_STANDARD_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD)})),
        anti_rollback_anchor=anchor,
        encryption_key=_ENCRYPTION_KEY,
        capability_security_classes=_CAPABILITY_SECURITY_CLASSES,
        standard_sealed_write_approval_authorities=authorities,
        standard_sealed_write_approval_source=source,
    )

    matching_intent = {"raw_target_hint": {"timeserver": "1.pool.ntp.org"}, "prefer": True}
    outcome = executor.execute(confirmed.contract_id, adapter=_FullFakeAdapter(), intent=matching_intent)

    assert source.load_calls == [confirmed.contract_id]
    assert read_client.settings_calls == 1  # the universal pfREST Read Only gate still ran, exactly once
    assert anchor.read_calls == 0  # no witness/HighWaterMark contact whatsoever
    assert anchor.advance_calls == []
    assert write_client.send_calls == 1  # exactly one bounded send
    assert outcome.state is RecoveryState.VERIFIED
    events = store.audit_events(confirmed.contract_id)
    assert events[-1]["event_type"] != "sealed_write_approval_rejected"


# ---------------------------------------------------------------------------
# B-L. Approval adversarial matrix: fail-closed, zero side effects
# ---------------------------------------------------------------------------


def _assert_refused(store, contract_id, *, anchor, read_client) -> None:
    events = store.audit_events(contract_id)
    assert events[-1]["event_type"] == "sealed_write_approval_rejected"
    assert events[-1]["previous_state"] == RecoveryState.PREPARED.value
    assert events[-1]["current_state"] == RecoveryState.FAILED.value
    assert anchor.read_calls == 0
    assert anchor.advance_calls == []
    assert read_client.settings_calls == 0


def test_missing_approval_is_refused_deterministically(tmp_path):
    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, _ = _standard_authority()
    source = _FakeApprovalSource({})  # nothing on file for this contract_id
    read_client = _StubReadClient()
    executor = MutationExecutor(
        store=store,
        write_client=_RaisingWriteClient(),
        read_client=read_client,
        policy=MutationPolicy(frozenset({MutationRule(_STANDARD_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD)})),
        anti_rollback_anchor=anchor,
        encryption_key=_ENCRYPTION_KEY,
        capability_security_classes=_CAPABILITY_SECURITY_CLASSES,
        standard_sealed_write_approval_authorities=authorities,
        standard_sealed_write_approval_source=source,
    )

    outcome = executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    assert source.load_calls == [confirmed.contract_id]
    _assert_refused(store, confirmed.contract_id, anchor=anchor, read_client=read_client)


def test_absent_authorities_and_source_is_refused_not_a_permissive_default(tmp_path):
    """Constructing an executor for a STANDARD-capable registry without
    ever supplying either STANDARD parameter (the pre-Phase-2 default)
    must still refuse -- never silently permit STANDARD execution."""

    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    read_client = _StubReadClient()
    executor = MutationExecutor(
        store=store,
        write_client=_RaisingWriteClient(),
        read_client=read_client,
        policy=MutationPolicy(frozenset({MutationRule(_STANDARD_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD)})),
        anti_rollback_anchor=anchor,
        encryption_key=_ENCRYPTION_KEY,
        capability_security_classes=_CAPABILITY_SECURITY_CLASSES,
        # standard_sealed_write_approval_authorities / _source both default to None
    )

    outcome = executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    _assert_refused(store, confirmed.contract_id, anchor=anchor, read_client=read_client)


def test_approval_source_raising_is_treated_as_missing(tmp_path):
    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, _ = _standard_authority()
    read_client = _StubReadClient()
    executor = MutationExecutor(
        store=store,
        write_client=_RaisingWriteClient(),
        read_client=read_client,
        policy=MutationPolicy(frozenset({MutationRule(_STANDARD_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD)})),
        anti_rollback_anchor=anchor,
        encryption_key=_ENCRYPTION_KEY,
        capability_security_classes=_CAPABILITY_SECURITY_CLASSES,
        standard_sealed_write_approval_authorities=authorities,
        standard_sealed_write_approval_source=_RaisingApprovalSource(),
    )

    outcome = executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    _assert_refused(store, confirmed.contract_id, anchor=anchor, read_client=read_client)


@pytest.mark.parametrize(
    "wrong_field,wrong_value",
    [
        ("contract_id", "ntppref-someone-else"),
        ("state_version", 999),
        ("security_class", WriteSecurityClass.HIGH_ASSURANCE_TIER1),
        ("execution_intent_digest", "f" * 64),
        ("target_identity_digest", "e" * 64),
    ],
)
def test_approval_with_one_wrong_binding_field_is_refused(tmp_path, wrong_field, wrong_value):
    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, private_key = _standard_authority()
    approval = _sign_approval(confirmed, private_key, **{wrong_field: wrong_value})
    read_client = _StubReadClient()
    executor = _standard_executor(
        store,
        anchor=anchor,
        approval_authorities=authorities,
        approval_source=_FakeApprovalSource({confirmed.contract_id: approval}),
    )
    executor._read_client = read_client

    outcome = executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    _assert_refused(store, confirmed.contract_id, anchor=anchor, read_client=read_client)


def test_expired_approval_is_refused(tmp_path):
    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, private_key = _standard_authority()
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    approval = _sign_approval(confirmed, private_key, issued_at=past - timedelta(minutes=5), expires_at=past)
    read_client = _StubReadClient()
    executor = _standard_executor(
        store,
        anchor=anchor,
        approval_authorities=authorities,
        approval_source=_FakeApprovalSource({confirmed.contract_id: approval}),
    )
    executor._read_client = read_client

    outcome = executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    _assert_refused(store, confirmed.contract_id, anchor=anchor, read_client=read_client)


def test_wrong_authority_is_refused(tmp_path):
    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, _ = _standard_authority()
    wrong_private_key = Ed25519PrivateKey.generate()
    approval = _sign_approval(confirmed, wrong_private_key, authority_id="some-other-authority-v1")
    read_client = _StubReadClient()
    executor = _standard_executor(
        store,
        anchor=anchor,
        approval_authorities=authorities,
        approval_source=_FakeApprovalSource({confirmed.contract_id: approval}),
    )
    executor._read_client = read_client

    outcome = executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    _assert_refused(store, confirmed.contract_id, anchor=anchor, read_client=read_client)


def test_wrong_signing_key_is_refused(tmp_path):
    """Same authority_id, different (unpinned) private key -- signature
    corruption/forgery, distinct from the wrong-authority-id case above."""

    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, _real_key = _standard_authority()
    forged_key = Ed25519PrivateKey.generate()
    approval = _sign_approval(confirmed, forged_key)
    read_client = _StubReadClient()
    executor = _standard_executor(
        store,
        anchor=anchor,
        approval_authorities=authorities,
        approval_source=_FakeApprovalSource({confirmed.contract_id: approval}),
    )
    executor._read_client = read_client

    outcome = executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    _assert_refused(store, confirmed.contract_id, anchor=anchor, read_client=read_client)


def test_malformed_approval_object_from_source_is_refused(tmp_path):
    """A source returning something that is not a real `SealedWriteApproval`
    at all (e.g. a stale cached value of the wrong type) must fail closed,
    never raise out of `execute()`."""

    class _MisbehavingSource:
        def load(self, contract_id: str) -> object:
            return "not-a-sealed-write-approval"

    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, _ = _standard_authority()
    read_client = _StubReadClient()
    executor = _standard_executor(
        store, anchor=anchor, approval_authorities=authorities, approval_source=_MisbehavingSource()
    )
    executor._read_client = read_client

    outcome = executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    _assert_refused(store, confirmed.contract_id, anchor=anchor, read_client=read_client)


def test_approval_replay_after_state_version_bump_is_rejected(tmp_path):
    """An approval signed for the version the contract had at PREPARED-
    unconfirmed time (one less than its actual confirmed version) must
    not verify -- proves the approval is bound to the exact execution-
    time state_version, not merely "some version this contract once had"."""

    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, private_key = _standard_authority()
    stale_approval = _sign_approval(confirmed, private_key, state_version=confirmed.state_version - 1)
    read_client = _StubReadClient()
    executor = _standard_executor(
        store,
        anchor=anchor,
        approval_authorities=authorities,
        approval_source=_FakeApprovalSource({confirmed.contract_id: stale_approval}),
    )
    executor._read_client = read_client

    outcome = executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    _assert_refused(store, confirmed.contract_id, anchor=anchor, read_client=read_client)


def test_approval_bound_to_a_different_semantic_intent_is_rejected(tmp_path):
    """An approval whose execution_intent_digest reflects a different
    (e.g. previously-reviewed-then-changed) semantic mutation must not
    verify against a contract carrying a different intent_digest, even
    with every other field matching."""

    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, private_key = _standard_authority()
    different_intent_digest = digest_value(
        DigestPurpose.INTENT, {"raw_target_hint": {}, "prefer": False}, context=_CONTEXT
    )
    approval = _sign_approval(confirmed, private_key, execution_intent_digest=different_intent_digest)
    read_client = _StubReadClient()
    executor = _standard_executor(
        store,
        anchor=anchor,
        approval_authorities=authorities,
        approval_source=_FakeApprovalSource({confirmed.contract_id: approval}),
    )
    executor._read_client = read_client

    outcome = executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is RecoveryState.FAILED
    _assert_refused(store, confirmed.contract_id, anchor=anchor, read_client=read_client)


def test_approval_rejection_never_becomes_reconciliation(tmp_path):
    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, _ = _standard_authority()
    executor = _standard_executor(
        store, anchor=anchor, approval_authorities=authorities, approval_source=_FakeApprovalSource({})
    )

    outcome = executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    assert outcome.state is not RecoveryState.RECONCILIATION
    assert store.load(confirmed.contract_id).state is not RecoveryState.RECONCILIATION


def test_approval_rejection_audit_event_is_mac_protected_tamper_evident(tmp_path):
    """Tampering with the durable `event_type` (or any other audit field)
    after the fact must be detected by the existing audit MAC mechanism
    -- proves this new event_type rides the existing integrity-protected
    audit chain, not a parallel, unprotected log."""

    import sqlite3

    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(security_class=WriteSecurityClass.STANDARD_SEALED_WRITE)
    confirmed = _confirm(store, contract)
    authorities, _ = _standard_authority()
    executor = _standard_executor(
        store, anchor=anchor, approval_authorities=authorities, approval_source=_FakeApprovalSource({})
    )
    executor.execute(confirmed.contract_id, adapter=_SyntheticAdapter(), intent={"raw_target_hint": {}})

    db_path = tmp_path / "contracts.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE audit_events SET event_type = 'security_class_mismatch' "
            "WHERE contract_id = ? AND event_type = 'sealed_write_approval_rejected'",
            (confirmed.contract_id,),
        )
        connection.commit()

    reopened = _store(tmp_path, anchor=anchor)
    with pytest.raises(ContractIntegrityError):
        reopened.audit_events(confirmed.contract_id)


# ---------------------------------------------------------------------------
# M. HIGH_ASSURANCE irrelevance: a valid STANDARD approval never downgrades HIGH
# ---------------------------------------------------------------------------


class _HighCapabilityAdapterFailingAtRead:
    """A HIGH-classified adapter whose semantic-identity bindings match
    the contract exactly (so `verify_bindings()` passes and the flow
    reaches the normal witness-gated EXECUTING transition), but whose
    `read_target()` then deliberately fails with a plain, expected
    exception -- caught by `execute()`'s own existing pre-send fault
    handling, producing an ordinary FAILED outcome for a reason
    completely unrelated to the STANDARD approval mechanism."""

    endpoint_symbol = _ENDPOINT_SYMBOL
    http_method = _HTTP_METHOD
    capability = _HIGH_CAPABILITY

    def natural_identity(self, raw_target):
        return {"timeserver": "1.pool.ntp.org"}

    def fingerprint(self, raw_target):
        return {"prefer": False}

    def read_target(self, read_client, natural_identity):
        raise RuntimeError("synthetic pre-send read failure -- expected for this test")


def test_valid_standard_approval_is_irrelevant_to_a_high_assurance_capability(tmp_path):
    """A HIGH_ASSURANCE_TIER1 contract must follow its existing witness
    path regardless of whether a *valid* STANDARD approval happens to
    exist for it -- the approval source must never even be consulted."""

    anchor = _FakeAnchor()
    store = _store(tmp_path, anchor=anchor)
    contract = _build_contract(
        contract_id="systz-001", capability=_HIGH_CAPABILITY, security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1
    )
    confirmed = _confirm(store, contract)
    authorities, private_key = _standard_authority()
    # A validly-signed STANDARD approval, bound correctly to THIS
    # contract's own fields -- if the executor ever consulted it for a
    # HIGH capability, this would (incorrectly) let it "pass".
    approval = _sign_approval(confirmed, private_key)
    source = _FakeApprovalSource({confirmed.contract_id: approval})
    executor = _standard_executor(store, anchor=anchor, approval_authorities=authorities, approval_source=source)

    matching_intent = {"raw_target_hint": {"timeserver": "1.pool.ntp.org"}, "prefer": True}
    executor.execute(confirmed.contract_id, adapter=_HighCapabilityAdapterFailingAtRead(), intent=matching_intent)

    # The adapter's own read_target() deliberately raises, so this HIGH
    # contract still fails -- for an entirely different, existing reason
    # (adapter read failure during the normal witness-gated path), never
    # security_class_mismatch, never sealed_write_approval_rejected.
    events = store.audit_events(confirmed.contract_id)
    assert events[-1]["event_type"] not in ("sealed_write_approval_rejected", "security_class_mismatch")
    # The approval source must never even be consulted for a HIGH capability.
    assert source.load_calls == []
    # HIGH's witness gate still ran (anchor.read_calls == 1 proves the
    # EXECUTING transition's HighWaterMark check executed normally).
    assert anchor.read_calls == 1


# ---------------------------------------------------------------------------
# T. Runtime import graph: signing/private-key operations unreachable
# ---------------------------------------------------------------------------


def test_executor_module_never_imports_the_signing_cli_package():
    """`executor.py` (and everything it imports) must never reach
    `signing.standard_sealed_write_signing` or any private-key-signing
    function -- the runtime only ever *verifies* approvals, never signs
    them. Proven by direct import-graph inspection, mirroring
    `signing/tests/test_signing_transport_isolation.py`'s own established
    discipline (inverted: proving the runtime cannot reach the signer,
    rather than the signer cannot reach the runtime)."""

    import sys

    for name in list(sys.modules):
        if name.startswith("signing") or name == "pfsense_mcp.tier1.executor":
            del sys.modules[name]

    import pfsense_mcp.tier1.executor  # noqa: F401

    loaded = {name for name in sys.modules if name.startswith("signing")}
    assert loaded == set(), f"executor.py must never load the signing CLI package, but loaded: {loaded}"


def test_sealed_write_approval_module_exposes_no_signing_function_to_the_executor():
    """`MutationExecutor` only ever imports `verify_sealed_write_approval`
    and `StandardSealedWriteApprovalSource` from `sealed_write_approval.py`
    -- never `sign_sealed_write_approval` (which requires an
    `Ed25519PrivateKey` the runtime never holds)."""

    import pfsense_mcp.tier1.executor as executor_module

    assert not hasattr(executor_module, "sign_sealed_write_approval")
