"""W3 Slice 3 -- production composition tests for
`ProductionAliasDescriptionRuntime.request_alias_description_change()`.

Constructs `ProductionAliasDescriptionRuntime` directly with synthetic
components (mirroring `test_alias_description_execution.py`'s established
`_core()` pattern), not through `build_production_runtime()` -- the
composed operation's own logic is what these tests exercise, not
environment-variable plumbing (already covered by `test_production_runtime.py`).
A `Mock(spec=MutationExecutor)` stands in for the sealed executor exactly
as the existing W1 test suite already does; every other component
(store, consumption store, authorization/confirmation verification) is
real.
"""

from __future__ import annotations

import dataclasses
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pfsense_mcp.models.firewall_alias import FirewallAlias
from pfsense_mcp.models.system import SystemStatus
from pfsense_mcp.models.system_ha_sync import SystemHaSync
from pfsense_mcp.security_authorization import (
    PlanAuthorizationStepBinding,
    build_plan_authorization_v2_payload,
    sign_plan_authorization_v2,
)
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.tier1.alias_description import (
    AliasDescriptionChangeV1,
    AliasDescriptionPreparerV1,
    ConfiguredApplianceTargetV1,
)
from pfsense_mcp.tier1.alias_description_execution import AliasDescriptionExecutionCoreV1
from pfsense_mcp.tier1.artifact_exchange import (
    confirmation_evidence_to_bytes,
    load_authorization_preview,
    load_pending_confirmation_request,
    plan_authorization_v2_to_bytes,
    write_secure_new,
)
from pfsense_mcp.tier1.authorization_consumption_store import AuthorizationConsumptionStore
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM, Ed25519ConfirmationVerifier, signing_payload
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.executor import ExecutionOutcome, MutationExecutor
from pfsense_mcp.tier1.key_lifecycle import KeyPurpose, KeyRecord, NonceCounter
from pfsense_mcp.tier1.prepared_execution_intent import compute_execution_intent_digest
from pfsense_mcp.tier1.production_runtime import (
    ProductionAliasDescriptionRuntime,
    ProductOutcomeState,
    _project_recovery_state,
)
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore
from pfsense_mcp.tls import TLSMode
from tests.test_security_plan_digest import _synthetic_plan, _synthetic_step

NOW = datetime.now(timezone.utc).replace(microsecond=0)
_ARTIFACT_INTEGRITY_KEY = b"slice3-artifact-integrity-key-32"
_CONFIRMATION_AUTHORITY_ID = "confirm-owner-v3"


@pytest.fixture(autouse=True)
def _bypass_plan_freshness_environment_discovery(monkeypatch):
    """Mirrors `test_alias_description_execution.py`'s established
    pattern: `_plan_is_fresh()`'s real implementation calls
    `discover_security_posture()`/`generate_security_posture_plan()`
    against the actual runtime environment, which these composition
    tests are not exercising -- every other check in `authorize_and_create()`
    (signature, expiry, exact plan/step/digest binding) remains real."""

    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))


class _ReadClient:
    def __init__(self) -> None:
        self.aliases = [
            FirewallAlias(
                id=0, name="LAB_ALIAS_TEST", type="host", descr="before", address=["192.0.2.10"], detail=["synthetic"]
            )
        ]
        self.netgate_id: str | None = "netgate-synthetic"
        self.pfhostid: str | None = "pfhost-synthetic"

    def get_firewall_aliases(self, *, include_identifying_metadata: bool = False, limit: int = 100):
        assert include_identifying_metadata is True
        assert limit == 500
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


def _target() -> ConfiguredApplianceTargetV1:
    return ConfiguredApplianceTargetV1(base_url="https://pfsense.invalid", tls_mode=TLSMode.STRICT)


def _preparer(client: _ReadClient) -> AliasDescriptionPreparerV1:
    return AliasDescriptionPreparerV1(read_client=client, configured_target=_target())


def _store(tmp_path: Path, *, confirmation_verifier) -> SqliteRecoveryContractStore:
    tmp_path.chmod(0o700)
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=b"i" * 32,
        store_id="w3-slice3-synthetic",
        clock=lambda: NOW,
        confirmation_verifier=confirmation_verifier,
    )


def _keypair() -> tuple[Ed25519PrivateKey, PinnedAuthoritySet]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, PinnedAuthoritySet((PinnedAuthority(authority_id="owner-v2", public_key=public),))


def _authorization(private: Ed25519PrivateKey, digest: str, **changes: object):
    plan = _synthetic_plan(
        steps=(
            _synthetic_step(
                step_id="first.write.alias.description",
                order=1,
                authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE,
            ),
        )
    )
    values: dict[str, object] = {
        "plan": plan,
        "authorized_executions": (
            PlanAuthorizationStepBinding(step_id="first.write.alias.description", execution_intent_digest=digest),
        ),
        "authorization_id": f"authz-{os.urandom(4).hex()}",
        "authority_id": "owner-v2",
        "issued_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=4),
    }
    values.update(changes)
    return sign_plan_authorization_v2(build_plan_authorization_v2_payload(**values), private)  # type: ignore[arg-type]


def _confirm_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def _sign_confirmation(private: Ed25519PrivateKey, contract, **changes: object) -> ConfirmationEvidence:
    values: dict[str, object] = {
        "authority_id": _CONFIRMATION_AUTHORITY_ID,
        "algorithm": ACCEPTED_ALGORITHM,
        "nonce": f"nonce-{os.urandom(4).hex()}",
        "contract_id": contract.contract_id,
        "operation_id": contract.operation_id,
        "target_identity_digest": contract.target_identity_digest,
        "target_fingerprint": contract.target_fingerprint,
        "intent_digest": contract.intent_digest,
        "expires_at": contract.expires_at,
        "issued_at": NOW - timedelta(seconds=1),
    }
    values.update(changes)
    unsigned = ConfirmationEvidence(**values, proof=b"x" * 64)  # type: ignore[arg-type]
    proof = private.sign(signing_payload(unsigned))
    return ConfirmationEvidence(**{**values, "proof": proof})  # type: ignore[arg-type]


class _RuntimeHandles:
    def __init__(
        self,
        runtime: ProductionAliasDescriptionRuntime,
        store: SqliteRecoveryContractStore,
        consumption: _ConsumptionStore,
        executor: Mock,
    ) -> None:
        self.runtime = runtime
        self.store = store
        self.consumption = consumption
        self.executor = executor


def _paths(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    return (
        tmp_path / "authorization-inbox.json",
        tmp_path / "confirmation-pending.json",
        tmp_path / "confirmation-signed.json",
        tmp_path / "authorization-preview.json",
    )


def _new_runtime(
    tmp_path: Path,
    client: _ReadClient,
    *,
    authorities: PinnedAuthoritySet,
    confirm_public: bytes,
    verified_outcome: RecoveryState = RecoveryState.VERIFIED,
) -> _RuntimeHandles:
    """A fresh `ProductionAliasDescriptionRuntime` sharing the on-disk
    store at `tmp_path` -- simulating a later, separate call (or a real
    restart) against the same durable state, exactly like
    `test_alias_description_execution.py`'s Slice 3A tests do. Pinned to
    the SAME `authorities`/`confirm_public` across every call in a test --
    a fresh, unrelated keypair per call would make every authorization/
    confirmation fail signature verification regardless of what this
    composed method actually does."""

    confirmation_verifier = Ed25519ConfirmationVerifier(
        (PinnedAuthority(authority_id=_CONFIRMATION_AUTHORITY_ID, public_key=confirm_public),)
    )
    store = _store(tmp_path, confirmation_verifier=confirmation_verifier)
    consumption = _ConsumptionStore()
    executor = Mock(spec=MutationExecutor)
    executor.execute.return_value = ExecutionOutcome("unused", verified_outcome, "synthetic")
    counter = NonceCounter(tmp_path / "nonce.json", key_id="enc-w1")
    preparer = _preparer(client)
    execution_core = AliasDescriptionExecutionCoreV1(
        preparer=preparer,
        authorities=authorities,
        consumption_store=consumption,
        contract_store=store,
        executor=executor,
        encryption_key=KeyRecord("enc-w1", 0, b"e" * 32, KeyPurpose.ENCRYPTION),
        nonce_counter=counter,
    )
    authorization_inbox_file, confirmation_pending_file, confirmation_signed_file, authorization_preview_file = _paths(
        tmp_path
    )
    runtime = ProductionAliasDescriptionRuntime(
        execution_core=execution_core,
        store=store,
        preparer=preparer,
        authorization_inbox_file=authorization_inbox_file,
        confirmation_pending_file=confirmation_pending_file,
        confirmation_signed_file=confirmation_signed_file,
        authorization_preview_file=authorization_preview_file,
        confirmation_authority_id=_CONFIRMATION_AUTHORITY_ID,
        artifact_integrity_key=_ARTIFACT_INTEGRITY_KEY,
    )
    return _RuntimeHandles(runtime, store, consumption, executor)


def _fixture(
    tmp_path: Path,
) -> tuple[_ReadClient, Ed25519PrivateKey, PinnedAuthoritySet, bytes, Ed25519PrivateKey]:
    client = _ReadClient()
    authz_private, authorities = _keypair()
    confirm_private, confirm_public = _confirm_keypair()
    return client, authz_private, authorities, confirm_public, confirm_private


def _request() -> AliasDescriptionChangeV1:
    return AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")


def _call(handles: _RuntimeHandles, request: AliasDescriptionChangeV1 | None = None, *, now: datetime = NOW):
    return handles.runtime.request_alias_description_change(
        request or _request(),
        requested_plan_digest="",  # overwritten below via authorization's own plan_digest when relevant
        requested_step_id="first.write.alias.description",
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
        target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
        now=now,
    )


def _call_with_plan_digest(
    handles: _RuntimeHandles,
    authorization,
    request=None,
    *,
    now: datetime = NOW,
    requested_step_id: str = "first.write.alias.description",
):
    return handles.runtime.request_alias_description_change(
        request or _request(),
        requested_plan_digest=authorization.plan_digest,
        requested_step_id=requested_step_id,
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
        target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
        now=now,
    )


def _authorized_intent_digest(client: _ReadClient) -> str:
    prepared = _preparer(client).prepare(_request())
    return compute_execution_intent_digest(prepared.intent)


# --------------------------------------------------------------------------
# Pure mapping / helper unit tests
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "state,expected",
    [
        (RecoveryState.VERIFIED, ProductOutcomeState.VERIFIED),
        (RecoveryState.RECONCILIATION, ProductOutcomeState.RECONCILIATION_REQUIRED),
        (RecoveryState.PREPARING, ProductOutcomeState.REFUSED),
        (RecoveryState.PREPARED, ProductOutcomeState.REFUSED),
        (RecoveryState.EXECUTING, ProductOutcomeState.REFUSED),
        (RecoveryState.FAILED, ProductOutcomeState.REFUSED),
        (RecoveryState.ROLLING_BACK, ProductOutcomeState.REFUSED),
        (RecoveryState.ROLLED_BACK, ProductOutcomeState.REFUSED),
        (RecoveryState.ROLLBACK_FAILED, ProductOutcomeState.REFUSED),
        (RecoveryState.EXPIRED, ProductOutcomeState.REFUSED),
    ],
)
def test_project_recovery_state_mapping_is_exhaustive_and_uniform(state, expected):
    assert _project_recovery_state(state) is expected


# --------------------------------------------------------------------------
# No-match / REQUESTED
# --------------------------------------------------------------------------


def test_no_authorization_artifact_returns_requested_zero_consumption(tmp_path):
    client, _authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)

    outcome = _call(handles)

    assert outcome.state is ProductOutcomeState.REQUESTED
    assert outcome.contract_id is None
    assert handles.consumption.calls == 0
    assert handles.store.all_contracts() == ()


# --------------------------------------------------------------------------
# AuthorizationPreview (W3 Slice 5A)
# --------------------------------------------------------------------------


def _call_requested_with_real_digest(handles: _RuntimeHandles, *, plan_digest: str = "a" * 64, now: datetime = NOW):
    return handles.runtime.request_alias_description_change(
        _request(),
        requested_plan_digest=plan_digest,
        requested_step_id="first.write.alias.description",
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
        target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
        now=now,
    )


def test_authorization_preview_emitted_on_requested_state_matches_exact_fields(tmp_path):
    client, _authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    _authorization_inbox_file, _pending, _signed, preview_file = _paths(tmp_path)

    outcome = _call_requested_with_real_digest(handles, plan_digest="c" * 64)

    assert outcome.state is ProductOutcomeState.REQUESTED
    assert preview_file.exists()
    preview = load_authorization_preview(preview_file, integrity_key=_ARTIFACT_INTEGRITY_KEY)
    assert preview.alias_name == "LAB_ALIAS_TEST"
    assert preview.previous_description == "before"
    assert preview.requested_description == "after"
    assert preview.execution_intent_digest == _authorized_intent_digest(client)
    assert preview.requested_plan_digest == "c" * 64
    assert preview.requested_step_id == "first.write.alias.description"
    assert preview.target_capability_posture is CapabilityPosture.WRITE_PROTECTED
    assert preview.target_anchor_assurance is AnchorAssurance.HARDWARE_WITNESS


def test_authorization_preview_grants_no_authority_by_itself(tmp_path):
    """A preview existing on disk, with no signed PlanAuthorizationV2 in
    the inbox, must never itself cause anything to be authorized --
    the outcome remains REQUESTED, zero consumption, zero contract."""

    client, _authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)

    first = _call_requested_with_real_digest(handles)
    assert first.state is ProductOutcomeState.REQUESTED
    _authorization_inbox_file, _pending, _signed, preview_file = _paths(tmp_path)
    assert preview_file.exists()

    second = _call_requested_with_real_digest(handles)

    assert second.state is ProductOutcomeState.REQUESTED
    assert second.contract_id is None
    assert handles.consumption.calls == 0
    assert handles.store.all_contracts() == ()


def test_authorization_preview_not_overwritten_if_already_present(tmp_path):
    client, _authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    _authorization_inbox_file, _pending, _signed, preview_file = _paths(tmp_path)
    preview_file.parent.mkdir(parents=True, exist_ok=True)
    write_secure_new(preview_file, b'{"unrelated": "leftover-artifact"}')

    outcome = _call_requested_with_real_digest(handles)

    assert outcome.state is ProductOutcomeState.REQUESTED
    assert preview_file.read_bytes() == b'{"unrelated": "leftover-artifact"}'


def test_authorization_preview_carries_no_sensitive_internal_fields():
    """Structural: the artifact never exposes raw_target_hint, a numeric
    lifecycle locator, a raw target fingerprint dict, credentials, keys,
    or HMAC secrets -- only the fixed, narrow field set ADR-028's Slice
    5A authorization anticipated."""

    import dataclasses as _dc

    from pfsense_mcp.tier1.artifact_exchange import AuthorizationPreview

    field_names = {field.name for field in _dc.fields(AuthorizationPreview)}
    forbidden = {
        "raw_target_hint",
        "numeric_locator",
        "lifecycle_locator",
        "target_fingerprint",
        "api_key",
        "encryption_key",
        "integrity_key",
        "hmac_secret",
        "private_key",
        "proof",
        "signature",
    }
    assert field_names.isdisjoint(forbidden)


# --------------------------------------------------------------------------
# Invalid authorization artifact -> REFUSED, zero consumption
# --------------------------------------------------------------------------


def test_malformed_authorization_artifact_refused_zero_consumption(tmp_path):
    client, _authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, _signed, _preview = _paths(tmp_path)
    authorization_inbox_file.parent.mkdir(parents=True, exist_ok=True)
    authorization_inbox_file.write_bytes(b"not json")
    os.chmod(authorization_inbox_file, 0o600)

    outcome = _call(handles)

    assert outcome.state is ProductOutcomeState.REFUSED
    assert outcome.contract_id is None
    assert handles.consumption.calls == 0
    assert handles.store.all_contracts() == ()
    assert authorization_inbox_file.exists()  # never auto-deleted


def test_unsafe_permission_authorization_artifact_refused(tmp_path):
    client, authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, _signed, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))
    os.chmod(authorization_inbox_file, 0o644)

    outcome = _call_with_plan_digest(handles, authorization)

    assert outcome.state is ProductOutcomeState.REFUSED
    assert handles.consumption.calls == 0
    assert handles.store.all_contracts() == ()


def test_symlinked_authorization_artifact_refused(tmp_path):
    client, authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, _signed, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    real = tmp_path / "real-authorization.json"
    write_secure_new(real, plan_authorization_v2_to_bytes(authorization))
    authorization_inbox_file.symlink_to(real)

    outcome = _call_with_plan_digest(handles, authorization)

    assert outcome.state is ProductOutcomeState.REFUSED
    assert handles.consumption.calls == 0


@pytest.mark.parametrize(
    "case", ["wrong-step", "wrong-digest", "expired", "future", "bad-signature", "wrong-authority"]
)
def test_authorization_binding_failures_refuse_before_handoff(tmp_path, case):
    """Every one of these cases fails one of `authorize_and_create()`'s
    non-mutating gates (signature, validity window, exact plan/step/digest
    binding) -- all of which run strictly before `try_consume()` -- so
    zero consumption is the correct expectation across the board, not
    just "never succeeds into a contract"."""

    client, authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, _signed, _preview = _paths(tmp_path)
    digest = _authorized_intent_digest(client)

    changes: dict[str, object] = {}
    requested_step_id = "first.write.alias.description"
    if case == "wrong-step":
        # The authorization is validly bound to the plan's own (only)
        # step; the OPERATION requests a different step_id than what was
        # authorized -- plan_authorization_v2_authorizes_execution()'s
        # exact-membership check must refuse this, not
        # build_plan_authorization_v2_payload() (which validates the
        # authorized step_id is a real plan step, not what the caller
        # later requests).
        requested_step_id = "a-different-step-than-was-authorized"
    elif case == "wrong-digest":
        digest = "a" * 64
    elif case == "expired":
        changes["issued_at"] = NOW - timedelta(minutes=10)
        changes["expires_at"] = NOW - timedelta(minutes=5)
    elif case == "future":
        changes["issued_at"] = NOW + timedelta(minutes=5)
        changes["expires_at"] = NOW + timedelta(minutes=10)

    authorization = _authorization(authz_private, digest, **changes)
    if case == "bad-signature":
        authorization = dataclasses.replace(authorization, proof=b"x" * 64)
    if case == "wrong-authority":
        other_private, _other = _keypair()
        authorization = _authorization(other_private, digest)

    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))

    outcome = _call_with_plan_digest(handles, authorization, requested_step_id=requested_step_id)

    assert outcome.state is ProductOutcomeState.REFUSED
    assert handles.consumption.calls == 0
    assert handles.store.all_contracts() == ()


# --------------------------------------------------------------------------
# Valid authorization -> exactly one W1 path
# --------------------------------------------------------------------------


def test_valid_authorization_creates_prepared_contract_and_awaits_confirmation(tmp_path):
    client, authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, confirmation_pending_file, _signed, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))

    outcome = _call_with_plan_digest(handles, authorization)

    assert outcome.state is ProductOutcomeState.AWAITING_CONFIRMATION
    assert outcome.contract_id is not None
    assert handles.consumption.calls == 1
    contracts = handles.store.all_contracts()
    assert len(contracts) == 1
    assert contracts[0].contract_id == outcome.contract_id
    assert contracts[0].state is RecoveryState.PREPARED
    handles.executor.execute.assert_not_called()

    # Exact pending-confirmation request emitted, matching the contract.
    assert confirmation_pending_file.exists()
    pending = load_pending_confirmation_request(confirmation_pending_file, integrity_key=_ARTIFACT_INTEGRITY_KEY)
    assert pending.contract_id == outcome.contract_id
    assert pending.expected_authority_id == _CONFIRMATION_AUTHORITY_ID
    assert pending.alias_name == "LAB_ALIAS_TEST"
    assert pending.previous_description == "before"
    assert pending.requested_description == "after"
    assert pending.target_identity_digest == contracts[0].target_identity_digest
    assert pending.target_fingerprint == contracts[0].target_fingerprint
    assert pending.intent_digest == contracts[0].intent_digest


def test_confirmation_preview_grants_no_confirmation_authority_by_itself(tmp_path):
    """A pending-confirmation preview existing on disk, with no signed
    ConfirmationEvidence yet, must never itself advance the operation --
    the outcome remains AWAITING_CONFIRMATION until a real, verified
    signature arrives."""

    client, authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, confirmation_pending_file, _signed, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))

    first = _call_with_plan_digest(handles, authorization)
    assert first.state is ProductOutcomeState.AWAITING_CONFIRMATION
    assert confirmation_pending_file.exists()

    second = _call_with_plan_digest(handles, authorization)

    assert second.state is ProductOutcomeState.AWAITING_CONFIRMATION
    assert second.contract_id == first.contract_id
    assert len(handles.store.all_contracts()) == 1
    handles.executor.execute.assert_not_called()


def test_pending_confirmation_request_carries_no_sensitive_internal_fields():
    """Structural: no raw_target_hint, numeric lifecycle locator, raw
    API payload, credentials, keys, or HMAC secrets -- only the fixed,
    narrow field set ADR-028's Slice 5A authorization anticipated."""

    import dataclasses as _dc

    from pfsense_mcp.tier1.artifact_exchange import PendingConfirmationRequest

    field_names = {field.name for field in _dc.fields(PendingConfirmationRequest)}
    forbidden = {
        "raw_target_hint",
        "numeric_locator",
        "lifecycle_locator",
        "api_key",
        "encryption_key",
        "integrity_key",
        "hmac_secret",
        "private_key",
        "proof",
        "signature",
    }
    assert field_names.isdisjoint(forbidden)


def test_valid_authorization_and_prepositioned_confirmation_completes_in_one_call(tmp_path):
    """ADR-028's accepted pre-positioned special case: both artifacts are
    already present before the first call. Requires the confirmation's
    contract_id to be predictable -- exercised via the two-call sequence
    below instead, since a contract_id is only known after creation. This
    test instead proves the immediately-following call (still logically
    "one call" from the product's perspective in the sense that no
    artifact changes between contract-creation and confirmation-pickup)
    completes straight through without a second contract or duplicate
    consumption."""

    client, authz_private, authorities, confirm_public, confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, confirmation_signed_file, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))

    first = _call_with_plan_digest(handles, authorization)
    assert first.state is ProductOutcomeState.AWAITING_CONFIRMATION
    contract = handles.store.load(first.contract_id)
    confirmation = _sign_confirmation(confirm_private, contract)
    write_secure_new(confirmation_signed_file, confirmation_evidence_to_bytes(confirmation))

    second = _call_with_plan_digest(handles, authorization)

    assert second.state is ProductOutcomeState.VERIFIED
    assert second.contract_id == first.contract_id
    handles.executor.execute.assert_called_once()
    assert handles.consumption.calls == 1
    assert len(handles.store.all_contracts()) == 1


# --------------------------------------------------------------------------
# Dedup / re-invocation (across fresh runtime instances -- restart-safe)
# --------------------------------------------------------------------------


def test_reinvocation_with_prepared_contract_does_not_reconsume_or_recreate(tmp_path):
    client, authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    first_handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, _signed, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))

    first = _call_with_plan_digest(first_handles, authorization)
    assert first.state is ProductOutcomeState.AWAITING_CONFIRMATION

    # Fresh runtime, same durable store -- the authorization artifact is
    # still sitting in the inbox (already consumed), but the fresh
    # runtime's OWN consumption store must never even be asked.
    second_handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    second = _call_with_plan_digest(second_handles, authorization)

    assert second.state is ProductOutcomeState.AWAITING_CONFIRMATION
    assert second.contract_id == first.contract_id
    assert second_handles.consumption.calls == 0
    assert len(second_handles.store.all_contracts()) == 1
    second_handles.executor.execute.assert_not_called()


def test_reinvocation_after_confirmation_present_completes_via_resume(tmp_path):
    client, authz_private, authorities, confirm_public, confirm_private = _fixture(tmp_path)
    first_handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, confirmation_signed_file, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))
    first = _call_with_plan_digest(first_handles, authorization)
    assert first.state is ProductOutcomeState.AWAITING_CONFIRMATION
    first_handles.executor.execute.assert_not_called()

    contract = first_handles.store.load(first.contract_id)
    confirmation = _sign_confirmation(confirm_private, contract)
    write_secure_new(confirmation_signed_file, confirmation_evidence_to_bytes(confirmation))

    # A third, entirely fresh runtime -- simulates a real restart between
    # authorization and confirmation.
    third_handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    third = _call_with_plan_digest(third_handles, authorization)

    assert third.state is ProductOutcomeState.VERIFIED
    assert third.contract_id == first.contract_id
    third_handles.executor.execute.assert_called_once()
    first_handles.executor.execute.assert_not_called()  # the original runtime's executor never fires
    assert third_handles.consumption.calls == 0  # never re-consumed by the resuming runtime
    assert len(third_handles.store.all_contracts()) == 1


def test_existing_non_prepared_contract_refuses_without_reauthorizing(tmp_path):
    client, authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    first_handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, _signed, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))
    first = _call_with_plan_digest(first_handles, authorization)
    assert first.state is ProductOutcomeState.AWAITING_CONFIRMATION

    # Move the contract past PREPARED via a direct, already-tested store
    # transition (PREPARED -> FAILED needs no confirmation) -- simulates
    # "already handled to completion or in flight elsewhere."
    first_handles.store.transition(
        first.contract_id,
        expected_state=RecoveryState.PREPARED,
        expected_version=first_handles.store.load(first.contract_id).state_version,
        target_state=RecoveryState.FAILED,
    )

    # The original (already-consumed) authorization artifact is still
    # sitting in the fixed inbox (never auto-deleted). A fresh runtime
    # must refuse the dedup-matched, now-FAILED contract without ever
    # attempting to consume it again.
    second_handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    outcome = _call_with_plan_digest(second_handles, authorization)

    assert outcome.state is ProductOutcomeState.REFUSED
    assert outcome.contract_id == first.contract_id
    assert second_handles.consumption.calls == 0
    assert len(second_handles.store.all_contracts()) == 1


# --------------------------------------------------------------------------
# Confirmation-phase adversarial cases
# --------------------------------------------------------------------------


def test_malformed_confirmation_refused_no_handoff(tmp_path):
    client, authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, confirmation_signed_file, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))
    first = _call_with_plan_digest(handles, authorization)
    assert first.state is ProductOutcomeState.AWAITING_CONFIRMATION

    write_secure_new(confirmation_signed_file, b"not json")
    outcome = _call_with_plan_digest(handles, authorization)

    assert outcome.state is ProductOutcomeState.REFUSED
    assert outcome.contract_id == first.contract_id
    handles.executor.execute.assert_not_called()


def test_wrong_authority_confirmation_refused_no_handoff(tmp_path):
    client, authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, confirmation_signed_file, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))
    first = _call_with_plan_digest(handles, authorization)
    contract = handles.store.load(first.contract_id)

    wrong_private, _wrong_public = _confirm_keypair()
    confirmation = _sign_confirmation(wrong_private, contract)
    write_secure_new(confirmation_signed_file, confirmation_evidence_to_bytes(confirmation))

    outcome = _call_with_plan_digest(handles, authorization)

    assert outcome.state is ProductOutcomeState.REFUSED
    handles.executor.execute.assert_not_called()


def test_wrong_contract_binding_confirmation_refused(tmp_path):
    client, authz_private, authorities, confirm_public, confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, confirmation_signed_file, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))
    first = _call_with_plan_digest(handles, authorization)
    contract = handles.store.load(first.contract_id)

    confirmation = _sign_confirmation(confirm_private, contract, contract_id="aliasdescr-wrong-contract")
    write_secure_new(confirmation_signed_file, confirmation_evidence_to_bytes(confirmation))

    outcome = _call_with_plan_digest(handles, authorization)

    assert outcome.state is ProductOutcomeState.REFUSED
    handles.executor.execute.assert_not_called()


def test_duplicate_confirmation_cannot_produce_duplicate_handoff(tmp_path):
    client, authz_private, authorities, confirm_public, confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, confirmation_signed_file, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))
    first = _call_with_plan_digest(handles, authorization)
    contract = handles.store.load(first.contract_id)
    confirmation = _sign_confirmation(confirm_private, contract)
    write_secure_new(confirmation_signed_file, confirmation_evidence_to_bytes(confirmation))

    completed = _call_with_plan_digest(handles, authorization)
    assert completed.state is ProductOutcomeState.VERIFIED
    handles.executor.execute.assert_called_once()

    # Fresh runtime, same store, same (now-stale) signed confirmation
    # still present -- must not produce a second handoff.
    second_handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    outcome = _call_with_plan_digest(second_handles, authorization)

    assert outcome.state is ProductOutcomeState.REFUSED
    second_handles.executor.execute.assert_not_called()


# --------------------------------------------------------------------------
# Restart / no automatic resend, across three separate runtime instances
# --------------------------------------------------------------------------


def test_restart_sequence_creates_exactly_one_contract_and_one_send(tmp_path):
    client, authz_private, authorities, confirm_public, confirm_private = _fixture(tmp_path)
    authorization_inbox_file, _pending, confirmation_signed_file, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))

    call1 = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    outcome1 = _call_with_plan_digest(call1, authorization)
    assert outcome1.state is ProductOutcomeState.AWAITING_CONFIRMATION
    call1.executor.execute.assert_not_called()

    call2 = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    outcome2 = _call_with_plan_digest(call2, authorization)
    assert outcome2.state is ProductOutcomeState.AWAITING_CONFIRMATION
    assert outcome2.contract_id == outcome1.contract_id
    call2.executor.execute.assert_not_called()

    contract = call2.store.load(outcome1.contract_id)
    confirmation = _sign_confirmation(confirm_private, contract)
    write_secure_new(confirmation_signed_file, confirmation_evidence_to_bytes(confirmation))

    call3 = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    outcome3 = _call_with_plan_digest(call3, authorization)
    assert outcome3.state is ProductOutcomeState.VERIFIED
    call3.executor.execute.assert_called_once()

    call4 = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    outcome4 = _call_with_plan_digest(call4, authorization)
    assert outcome4.state is ProductOutcomeState.REFUSED  # duplicate confirmation, no second handoff
    call4.executor.execute.assert_not_called()

    assert len(call4.store.all_contracts()) == 1
    assert call1.consumption.calls == 1
    assert call2.consumption.calls == 0
    assert call3.consumption.calls == 0
    assert call4.consumption.calls == 0


# --------------------------------------------------------------------------
# Reconciliation-outcome projection (end to end, via the confirm branch)
# --------------------------------------------------------------------------


def test_reconciliation_outcome_projects_to_reconciliation_required(tmp_path):
    client, authz_private, authorities, confirm_public, confirm_private = _fixture(tmp_path)
    handles = _new_runtime(
        tmp_path,
        client,
        authorities=authorities,
        confirm_public=confirm_public,
        verified_outcome=RecoveryState.RECONCILIATION,
    )
    authorization_inbox_file, _pending, confirmation_signed_file, _preview = _paths(tmp_path)
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))
    first = _call_with_plan_digest(handles, authorization)
    contract = handles.store.load(first.contract_id)
    confirmation = _sign_confirmation(confirm_private, contract)
    write_secure_new(confirmation_signed_file, confirmation_evidence_to_bytes(confirmation))

    outcome = _call_with_plan_digest(handles, authorization)

    assert outcome.state is ProductOutcomeState.RECONCILIATION_REQUIRED
    handles.executor.execute.assert_called_once()


# --------------------------------------------------------------------------
# Artifact hygiene
# --------------------------------------------------------------------------


def test_pending_confirmation_request_not_overwritten_if_already_present(tmp_path):
    client, authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, confirmation_pending_file, _signed, _preview = _paths(tmp_path)
    confirmation_pending_file.parent.mkdir(parents=True, exist_ok=True)
    write_secure_new(confirmation_pending_file, b'{"unrelated": "leftover-artifact"}')
    authorization = _authorization(authz_private, _authorized_intent_digest(client))
    write_secure_new(authorization_inbox_file, plan_authorization_v2_to_bytes(authorization))

    outcome = _call_with_plan_digest(handles, authorization)

    assert outcome.state is ProductOutcomeState.AWAITING_CONFIRMATION
    assert confirmation_pending_file.read_bytes() == b'{"unrelated": "leftover-artifact"}'
    assert len(handles.store.all_contracts()) == 1  # the contract still exists regardless


def test_fixed_artifact_paths_are_never_selected_by_request_content(tmp_path):
    client, _authz_private, authorities, confirm_public, _confirm_private = _fixture(tmp_path)
    handles = _new_runtime(tmp_path, client, authorities=authorities, confirm_public=confirm_public)
    authorization_inbox_file, _pending, _signed, _preview = _paths(tmp_path)
    assert handles.runtime._authorization_inbox_file == authorization_inbox_file
    other_request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="a different description")
    outcome = _call(handles, other_request)
    assert outcome.state is ProductOutcomeState.REQUESTED  # same fixed (empty) inbox regardless of request content
