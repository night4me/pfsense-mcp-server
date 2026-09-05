"""Generic, capability-agnostic W1 authorization-to-contract core, shared by
every ADR-037 Batch 1 capability (`ntp_time_server_prefer.py`,
`ntp_settings_observability.py`, `log_display_preferences.py`,
`log_retention_settings.py`, `system_timezone_write.py`).

Inert, exactly like `alias_description_execution.py`: no tool, endpoint,
policy, capability, or runtime is registered here.

**Why a second module rather than generalizing `alias_description_execution.py`
itself**: ADR-036 W0 Gap 2's own resolution text frames consolidating the
existing live capability's canonical gate onto shared/generic code as "a
materially different, separately-risky change" out of scope for an
incidental hardening/expansion pass -- `alias_description_execution.py`'s
own `AliasDescriptionExecutionCoreV1` remains completely untouched, still
this codebase's sole canonical gate implementation for
`set_firewall_alias_description_v1`. This module is a NEW, independently
reviewable second implementation of the *same proven algorithm*, used only
by the five NEW ADR-037 Batch 1 capabilities.

**Why this generalization is safe**: reading `AliasDescriptionExecutionCoreV1`
end to end shows every method's logic operates only on: (a) `request`'s own
*identity* (an `isinstance()` check, never a field read), (b)
`authorized_preparation`'s three generic attributes (`.intent` -- already a
capability-agnostic `PreparedExecutionIntentV1`; `.authoritative_a` -- used
only via its generic `.numeric_locator` attribute; `.appliance_target_digest`),
and (c) two small alias-specific literals (the `contract_id`/`operation_id`
prefix, and the `_raw_target()` dict-construction rule for the idempotency
hint). Every other line -- signature verification, expiry, plan/step/risk-
class binding, freshness, one-time consumption, contract creation/encryption,
confirm/handoff, resume-from-durable-state, idempotency derivation -- is
already 100% generic. This module reproduces that logic verbatim, with only
those few capability-specific pieces taken as constructor parameters instead
of hardcoded, so it can never silently drift from the proven original: any
change made here for one capability is automatically reviewed for every
capability that shares this file, rather than needing five parallel
hand-edits kept in sync by convention alone.
"""

from __future__ import annotations

import hmac
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Protocol

from pfsense_mcp.security_authorization import PLAN_AUTHORIZATION_V2_SCHEMA_VERSION, PlanAuthorizationV2
from pfsense_mcp.security_authorization_verifier import (
    plan_authorization_v2_authorizes_execution,
    plan_authorization_v2_satisfies_required_risk_class,
    verify_plan_authorization_v2_signature,
)
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.security_plan_freshness import plan_authorization_is_fresh

from .authorization_consumption_store import AuthorizationConsumptionStore
from .canonical import CanonicalValue, DigestPurpose, canonical_json, digest_value
from .confirmation import ConfirmationEvidence
from .contract import (
    AUTHORIZATION_PROVENANCE_SCHEMA_VERSION,
    AuthorizationProvenance,
    ProtectedArtifact,
    RecoveryContract,
    derive_idempotency_key,
)
from .crypto import ArtifactRole, build_nonce, encrypt_artifact
from .ed25519_authority import PinnedAuthoritySet
from .errors import BoundExecutionError
from .executor import ExecutionOutcome, MutationExecutor
from .key_lifecycle import KeyRecord, NonceCounter
from .prepared_execution_intent import PreparedExecutionIntentV1, compute_execution_intent_digest

if TYPE_CHECKING:
    from .acceptance import AcceptanceExecutionContext

from .state_machine import RecoveryState
from .store import SqliteRecoveryContractStore

_DENIED = "Bound write execution denied."


class _AuthoritativeStateV1(Protocol):
    """The one attribute this core ever reads off `authoritative_a`."""

    numeric_locator: int


class PreparedWriteExecutionV1(Protocol):
    """The generic shape every capability's own `Prepared<Capability>
    ExecutionV1` frozen dataclass must have -- identical field set to
    `PreparedAliasDescriptionExecutionV1`, structurally, not by
    inheritance. `authoritative_a` need only expose `.numeric_locator: int`;
    this core never reads any other attribute of it."""

    intent: PreparedExecutionIntentV1
    authoritative_a: _AuthoritativeStateV1
    appliance_target_digest: str


class _PreparerProtocol(Protocol):
    """The two members `WriteExecutionCoreV1` ever uses on `preparer`.

    `adapter` is declared as a read-only `@property`, not a plain settable
    attribute: every concrete capability preparer (`SystemTimezonePreparerV1`
    etc.) exposes `adapter` via `@property`, mirroring
    `write_adapter_support.py`'s own `ConfiguredApplianceTargetLike`/
    `_TlsModeLike` fix for the identical mypy read-only-vs-settable-attribute
    issue -- a plain-attribute Protocol member requires the implementation
    to be settable, which a `@property` deliberately is not. This was never
    exercised by type-checked code before `tier1/write_batch1_production_
    runtime.py` (2026-09-04): only test files constructed a real
    `WriteExecutionCoreV1` with a concrete preparer previously, and `tests/`
    is not part of this project's mypy gate. Purely a static-typing
    correction -- Python does not check Protocol conformance at runtime, so
    this changes no runtime behavior of `authorize_and_create()`/
    `confirm_and_handoff()`/`resume_prepared()`.

    `prepare()`'s `request` parameter is `Any`, not `object`, for the same
    reason: every concrete preparer's own `prepare()` narrows this
    parameter to its own capability-specific request type (e.g.
    `SystemTimezonePreparerV1.prepare(self, request: SystemTimezoneChangeV1)`),
    which violates parameter contravariance against an `object`-typed
    Protocol member -- a function that only accepts one narrow type can
    never structurally substitute for one that must accept every `object`.
    `Any` is the correct, intentional width here: `_validate_inputs()`
    below is what actually enforces `isinstance(request, self._request_type)`
    at runtime, not this Protocol -- the Protocol's own job is only to let
    `WriteExecutionCoreV1` call `preparer.prepare(request)` generically
    across capabilities, never to itself narrow or validate `request`'s
    type."""

    @property
    def adapter(self) -> object: ...

    def prepare(self, request: Any) -> PreparedWriteExecutionV1: ...


@dataclass(frozen=True, slots=True)
class _PendingExecution:
    contract_id: str
    executor_intent: dict[str, CanonicalValue]
    provenance: AuthorizationProvenance


@dataclass(frozen=True, slots=True)
class _IdempotencyDerivation:
    target_identity_digest: str
    target_fingerprint_digest: str
    intent_digest: str
    snapshot_digest: str
    idempotency_key: str
    executor_intent: dict[str, CanonicalValue]


class AuthorizedWriteExecution:
    """Opaque process-local reference to one coordinator-created contract.
    Generic -- identical in shape and purpose to
    `AuthorizedAliasDescriptionExecution`."""

    __slots__ = ("_owner_token", "contract_id")

    def __init__(self, *, contract_id: str, owner_token: object) -> None:
        self.contract_id = contract_id
        self._owner_token = owner_token


class WriteExecutionCoreV1:
    """Generic product-specific V2 verification, consume, contract and
    handoff chain -- one instance per capability, each constructed with its
    own `request_type`/`prepared_type`/`preparer`/`contract_id_prefix`/
    `raw_target_fn`, never shared or reused across capabilities."""

    def __init__(
        self,
        *,
        request_type: type,
        prepared_type: type,
        contract_id_prefix: str,
        raw_target_fn: Callable[[object], dict[str, CanonicalValue]],
        preparer: _PreparerProtocol,
        authorities: PinnedAuthoritySet,
        consumption_store: AuthorizationConsumptionStore,
        contract_store: SqliteRecoveryContractStore,
        executor: MutationExecutor,
        encryption_key: KeyRecord,
        nonce_counter: NonceCounter,
        contract_validity: timedelta = timedelta(minutes=5),
    ) -> None:
        if encryption_key.retired or encryption_key.purpose.value != "encryption":
            raise BoundExecutionError(_DENIED)
        if not isinstance(contract_validity, timedelta) or contract_validity <= timedelta(0):
            raise BoundExecutionError(_DENIED)
        if not isinstance(request_type, type) or not isinstance(prepared_type, type):
            raise BoundExecutionError(_DENIED)
        if not isinstance(contract_id_prefix, str) or not contract_id_prefix or not contract_id_prefix.isascii():
            raise BoundExecutionError(_DENIED)
        if not callable(raw_target_fn):
            raise BoundExecutionError(_DENIED)
        self._request_type = request_type
        self._prepared_type = prepared_type
        self._contract_id_prefix = contract_id_prefix
        self._raw_target_fn = raw_target_fn
        self._preparer = preparer
        self._authorities = authorities
        self._consumption_store = consumption_store
        self._store = contract_store
        self._executor = executor
        self._encryption_key = encryption_key
        self._nonce_counter = nonce_counter
        self._contract_validity = contract_validity
        self._owner_token = object()
        self._pending: dict[str, _PendingExecution] = {}

    def authorize_and_create(
        self,
        request: object,
        *,
        authorized_preparation: PreparedWriteExecutionV1,
        authorization: PlanAuthorizationV2,
        requested_plan_digest: str,
        requested_step_id: str,
        required_risk_class: AuthorizationLevel,
        target_capability_posture: CapabilityPosture,
        target_anchor_assurance: AnchorAssurance,
        now: datetime,
        freshness_env: dict[str, str] | None = None,
    ) -> AuthorizedWriteExecution:
        """Run every non-mutating gate, consume once, then create once.
        Identical algorithm and identical gate ordering to
        `AliasDescriptionExecutionCoreV1.authorize_and_create()` -- see
        that method's own docstring for the full `required_risk_class`
        rationale, unchanged here."""

        try:
            self._validate_inputs(
                request=request,
                authorized_preparation=authorized_preparation,
                authorization=authorization,
                requested_plan_digest=requested_plan_digest,
                requested_step_id=requested_step_id,
                required_risk_class=required_risk_class,
                target_capability_posture=target_capability_posture,
                target_anchor_assurance=target_anchor_assurance,
                now=now,
            )
            authorized_digest = compute_execution_intent_digest(authorized_preparation.intent)
            if not verify_plan_authorization_v2_signature(authorization, self._authorities):
                raise BoundExecutionError(_DENIED)
            if not authorization.issued_at <= now < authorization.expires_at:
                raise BoundExecutionError(_DENIED)
            if not plan_authorization_v2_authorizes_execution(
                authorization,
                plan_digest=requested_plan_digest,
                step_id=requested_step_id,
                execution_intent_digest=authorized_digest,
            ):
                raise BoundExecutionError(_DENIED)
            if not plan_authorization_v2_satisfies_required_risk_class(
                authorization, required_risk_class=required_risk_class
            ):
                raise BoundExecutionError(_DENIED)
            if not self._plan_is_fresh(
                target_capability_posture=target_capability_posture,
                target_anchor_assurance=target_anchor_assurance,
                expected_plan_digest=requested_plan_digest,
                env=freshness_env,
            ):
                raise BoundExecutionError(_DENIED)

            fresh = self._preparer.prepare(request)
            fresh_digest = compute_execution_intent_digest(fresh.intent)
            if (
                not hmac.compare_digest(authorized_digest, fresh_digest)
                or fresh.authoritative_a.numeric_locator != authorized_preparation.authoritative_a.numeric_locator
            ):
                raise BoundExecutionError(_DENIED)

            # 2026-09-05 owner-directed retry/idempotency redesign, Slice 2:
            # refuse BEFORE try_consume() if a currently-blocking contract
            # already exists for this exact semantic idempotency identity --
            # never burn a fresh authorization on a collision the caller
            # could have avoided. This is a preflight, not a race guard: the
            # store's own active-idempotency partial unique index at INSERT
            # time (create_authorized(), below) remains the sole authoritative
            # defense against a concurrent attempt racing between this check
            # and that INSERT.
            if self._store.find_by_idempotency_key(self._derive_idempotency(fresh).idempotency_key) is not None:
                raise BoundExecutionError(_DENIED)

            expires_at = min(now + self._contract_validity, authorization.expires_at)
            provenance = AuthorizationProvenance(
                schema_version=AUTHORIZATION_PROVENANCE_SCHEMA_VERSION,
                authorization_id=authorization.authorization_id,
                authority_id=authorization.authority_id,
                plan_authorization_schema_version=authorization.schema_version,
                plan_digest=requested_plan_digest,
                step_id=requested_step_id,
                execution_intent_digest=fresh_digest,
                authorization_issued_at=authorization.issued_at,
                authorization_expires_at=authorization.expires_at,
                appliance_target_digest=fresh.appliance_target_digest,
            )
            material = self._contract_material(fresh, created_at=now, expires_at=expires_at, provenance=provenance)
        except BoundExecutionError:
            raise
        except Exception:
            raise BoundExecutionError(_DENIED) from None

        try:
            consumed = self._consumption_store.try_consume(authorization.authorization_id)
        except Exception:
            raise BoundExecutionError(_DENIED) from None
        if not consumed:
            raise BoundExecutionError(_DENIED)

        try:
            contract, executor_intent = self._create_contract(material)
            self._store.create_authorized(contract)
            prepared_contract = self._store.transition(
                contract.contract_id,
                expected_state=RecoveryState.PREPARING,
                expected_version=0,
                target_state=RecoveryState.PREPARED,
            )
            pending = _PendingExecution(prepared_contract.contract_id, executor_intent, provenance)
            self._pending[prepared_contract.contract_id] = pending
            return AuthorizedWriteExecution(contract_id=prepared_contract.contract_id, owner_token=self._owner_token)
        except Exception:
            raise BoundExecutionError(_DENIED) from None

    def confirm_and_handoff(
        self,
        handle: AuthorizedWriteExecution,
        *,
        confirmation: ConfirmationEvidence,
        now: datetime,
        acceptance_context: AcceptanceExecutionContext | None = None,
    ) -> ExecutionOutcome:
        if (
            not isinstance(handle, AuthorizedWriteExecution)
            or handle._owner_token is not self._owner_token
            or not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != timezone.utc.utcoffset(now)
        ):
            raise BoundExecutionError(_DENIED)
        pending = self._pending.get(handle.contract_id)
        if pending is None:
            raise BoundExecutionError(_DENIED)
        try:
            contract = self._store.load(handle.contract_id)
            if (
                contract.state is not RecoveryState.PREPARED
                or contract.is_confirmed
                or contract.authorization_provenance != pending.provenance
                or not pending.provenance.authorization_issued_at <= now < pending.provenance.authorization_expires_at
                or not confirmation.issued_at <= now < confirmation.expires_at
            ):
                raise BoundExecutionError(_DENIED)
            confirmed = self._store.confirm(
                contract.contract_id,
                evidence=confirmation,
                expected_version=contract.state_version,
            )
            if confirmed.authorization_provenance != pending.provenance:
                raise BoundExecutionError(_DENIED)
        except BoundExecutionError:
            raise
        except Exception:
            raise BoundExecutionError(_DENIED) from None

        del self._pending[handle.contract_id]
        try:
            return self._executor.execute(
                confirmed.contract_id,
                adapter=self._preparer.adapter,  # type: ignore[arg-type]
                intent=dict(pending.executor_intent),
                acceptance_context=acceptance_context,
            )
        except Exception:
            raise BoundExecutionError(_DENIED) from None

    def resume_prepared(
        self,
        contract_id: str,
        *,
        request: object,
        now: datetime,
    ) -> AuthorizedWriteExecution:
        try:
            self._validate_resume_inputs(contract_id=contract_id, request=request, now=now)
            contract = self._store.load(contract_id)
            provenance = contract.authorization_provenance
            if (
                contract.state is not RecoveryState.PREPARED
                or provenance is None
                or not provenance.authorization_issued_at <= now < provenance.authorization_expires_at
                or contract.is_expired(now=now)
            ):
                raise BoundExecutionError(_DENIED)

            fresh = self._preparer.prepare(request)
            if (
                fresh.intent.capability != contract.capability
                or fresh.intent.endpoint_symbol != contract.endpoint_symbol
                or fresh.intent.http_method != contract.http_method
                or fresh.appliance_target_digest != provenance.appliance_target_digest
            ):
                raise BoundExecutionError(_DENIED)

            fresh_execution_intent_digest = compute_execution_intent_digest(fresh.intent)
            if not hmac.compare_digest(fresh_execution_intent_digest, provenance.execution_intent_digest):
                raise BoundExecutionError(_DENIED)
            if fresh.authoritative_a.numeric_locator != contract.lifecycle_locator:
                raise BoundExecutionError(_DENIED)

            context = (fresh.intent.capability.name, fresh.intent.endpoint_symbol, fresh.intent.http_method)
            raw_target = self._raw_target_fn(fresh.authoritative_a)
            executor_intent: dict[str, CanonicalValue] = {
                **fresh.intent.normalized_mutation_intent,
                "raw_target_hint": raw_target,
            }
            target_digest = digest_value(
                DigestPurpose.TARGET_IDENTITY, fresh.intent.resource_target, context=(fresh.intent.capability.name,)
            )
            fingerprint_digest = digest_value(
                DigestPurpose.TARGET_FINGERPRINT, fresh.intent.target_precondition, context=context
            )
            intent_digest = digest_value(DigestPurpose.INTENT, executor_intent, context=context)
            snapshot_digest = digest_value(DigestPurpose.SNAPSHOT, fresh.intent.rollback_snapshot, context=context)

            if (
                not hmac.compare_digest(target_digest, contract.target_identity_digest)
                or not hmac.compare_digest(fingerprint_digest, contract.target_fingerprint)
                or not hmac.compare_digest(intent_digest, contract.intent_digest)
                or not hmac.compare_digest(snapshot_digest, contract.snapshot_digest)
                or fresh.intent.rollback_plan_version != contract.rollback_plan_version
            ):
                raise BoundExecutionError(_DENIED)
        except BoundExecutionError:
            raise
        except Exception:
            raise BoundExecutionError(_DENIED) from None

        pending = _PendingExecution(contract.contract_id, executor_intent, provenance)
        self._pending[contract.contract_id] = pending
        return AuthorizedWriteExecution(contract_id=contract.contract_id, owner_token=self._owner_token)

    def _validate_resume_inputs(self, *, contract_id: object, request: object, now: object) -> None:
        if (
            not isinstance(contract_id, str)
            or not contract_id
            or not isinstance(request, self._request_type)
            or not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != timezone.utc.utcoffset(now)
        ):
            raise BoundExecutionError(_DENIED)

    @staticmethod
    def _plan_is_fresh(
        *,
        target_capability_posture: CapabilityPosture,
        target_anchor_assurance: AnchorAssurance,
        expected_plan_digest: str,
        env: dict[str, str] | None,
    ) -> bool:
        return plan_authorization_is_fresh(
            target_capability_posture=target_capability_posture,
            target_anchor_assurance=target_anchor_assurance,
            expected_plan_digest=expected_plan_digest,
            env=env,
        )

    def _validate_inputs(
        self,
        *,
        request: object,
        authorized_preparation: PreparedWriteExecutionV1,
        authorization: object,
        requested_plan_digest: object,
        requested_step_id: object,
        required_risk_class: object,
        target_capability_posture: object,
        target_anchor_assurance: object,
        now: object,
    ) -> None:
        if (
            not isinstance(request, self._request_type)
            or not isinstance(authorized_preparation, self._prepared_type)
            or not isinstance(authorization, PlanAuthorizationV2)
            or authorization.schema_version != PLAN_AUTHORIZATION_V2_SCHEMA_VERSION
            or not isinstance(requested_plan_digest, str)
            or requested_plan_digest != authorization.plan_digest
            or not isinstance(requested_step_id, str)
            or not requested_step_id
            or not isinstance(required_risk_class, AuthorizationLevel)
            or not isinstance(target_capability_posture, CapabilityPosture)
            or not isinstance(target_anchor_assurance, AnchorAssurance)
            or not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != timezone.utc.utcoffset(now)
        ):
            raise BoundExecutionError(_DENIED)

    @staticmethod
    def _contract_material(
        prepared: PreparedWriteExecutionV1,
        *,
        created_at: datetime,
        expires_at: datetime,
        provenance: AuthorizationProvenance,
    ) -> tuple[PreparedWriteExecutionV1, datetime, datetime, AuthorizationProvenance]:
        if expires_at <= created_at or prepared.appliance_target_digest != provenance.appliance_target_digest:
            raise BoundExecutionError(_DENIED)
        if (
            prepared.intent.normalized_mutation_intent.get("appliance_target_digest")
            != provenance.appliance_target_digest
        ):
            raise BoundExecutionError(_DENIED)
        return prepared, created_at, expires_at, provenance

    def compute_idempotency_key(self, prepared: PreparedWriteExecutionV1) -> str:
        return self._derive_idempotency(prepared).idempotency_key

    def _derive_idempotency(self, prepared: PreparedWriteExecutionV1) -> _IdempotencyDerivation:
        intent = prepared.intent
        state = prepared.authoritative_a
        context = (intent.capability.name, intent.endpoint_symbol, intent.http_method)
        raw_target = self._raw_target_fn(state)
        executor_intent: dict[str, CanonicalValue] = {
            **intent.normalized_mutation_intent,
            "raw_target_hint": raw_target,
        }
        target_digest = digest_value(
            DigestPurpose.TARGET_IDENTITY, intent.resource_target, context=(intent.capability.name,)
        )
        fingerprint_digest = digest_value(DigestPurpose.TARGET_FINGERPRINT, intent.target_precondition, context=context)
        intent_digest = digest_value(DigestPurpose.INTENT, executor_intent, context=context)
        snapshot_digest = digest_value(DigestPurpose.SNAPSHOT, intent.rollback_snapshot, context=context)
        idempotency_key = derive_idempotency_key(
            capability=intent.capability,
            endpoint_symbol=intent.endpoint_symbol,
            http_method=intent.http_method,
            target_identity_digest=target_digest,
            target_fingerprint=fingerprint_digest,
            lifecycle_locator=state.numeric_locator,
            intent_digest=intent_digest,
            snapshot_digest=snapshot_digest,
            rollback_plan_version=intent.rollback_plan_version,
        )
        return _IdempotencyDerivation(
            target_identity_digest=target_digest,
            target_fingerprint_digest=fingerprint_digest,
            intent_digest=intent_digest,
            snapshot_digest=snapshot_digest,
            idempotency_key=idempotency_key,
            executor_intent=executor_intent,
        )

    def _create_contract(
        self, material: tuple[PreparedWriteExecutionV1, datetime, datetime, AuthorizationProvenance]
    ) -> tuple[RecoveryContract, dict[str, CanonicalValue]]:
        prepared, created_at, expires_at, provenance = material
        intent = prepared.intent
        state = prepared.authoritative_a
        contract_id = f"{self._contract_id_prefix}-{uuid.uuid4().hex}"
        operation_id = f"{self._contract_id_prefix}-op-{uuid.uuid4().hex}"
        identity = intent.resource_target
        semantic_intent = intent.normalized_mutation_intent
        snapshot = intent.rollback_snapshot
        derived = self._derive_idempotency(prepared)
        contract = RecoveryContract(
            contract_id=contract_id,
            operation_id=operation_id,
            idempotency_key=derived.idempotency_key,
            capability=intent.capability,
            endpoint_symbol=intent.endpoint_symbol,
            http_method=intent.http_method,
            target_identity_digest=derived.target_identity_digest,
            target_fingerprint=derived.target_fingerprint_digest,
            lifecycle_locator=state.numeric_locator,
            intent_digest=derived.intent_digest,
            snapshot_digest=derived.snapshot_digest,
            rollback_plan_version=intent.rollback_plan_version,
            created_at=created_at,
            expires_at=expires_at,
            state=RecoveryState.PREPARING,
            state_version=0,
            protected_target_identity=self._encrypt(contract_id, ArtifactRole.TARGET_IDENTITY, identity),
            protected_intent=self._encrypt(contract_id, ArtifactRole.INTENT, semantic_intent),
            protected_snapshot=self._encrypt(contract_id, ArtifactRole.SNAPSHOT, snapshot),
            authorization_provenance=provenance,
        )
        return contract, derived.executor_intent

    def _encrypt(self, contract_id: str, role: ArtifactRole, value: CanonicalValue) -> ProtectedArtifact:
        nonce = build_nonce(epoch=self._encryption_key.epoch, counter=self._nonce_counter.next())
        return encrypt_artifact(
            key=self._encryption_key.material,
            key_id=self._encryption_key.key_id,
            contract_id=contract_id,
            role=role,
            plaintext=canonical_json(value),
            nonce=nonce,
        )
