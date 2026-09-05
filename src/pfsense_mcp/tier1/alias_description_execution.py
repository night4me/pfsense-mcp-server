"""Inert W1 authorization-to-contract core for one alias description.

No production bootstrap imports this module.  It composes existing security
owners and ends at one call to ``MutationExecutor.execute``; it registers no
tool, endpoint, policy or capability.

**ADR-036 W0 canonical-gate note**: ``authorize_and_create()``'s own
signature->expiry->plan/step->risk_class->freshness->consume sequence
below is the ONE authorization-gate implementation this codebase's sole
live WRITE capability actually runs -- reachable, via
``tier1_write_bridge.py``/``production_runtime.py``, from a real
(currently non-default) MCP tool. ``tier1/execution_coordinator.py``
composes a similarly-ordered gate sequence but operates on the
superseded V1 ``PlanAuthorization`` schema and has no analog of this
method's fresh-re-preparation/execution-intent-digest/numeric-locator
continuity check -- it is not a semantically equivalent alternative,
is never imported by any production module (mechanically proven,
``tests/tier1/test_execution_coordinator_isolation.py``), and is not
this codebase's canonical gate.
"""

from __future__ import annotations

import hmac
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from pfsense_mcp.security_authorization import PLAN_AUTHORIZATION_V2_SCHEMA_VERSION, PlanAuthorizationV2
from pfsense_mcp.security_authorization_verifier import (
    plan_authorization_v2_authorizes_execution,
    plan_authorization_v2_satisfies_required_risk_class,
    verify_plan_authorization_v2_signature,
)
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.security_plan_freshness import plan_authorization_is_fresh

from .alias_description import (
    AliasDescriptionChangeV1,
    AliasDescriptionPreparerV1,
    AliasStateV1,
    PreparedAliasDescriptionExecutionV1,
)
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
from .prepared_execution_intent import compute_execution_intent_digest

if TYPE_CHECKING:
    # ADR-029: type-checking only -- see write_api_client.py's identical
    # guard for why.
    from .acceptance import AcceptanceExecutionContext
from .state_machine import RecoveryState
from .store import SqliteRecoveryContractStore

_DENIED = "Bound alias-description execution denied."


@dataclass(frozen=True, slots=True)
class _PendingExecution:
    contract_id: str
    executor_intent: dict[str, CanonicalValue]
    provenance: AuthorizationProvenance


@dataclass(frozen=True, slots=True)
class _IdempotencyDerivation:
    """Every digest `_create_contract()` derives from a prepared intent,
    computed in exactly one place (`_derive_idempotency()`) and reused by
    both `_create_contract()` and the read-only `compute_idempotency_key()`
    -- never duplicated a second way."""

    target_identity_digest: str
    target_fingerprint_digest: str
    intent_digest: str
    snapshot_digest: str
    idempotency_key: str
    executor_intent: dict[str, CanonicalValue]


class AuthorizedAliasDescriptionExecution:
    """Opaque process-local reference to one coordinator-created contract."""

    __slots__ = ("_owner_token", "contract_id")

    def __init__(self, *, contract_id: str, owner_token: object) -> None:
        self.contract_id = contract_id
        self._owner_token = owner_token


class AliasDescriptionExecutionCoreV1:
    """Product-specific V2 verification, consume, contract and handoff chain."""

    def __init__(
        self,
        *,
        preparer: AliasDescriptionPreparerV1,
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
        request: AliasDescriptionChangeV1,
        *,
        authorized_preparation: PreparedAliasDescriptionExecutionV1,
        authorization: PlanAuthorizationV2,
        requested_plan_digest: str,
        requested_step_id: str,
        required_risk_class: AuthorizationLevel,
        target_capability_posture: CapabilityPosture,
        target_anchor_assurance: AnchorAssurance,
        now: datetime,
        freshness_env: dict[str, str] | None = None,
    ) -> AuthorizedAliasDescriptionExecution:
        """Run every non-mutating gate, consume once, then create once.

        `required_risk_class` (ADR-036 W0): the exact `AuthorizationLevel`
        the specific requested step actually, invariantly requires --
        caller-derived from `security_plan.py`'s own step catalogue
        (`ALIAS_DESCRIPTION_WRITE_REQUIRED_RISK_CLASS` for the one live
        production capability), never from `authorization`'s own claimed
        `risk_class` -- the same "independently derive, never trust the
        artifact's own self-report" discipline `requested_plan_digest`/
        `requested_step_id` already establish for plan/step identity.
        `authorization.risk_class` must be at least this rank or the
        authorization is refused before consumption, exactly like every
        other pre-consumption gate below."""

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
            # and that INSERT. Parity with write_execution_core.py's
            # WriteExecutionCoreV1.authorize_and_create().
            if self._store.find_by_idempotency_key(self._derive_idempotency(fresh).idempotency_key) is not None:
                raise BoundExecutionError(_DENIED)

            # Feasibility is computed before consumption; nonce allocation,
            # encryption and persistence deliberately occur only afterwards.
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

        # Everything below is intentionally burn-on-failure.  No exception
        # restores consumption and no retry right is returned.
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
            return AuthorizedAliasDescriptionExecution(
                contract_id=prepared_contract.contract_id,
                owner_token=self._owner_token,
            )
        except Exception:
            raise BoundExecutionError(_DENIED) from None

    def confirm_and_handoff(
        self,
        handle: AuthorizedAliasDescriptionExecution,
        *,
        confirmation: ConfirmationEvidence,
        now: datetime,
        acceptance_context: AcceptanceExecutionContext | None = None,
    ) -> ExecutionOutcome:
        """Confirm the exact created contract and hand it to the executor
        once. `acceptance_context` (ADR-029): `None` for every normal
        caller, threaded through to MutationExecutor.execute() unchanged --
        every check above (owner token, contract state, provenance match,
        authorization/confirmation freshness, atomic confirm()) is
        identical either way and runs before this parameter is ever
        consulted."""

        if (
            not isinstance(handle, AuthorizedAliasDescriptionExecution)
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

        # Remove before handoff: an exception at or after this boundary never
        # creates a second handoff right.  MutationExecutor owns acquisition,
        # sends, retry suppression and every subsequent transition.
        del self._pending[handle.contract_id]
        try:
            return self._executor.execute(
                confirmed.contract_id,
                adapter=self._preparer.adapter,
                intent=dict(pending.executor_intent),
                acceptance_context=acceptance_context,
            )
        except Exception:
            raise BoundExecutionError(_DENIED) from None

    def resume_prepared(
        self,
        contract_id: str,
        *,
        request: AliasDescriptionChangeV1,
        now: datetime,
    ) -> AuthorizedAliasDescriptionExecution:
        """Reconstruct a fresh, process-local handle for an already-durable
        `PREPARED` execution, so `confirm_and_handoff()` can complete it
        after the original `authorize_and_create()` call's in-process
        `self._pending` entry is gone -- a fresh `AliasDescriptionExecutionCoreV1`
        instance (this codebase's own `build_production_runtime()` convention
        constructs entirely fresh objects "across calls", not only across
        process restarts), a genuine restart, or simply a second, later call
        once a human operator has had time to review and sign a confirmation.

        Trusts nothing from the vanished prior process. Every value used to
        reconstruct the executor's required intent is re-derived from (a) a
        FRESH authoritative preparation of `request` via the existing,
        unchanged preparer/adapter, and (b) the durable, already-integrity-
        and-reservation-verified `RecoveryContract` loaded via
        `self._store.load()` (unchanged, unmodified). The reconstruction is
        accepted only if the resulting digests match the contract's own
        already-authenticated fields exactly, mirroring the exact
        derivation `_create_contract()` performed at authorization time --
        never decrypted, inferred, or taken on faith from the caller. A
        mismatch (drifted target, wrong request, tampered contract, wrong
        semantic unit) is refused identically to every other fail-closed
        gate in this class -- one uniform `BoundExecutionError`, no detail
        leaked about which check failed.

        Never consumes an authorization and never creates a contract --
        both remain `authorize_and_create()`'s exclusive responsibility,
        untouched here. A resumed handle is subject to every one of
        `confirm_and_handoff()`'s existing checks (state, confirmation,
        provenance, validity window) exactly as if it had come from
        `authorize_and_create()` in the same call -- this method performs
        no confirmation-phase work of its own."""

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
            raw_target = self._raw_target(fresh.authoritative_a)
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
        return AuthorizedAliasDescriptionExecution(contract_id=contract.contract_id, owner_token=self._owner_token)

    @staticmethod
    def _validate_resume_inputs(*, contract_id: object, request: object, now: object) -> None:
        if (
            not isinstance(contract_id, str)
            or not contract_id
            or not isinstance(request, AliasDescriptionChangeV1)
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

    @staticmethod
    def _validate_inputs(
        *,
        request: object,
        authorized_preparation: object,
        authorization: object,
        requested_plan_digest: object,
        requested_step_id: object,
        required_risk_class: object,
        target_capability_posture: object,
        target_anchor_assurance: object,
        now: object,
    ) -> None:
        if (
            not isinstance(request, AliasDescriptionChangeV1)
            or not isinstance(authorized_preparation, PreparedAliasDescriptionExecutionV1)
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
        prepared: PreparedAliasDescriptionExecutionV1,
        *,
        created_at: datetime,
        expires_at: datetime,
        provenance: AuthorizationProvenance,
    ) -> tuple[PreparedAliasDescriptionExecutionV1, datetime, datetime, AuthorizationProvenance]:
        if expires_at <= created_at or prepared.appliance_target_digest != provenance.appliance_target_digest:
            raise BoundExecutionError(_DENIED)
        if (
            prepared.intent.normalized_mutation_intent.get("appliance_target_digest")
            != provenance.appliance_target_digest
        ):
            raise BoundExecutionError(_DENIED)
        return prepared, created_at, expires_at, provenance

    def compute_idempotency_key(self, prepared: PreparedAliasDescriptionExecutionV1) -> str:
        """Read-only: the exact idempotency key `_create_contract()` would
        derive for this prepared intent, without creating anything --
        `_create_contract()` itself calls the same shared derivation
        (`_derive_idempotency()`) this delegates to, so the two can never
        drift apart. Exposed so a composition layer (W3 Slice 3) can
        discover whether a matching contract already exists via the
        store's own durable state (ADR-028's re-invocation/deduplication
        requirement) before deciding whether to attempt
        `authorize_and_create()` -- never a second identity concept."""

        return self._derive_idempotency(prepared).idempotency_key

    @staticmethod
    def _derive_idempotency(prepared: PreparedAliasDescriptionExecutionV1) -> _IdempotencyDerivation:
        intent = prepared.intent
        state = prepared.authoritative_a
        context = (intent.capability.name, intent.endpoint_symbol, intent.http_method)
        raw_target = AliasDescriptionExecutionCoreV1._raw_target(state)
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
        self,
        material: tuple[PreparedAliasDescriptionExecutionV1, datetime, datetime, AuthorizationProvenance],
    ) -> tuple[RecoveryContract, dict[str, CanonicalValue]]:
        prepared, created_at, expires_at, provenance = material
        intent = prepared.intent
        state = prepared.authoritative_a
        contract_id = f"aliasdescr-{uuid.uuid4().hex}"
        operation_id = f"aliasdescr-op-{uuid.uuid4().hex}"
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

    @staticmethod
    def _raw_target(state: AliasStateV1) -> dict[str, CanonicalValue]:
        return {
            "name": state.name,
            "id": state.numeric_locator,
            "type": state.alias_type,
            "descr": state.descr,
            "address": list(state.address),
            "detail": list(state.detail),
        }
