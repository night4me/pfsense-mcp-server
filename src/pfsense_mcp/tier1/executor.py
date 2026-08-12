"""The sealed Tier 1 mutation executor.

Not constructed by production. The one component authorized to bridge
Tier 1's authorization/state machinery to `WriteApiClient`'s
`send_for_tier1()` chokepoint. A capability adapter can never cause a
network call except through exactly one executor-owned send: it receives
no transport, no write client, and no way to choose a path or method at
runtime -- it computes pure projections the executor chooses to trust for
exactly one call. See docs/tier1/specs/sealed_executor.md for the full
specification this module implements, and docs/adr/ADR-014.
"""

from __future__ import annotations

import hmac
import json
import re
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.errors import WriteNotAllowedError
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.write_api_client import TransportConnectionError, TransportTimeoutError, WriteApiClient

from .anti_rollback import AntiRollbackAnchor
from .canonical import CanonicalValue, DigestPurpose, digest_value, validate_canonical_value
from .contract import ProtectedArtifact, RecoveryContract
from .crypto import ArtifactRole, decrypt_artifact
from .errors import ContractConflictError, ContractValidationError
from .faults import EffectKnowledge, MutationBoundary, classify_fault
from .policy import MutationPolicy
from .state_machine import RecoveryState
from .store import SqliteRecoveryContractStore

_HEX_64 = re.compile(r"[0-9a-f]{64}")


class CapabilityAdapter(Protocol):
    """See docs/tier1/specs/capability_adapter_contract.md for full
    implementation guidance. Every method here is pure with one sanctioned
    exception (`read_target`, read-only, through the executor-supplied
    client) -- no method may hold state, choose a transport, or claim
    verification."""

    endpoint_symbol: str
    http_method: str
    capability: Capability

    def read_target(self, read_client: PfSenseClient, natural_identity: CanonicalValue) -> object:
        """The one sanctioned adapter I/O: read-only, through the
        executor-supplied read_client (never a client the adapter
        constructs or imports itself -- adapter modules are forbidden
        from importing pfsense_client/write_api_client/transport at all,
        enforced by tests/tier1/test_isolation.py and its future
        tier1/adapters/ extension). `natural_identity` is the executor's
        already-verified digest input (matched against the contract's
        target_identity_digest before this is ever called) -- adapters
        are stateless, possibly module-level singletons, so this is the
        only way one knows which target to locate. Locates and returns
        the single raw target object every other method below operates
        on. Must raise on zero or multiple matches -- the executor treats
        any exception here as a pre-send refusal."""
        ...

    def natural_identity(self, raw_target: object) -> CanonicalValue: ...
    def fingerprint(self, raw_target: object) -> CanonicalValue: ...
    def transport_locator(self, raw_target: object) -> int: ...
    def build_request(self, intent: object, target: ResolvedTransportTarget) -> BaseModel: ...
    def parse_response(self, raw_response: object) -> object: ...
    def is_semantically_verified(self, pre: object, post: object, intent: object) -> bool: ...
    def build_rollback_request(self, pre: object, target: ResolvedTransportTarget) -> BaseModel: ...
    def is_rollback_verified(self, pre: object, post_rollback: object) -> bool: ...


@dataclass(frozen=True)
class ResolvedTransportTarget:
    """Fresh executor-owned transport projection for one exact semantic target."""

    numeric_locator: int
    target_identity_digest: str

    def __post_init__(self) -> None:
        if type(self.numeric_locator) is not int or not 0 <= self.numeric_locator <= 2_147_483_647:
            raise ContractValidationError("Resolved transport locator is invalid.")
        if not isinstance(self.target_identity_digest, str) or not _HEX_64.fullmatch(self.target_identity_digest):
            raise ContractValidationError("Resolved transport target identity is invalid.")


@dataclass(frozen=True)
class ExecutionOutcome:
    contract_id: str
    state: RecoveryState
    detail: str


@dataclass(frozen=True)
class RollbackOutcome:
    contract_id: str
    state: RecoveryState
    detail: str


@dataclass(frozen=True)
class AuthoritativeReconciliationObservation:
    """Fresh executor-validated target evidence for one unresolved operation.

    This is deliberately digest/locator-only: raw target state, clients,
    adapters, requests and transport projections never cross the executor
    boundary.
    """

    contract_id: str
    operation_id: str
    state_version: int
    uncertainty_origin: RecoveryState
    target_fingerprint: str
    lifecycle_locator: int


class MutationExecutor:
    """Owns every I/O operation and every security-relevant decision
    (docs/tier1/specs/sealed_executor.md's "Executor responsibilities").
    Constructed once, held for the process lifetime -- exactly one
    instance per process (no concurrent multi-executor operation, per
    that spec's Non-goals)."""

    def __init__(
        self,
        *,
        store: SqliteRecoveryContractStore,
        write_client: WriteApiClient,
        read_client: PfSenseClient,
        policy: MutationPolicy,
        anti_rollback_anchor: AntiRollbackAnchor | None,
        encryption_key: bytes,
    ) -> None:
        self._store = store
        self._write_client = write_client
        self._read_client = read_client
        self._policy = policy
        self._anti_rollback_anchor = anti_rollback_anchor
        self._encryption_key = encryption_key
        # A newly-constructed executor never serves a call against an
        # unreconciled store (sealed_executor.md Lifecycle step 4).
        self._store.reconcile_interrupted()

    def observe_reconciliation_target(
        self, contract_id: str, *, adapter: CapabilityAdapter
    ) -> AuthoritativeReconciliationObservation:
        """Read and validate one unresolved target without changing state.

        The method owns the same semantic-identity, fingerprint and lifecycle-
        locator checks as execution. It neither infers an outcome nor invokes
        the write client, store transitions, or reconciliation resolution.
        """

        contract = self._store.load(contract_id)
        if contract.state is not RecoveryState.RECONCILIATION:
            raise ContractConflictError("Recovery Contract is not in RECONCILIATION.")
        if (
            adapter.capability is not contract.capability
            or adapter.endpoint_symbol != contract.endpoint_symbol
            or adapter.http_method != contract.http_method
        ):
            raise ContractValidationError("Reconciliation adapter does not match the protected contract.")

        events = self._store.audit_events(contract.contract_id)
        if not events:
            raise ContractValidationError("Reconciliation history is missing.")
        latest = events[-1]
        try:
            origin = RecoveryState(latest["previous_state"])
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError("Reconciliation history is malformed.") from None
        if (
            latest.get("current_state") != RecoveryState.RECONCILIATION.value
            or latest.get("state_version") != contract.state_version
            or origin not in {RecoveryState.EXECUTING, RecoveryState.ROLLING_BACK}
        ):
            raise ContractValidationError("Reconciliation history does not match the protected contract.")

        try:
            target_identity = self._decrypt(contract, contract.protected_target_identity, ArtifactRole.TARGET_IDENTITY)
            raw_target = adapter.read_target(self._read_client, target_identity)
            resolved_target = self._resolve_transport_target(contract, adapter, raw_target)
            target_fingerprint = self._fingerprint_digest(contract, adapter.fingerprint(raw_target))
        except Exception:
            raise ContractValidationError("Authoritative reconciliation target observation failed.") from None

        return AuthoritativeReconciliationObservation(
            contract_id=contract.contract_id,
            operation_id=contract.operation_id,
            state_version=contract.state_version,
            uncertainty_origin=origin,
            target_fingerprint=target_fingerprint,
            lifecycle_locator=resolved_target.numeric_locator,
        )

    # -- execute ------------------------------------------------------

    def execute(
        self, contract_id: str, *, adapter: CapabilityAdapter, intent: dict[str, CanonicalValue]
    ) -> ExecutionOutcome:
        contract = self._store.load(contract_id)
        if contract.state != RecoveryState.PREPARED:
            raise ContractConflictError("Recovery Contract is not PREPARED.")
        if not contract.is_confirmed or contract.is_expired():
            raise ContractConflictError("Recovery Contract is unconfirmed or expired.")

        self._policy.authorize(
            capability=adapter.capability, endpoint_symbol=adapter.endpoint_symbol, http_method=adapter.http_method
        )

        # intent is a canonical (JSON-shaped) value -- it is digested
        # whole via normalized_intent=intent below, so it cannot be an
        # arbitrary object (canonical.py only accepts None/bool/int/str/
        # list/dict). Its "raw_target_hint" entry carries what the caller
        # believes still describes the target (sealed_executor.md
        # Verification flow): the executor never trusts its content, only
        # its digest -- the authoritative re-read below
        # (`adapter.read_target`) is what actually establishes pre/post
        # state.
        target_identity = adapter.natural_identity(intent["raw_target_hint"])
        target_precondition = adapter.fingerprint(intent["raw_target_hint"])
        contract.verify_bindings(
            capability=adapter.capability,
            endpoint_symbol=adapter.endpoint_symbol,
            http_method=adapter.http_method,
            target_identity=target_identity,
            target_precondition=target_precondition,
            normalized_intent=intent,
        )

        executing = self._store.transition(
            contract_id,
            expected_state=RecoveryState.PREPARED,
            expected_version=contract.state_version,
            target_state=RecoveryState.EXECUTING,
        )

        try:
            pre = adapter.read_target(self._read_client, target_identity)
        except Exception as exc:
            return self._finish_execute(
                executing, RecoveryState.FAILED, f"pre-send target read failed ({type(exc).__name__})"
            )

        try:
            pre_fingerprint = self._fingerprint_digest(executing, adapter.fingerprint(pre))
        except Exception:
            return self._finish_execute(executing, RecoveryState.FAILED, "pre-send target validation failed")
        if pre_fingerprint != executing.target_fingerprint:
            return self._finish_execute(executing, RecoveryState.FAILED, "target fingerprint drift before send")

        try:
            transport_target = self._resolve_transport_target(executing, adapter, pre)
        except Exception:
            return self._finish_execute(
                executing, RecoveryState.FAILED, "target incarnation continuity unproven before send"
            )

        try:
            plaintext_intent = self._decrypt(executing, executing.protected_intent, ArtifactRole.INTENT)
            request = adapter.build_request(plaintext_intent, transport_target)
        except Exception as exc:
            return self._finish_execute(
                executing, RecoveryState.FAILED, f"request construction failed ({type(exc).__name__})"
            )

        if not isinstance(request, BaseModel):
            return self._finish_execute(executing, RecoveryState.FAILED, "adapter did not return a typed request")

        boundary, knowledge, raw_response = self._send(executing, request)

        if knowledge != EffectKnowledge.VERIFIED_SUCCESS:
            decision = classify_fault(boundary, knowledge)
            detail = (
                "ambiguous outcome during send"
                if knowledge == EffectKnowledge.AMBIGUOUS
                else "mutation refused before any effect"
            )
            return self._finish_execute(executing, decision.target_state, detail)

        try:
            post = adapter.read_target(self._read_client, target_identity)
            post_transport_target = self._resolve_transport_target(executing, adapter, post)
            outcome = adapter.parse_response(raw_response)
            verified = adapter.is_semantically_verified(pre, post, plaintext_intent)
            verified_target_fingerprint = (
                self._fingerprint_digest(executing, adapter.fingerprint(post)) if verified else None
            )
        except Exception as exc:
            return self._finish_execute(
                executing, RecoveryState.RECONCILIATION, f"post-send verification failed ({type(exc).__name__})"
            )

        if verified_target_fingerprint is not None:
            updated = self._store.mark_execution_verified(
                executing.contract_id,
                expected_version=executing.state_version,
                verified_target_fingerprint=verified_target_fingerprint,
                verified_lifecycle_locator=post_transport_target.numeric_locator,
            )
            return ExecutionOutcome(
                contract_id=executing.contract_id,
                state=updated.state,
                detail=f"parsed response: {outcome!r}",
            )

        decision = classify_fault(MutationBoundary.AFTER_SEND, EffectKnowledge.VERIFIED_FAILURE)
        return self._finish_execute(executing, decision.target_state, "response received but not semantically verified")

    def _finish_execute(self, contract: RecoveryContract, target_state: RecoveryState, detail: str) -> ExecutionOutcome:
        updated = self._store.transition(
            contract.contract_id,
            expected_state=RecoveryState.EXECUTING,
            expected_version=contract.state_version,
            target_state=target_state,
        )
        return ExecutionOutcome(contract_id=contract.contract_id, state=updated.state, detail=detail)

    # -- rollback -------------------------------------------------------

    def rollback(self, contract_id: str, *, adapter: CapabilityAdapter) -> RollbackOutcome:
        contract = self._store.load(contract_id)
        if contract.state != RecoveryState.VERIFIED:
            raise ContractConflictError("Recovery Contract is not VERIFIED.")
        if contract.verified_target_fingerprint is None:
            raise ContractConflictError("Recovery Contract has no verified post-forward fingerprint.")

        rolling_back = self._store.transition(
            contract_id,
            expected_state=RecoveryState.VERIFIED,
            expected_version=contract.state_version,
            target_state=RecoveryState.ROLLING_BACK,
        )

        try:
            # rollback() takes no intent argument, so, unlike execute(),
            # the natural_identity needed to parameterize a stateless
            # adapter's read_target() can only come from the contract's
            # own protected artifact, not a caller-supplied hint.
            target_identity = self._decrypt(
                rolling_back, rolling_back.protected_target_identity, ArtifactRole.TARGET_IDENTITY
            )
            pre = adapter.read_target(self._read_client, target_identity)
        except Exception as exc:
            return self._finish_rollback(
                rolling_back,
                RecoveryState.ROLLBACK_FAILED,
                f"pre-rollback target read failed ({type(exc).__name__})",
            )

        try:
            pre_fingerprint = self._fingerprint_digest(rolling_back, adapter.fingerprint(pre))
        except Exception:
            return self._finish_rollback(
                rolling_back, RecoveryState.ROLLBACK_FAILED, "pre-rollback target validation failed"
            )
        if pre_fingerprint != rolling_back.verified_target_fingerprint:
            # An unrelated change since VERIFIED is a conflict, never a
            # forced overwrite (sealed_executor.md Rollback flow).
            return self._finish_rollback(rolling_back, RecoveryState.ROLLBACK_FAILED, "unrelated change detected")

        try:
            transport_target = self._resolve_transport_target(rolling_back, adapter, pre)
        except Exception:
            return self._finish_rollback(
                rolling_back,
                RecoveryState.ROLLBACK_FAILED,
                "target incarnation continuity unproven before rollback",
            )

        try:
            plaintext_snapshot = self._decrypt(rolling_back, rolling_back.protected_snapshot, ArtifactRole.SNAPSHOT)
            request = adapter.build_rollback_request(plaintext_snapshot, transport_target)
        except Exception as exc:
            return self._finish_rollback(
                rolling_back,
                RecoveryState.ROLLBACK_FAILED,
                f"rollback request construction failed ({type(exc).__name__})",
            )

        if not isinstance(request, BaseModel):
            return self._finish_rollback(
                rolling_back, RecoveryState.ROLLBACK_FAILED, "adapter did not return a typed rollback request"
            )

        # _send()'s own boundary (BEFORE_SEND/AFTER_SEND) is intentionally
        # discarded here: a rollback attempt is definitionally
        # DURING_ROLLBACK regardless of which side of the network call a
        # fault occurred on, so that fixed, more specific boundary is what
        # classify_fault() needs, not the generic one _send() returns.
        # raw_response is unused here (unlike execute()'s equivalent call)
        # because rollback verification re-reads the target and compares
        # snapshots (below); it does not parse the mutation response body.
        _boundary, knowledge, _raw_response = self._send(rolling_back, request)

        if knowledge != EffectKnowledge.VERIFIED_SUCCESS:
            decision = classify_fault(MutationBoundary.DURING_ROLLBACK, knowledge)
            detail = (
                "ambiguous outcome during rollback send"
                if knowledge == EffectKnowledge.AMBIGUOUS
                else "rollback refused before any effect"
            )
            return self._finish_rollback(rolling_back, decision.target_state, detail)

        try:
            post_rollback = adapter.read_target(self._read_client, target_identity)
            post_rollback_target = self._resolve_transport_target(rolling_back, adapter, post_rollback)
            verified = adapter.is_rollback_verified(plaintext_snapshot, post_rollback)
        except Exception as exc:
            return self._finish_rollback(
                rolling_back,
                RecoveryState.RECONCILIATION,
                f"post-rollback verification failed ({type(exc).__name__})",
            )

        if verified:
            updated = self._store.mark_rollback_verified(
                rolling_back.contract_id,
                expected_version=rolling_back.state_version,
                verified_lifecycle_locator=post_rollback_target.numeric_locator,
            )
            return RollbackOutcome(
                contract_id=rolling_back.contract_id,
                state=updated.state,
                detail="rollback verified",
            )
        decision = classify_fault(MutationBoundary.DURING_ROLLBACK, EffectKnowledge.VERIFIED_FAILURE)
        return self._finish_rollback(
            rolling_back, decision.target_state, "rollback response received but not semantically verified"
        )

    def _finish_rollback(self, contract: RecoveryContract, target_state: RecoveryState, detail: str) -> RollbackOutcome:
        updated = self._store.transition(
            contract.contract_id,
            expected_state=RecoveryState.ROLLING_BACK,
            expected_version=contract.state_version,
            target_state=target_state,
        )
        return RollbackOutcome(contract_id=contract.contract_id, state=updated.state, detail=detail)

    # -- shared helpers ---------------------------------------------------

    def _fingerprint_digest(self, contract: RecoveryContract, raw_fingerprint: CanonicalValue) -> str:
        """Recompute the same purpose/context-bound digest verify_bindings()
        used when the contract was created (contract.py), so a raw
        CanonicalValue from the adapter can be compared against the
        digest-only target_fingerprint stored on the contract."""

        context = (contract.capability.name, contract.endpoint_symbol, contract.http_method)
        return digest_value(DigestPurpose.TARGET_FINGERPRINT, raw_fingerprint, context=context)

    def _resolve_transport_target(
        self, contract: RecoveryContract, adapter: CapabilityAdapter, raw_target: object
    ) -> ResolvedTransportTarget:
        identity = adapter.natural_identity(raw_target)
        identity_digest = digest_value(DigestPurpose.TARGET_IDENTITY, identity, context=(contract.capability.name,))
        if not hmac.compare_digest(identity_digest, contract.target_identity_digest):
            raise ContractValidationError("Resolved transport target does not match the protected semantic target.")
        locator = adapter.transport_locator(raw_target)
        if locator != contract.lifecycle_locator:
            raise ContractValidationError("Target incarnation continuity cannot be proven.")
        return ResolvedTransportTarget(numeric_locator=locator, target_identity_digest=identity_digest)

    def _decrypt(self, contract: RecoveryContract, artifact: object, role: ArtifactRole) -> CanonicalValue:
        # Not an `assert`: assertions are stripped under -O, and this
        # guards a real invariant (RecoveryContract's protected_* fields
        # are typed ProtectedArtifact but not runtime-validated as such
        # by __post_init__), not just narrowing an already-proven type.
        if not isinstance(artifact, ProtectedArtifact):
            raise ContractValidationError("Recovery Contract protected artifact has an unexpected type.")
        plaintext_bytes = decrypt_artifact(
            key=self._encryption_key, artifact=artifact, contract_id=contract.contract_id, role=role
        )
        return validate_canonical_value(json.loads(plaintext_bytes))

    def _send(
        self, contract: RecoveryContract, request: BaseModel
    ) -> tuple[MutationBoundary, EffectKnowledge, object | None]:
        """Exactly one call to WriteApiClient.send_for_tier1() per
        invocation (sealed_executor.md I5). Classifies what actually
        happened -- never assumes success, never retries."""

        body = request.model_dump_json().encode("utf-8")
        try:
            response = self._write_client.send_for_tier1(
                endpoint_symbol=contract.endpoint_symbol, http_method=contract.http_method, body=body
            )
        except WriteNotAllowedError:
            # Refused before any network call -- zero effect, provably.
            return MutationBoundary.BEFORE_SEND, EffectKnowledge.PROVEN_NONE, None
        except TransportConnectionError:
            # Connection never established -- zero effect, provably.
            return MutationBoundary.BEFORE_SEND, EffectKnowledge.PROVEN_NONE, None
        except TransportTimeoutError:
            # The request may have reached pfSense; we cannot prove it
            # did not act on it. Never assume success or failure.
            return MutationBoundary.AFTER_SEND, EffectKnowledge.AMBIGUOUS, None
        except Exception:
            # Any other unexpected failure: never assume PROVEN_NONE
            # unless we are certain nothing was sent.
            return MutationBoundary.AFTER_SEND, EffectKnowledge.AMBIGUOUS, None

        if 200 <= response.status_code < 300:
            return MutationBoundary.AFTER_SEND, EffectKnowledge.VERIFIED_SUCCESS, response
        if 400 <= response.status_code < 500:
            # A client-error status is pfSense clearly rejecting the
            # request without processing it -- confidently no effect.
            return MutationBoundary.AFTER_SEND, EffectKnowledge.VERIFIED_FAILURE, response
        # 3xx (unexpected for a PATCH-shaped mutation) and 5xx (server
        # error -- pfSense may have partially processed the request
        # before failing) are not confidently "no effect": never assume
        # failure any more than success here.
        return MutationBoundary.AFTER_SEND, EffectKnowledge.AMBIGUOUS, response
