"""ADR-037 Shape-A generalized acceptance orchestration.

Generalizes `production_runtime.ProductionAliasDescriptionRuntime.
request_alias_description_change()`'s idempotent five-state product
operation (ADR-028) to any capability in `shape_a_registry.
SHAPE_A_REGISTRATIONS` -- the exact same algorithm and gate ordering,
parameterized by `capability_symbol` instead of hardcoded to the alias
capability. `ProductionAliasDescriptionRuntime` itself is completely
unmodified by this module.

What is reused unchanged (capability-independent security invariants,
never duplicated): `WriteExecutionCoreV1.authorize_and_create`/
`confirm_and_handoff`/`resume_prepared`/`compute_idempotency_key` (all
already capability-agnostic -- see `write_batch1_production_runtime.py`)
and the SAME shared `security_plan.generate_security_posture_plan()` step
(`MILESTONE_9_WRITE_STEP_ID`/`_TARGET_CAPABILITY_POSTURE`/
`_TARGET_ANCHOR_ASSURANCE` -- these name a single environment-wide
"write_protected + hardware witness" gate, not an alias-specific concept;
every capability in this codebase that requires `write_protected` shares
it, exactly as `security_plan.py`'s own module-level constants already
document).

`ProductOutcome`/`ProductOutcomeState`/`_project_recovery_state()` are
DUPLICATED here, deliberately, rather than imported from
`production_runtime.py`: `tests/tier1/test_production_runtime.py::
test_no_production_module_imports_production_runtime` enforces a hard,
unconditional (no-allow-list) invariant that NOTHING in `src/pfsense_mcp`
ever imports that module -- reusing it here would weaken an existing
security-isolation invariant rather than respect it. This is pure,
generic state-projection logic (an enum, a frozen dataclass, one
five-branch mapping function) with no cryptographic or policy decision
content -- duplicating it is the correct call under this pass's own "do
not duplicate cryptographic or policy decision logic" instruction, which
this is not.

What is new here (capability-specific orchestration, not security
decision-making): looking up a `ShapeARegistration` for `capability_symbol`
(refusing fail-closed if unregistered -- there is no path from here to any
`WriteEndpoints` entry that is not one of the five keys in
`shape_a_registry.SHAPE_A_REGISTRATIONS`), and deriving four
capability-namespaced artifact paths from one base directory so N
capabilities' artifacts can be in flight simultaneously without collision
(`shape_a_registry.py`'s own capability_symbol values are the namespace
token -- fixed strings from a finite dict, never caller input).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import (
    MILESTONE_9_WRITE_STEP_ID,
    MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
    MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
    AuthorizationLevel,
)

from .errors import ArtifactExchangeError, BoundExecutionError
from .shape_a_artifact_exchange import (
    load_shape_a_authorization_preview,  # noqa: F401  (re-exported for callers/tests)
    load_shape_a_pending_confirmation_request,  # noqa: F401
    load_signed_confirmation_evidence,
    load_signed_plan_authorization_v2,
    pending_confirmation_request_from_contract,
    preview_from_preparation,
    shape_a_authorization_preview_to_bytes,
    shape_a_pending_confirmation_request_to_bytes,
    write_secure_new,
)
from .shape_a_registry import SHAPE_A_REGISTRATIONS, ShapeARegistration, is_registered_capability
from .state_machine import RecoveryState

if TYPE_CHECKING:
    from .acceptance import AcceptanceExecutionContext
    from .write_batch1_production_runtime import ProductionWriteBatch1Runtime

__all__ = [
    "ProductOutcome",
    "ProductOutcomeState",
    "ShapeAAcceptanceOrchestrator",
    "ShapeAArtifactPaths",
    "UnregisteredShapeACapabilityError",
    "artifact_paths_for",
]


class ProductOutcomeState(str, Enum):
    """Byte-for-byte the same five ADR-028 product-facing states as
    `production_runtime.ProductOutcomeState` -- duplicated, not imported,
    per this module's own docstring (`test_no_production_module_imports_
    production_runtime`'s hard, no-exceptions invariant)."""

    REQUESTED = "requested"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    VERIFIED = "verified"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    REFUSED = "refused"


@dataclass(frozen=True)
class ProductOutcome:
    state: ProductOutcomeState
    contract_id: str | None = None


def _project_recovery_state(state: RecoveryState) -> ProductOutcomeState:
    if state is RecoveryState.VERIFIED:
        return ProductOutcomeState.VERIFIED
    if state is RecoveryState.RECONCILIATION:
        return ProductOutcomeState.RECONCILIATION_REQUIRED
    return ProductOutcomeState.REFUSED


class UnregisteredShapeACapabilityError(ArtifactExchangeError):
    """Raised whenever a caller names a `capability_symbol` that is not one
    of `shape_a_registry.SHAPE_A_REGISTRATIONS`'s finite keys -- never
    silently ignored, never dispatched to a best-guess default."""


@dataclass(frozen=True, slots=True)
class ShapeAArtifactPaths:
    authorization_preview_file: Path
    authorization_inbox_file: Path
    confirmation_pending_file: Path
    confirmation_signed_file: Path


def artifact_paths_for(base_directory: Path, capability_symbol: str) -> ShapeAArtifactPaths:
    """Four fixed, capability-namespaced paths under `base_directory /
    capability_symbol/` -- never a directory scan, never a wildcard, never
    a caller-suppliable file name; `capability_symbol` must already be one
    of the finite registered keys (checked by the caller,
    `ShapeAAcceptanceOrchestrator.__init__`, before this is ever called
    with an untrusted value)."""

    root = base_directory / capability_symbol
    return ShapeAArtifactPaths(
        authorization_preview_file=root / "authorization-preview.json",
        authorization_inbox_file=root / "authorization-inbox.json",
        confirmation_pending_file=root / "confirmation-pending.json",
        confirmation_signed_file=root / "confirmation-signed.json",
    )


class ShapeAAcceptanceOrchestrator:
    """One instance drives exactly one statically registered capability.
    Constructing an instance for an unregistered `capability_symbol`
    raises `UnregisteredShapeACapabilityError` immediately -- there is no
    lazy/deferred registration check, and no code path in this class ever
    accepts a capability_symbol from the request being processed instead
    of from its own constructor argument."""

    __slots__ = (
        "_artifact_integrity_key",
        "_confirmation_authority_id",
        "_core",
        "_paths",
        "_preparer",
        "_registration",
        "_store",
    )

    def __init__(
        self,
        *,
        capability_symbol: str,
        runtime: "ProductionWriteBatch1Runtime",
        artifact_base_directory: Path,
        confirmation_authority_id: str,
        artifact_integrity_key: bytes,
    ) -> None:
        if not is_registered_capability(capability_symbol):
            raise UnregisteredShapeACapabilityError(f"{capability_symbol!r} is not a registered Shape-A capability.")
        registration: ShapeARegistration = SHAPE_A_REGISTRATIONS[capability_symbol]
        self._registration = registration
        self._core = registration.core(runtime)
        self._preparer = registration.preparer(runtime)
        #: The same shared store `runtime.contract_store` exposes directly
        #: -- mirrors `ProductionAliasDescriptionRuntime` holding its own
        #: `_store` reference rather than reaching into the execution
        #: core's private internals for `find_by_idempotency_key()`/`load()`.
        self._store = runtime.contract_store
        self._paths = artifact_paths_for(artifact_base_directory, capability_symbol)
        self._confirmation_authority_id = confirmation_authority_id
        self._artifact_integrity_key = artifact_integrity_key
        #: Idempotent, one-time directory provisioning for this
        #: capability's own namespaced artifact subdirectory -- mirrors
        #: the alias path's own pre-provisioned fixed artifact directory
        #: (Step 2 provisioning, `tier1-lab.env`'s own comment: "parent
        #: dir provisioned, files intentionally absent until first
        #: emission"), except here each of the finitely many registered
        #: capabilities provisions its own subdirectory on first
        #: construction rather than requiring a separate manual step per
        #: capability. Never creates or touches any *file* here -- only
        #: the directory `write_secure_new()` itself requires to already
        #: exist before its own O_CREAT|O_EXCL write.
        root = artifact_base_directory / capability_symbol
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)

    @property
    def capability_symbol(self) -> str:
        return self._registration.capability_symbol

    def request_change(
        self,
        request: object,
        *,
        required_risk_class: AuthorizationLevel,
        now: datetime,
        freshness_env: dict[str, str] | None = None,
        acceptance_context: "AcceptanceExecutionContext | None" = None,
        target_capability_posture: CapabilityPosture = MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
        target_anchor_assurance: AnchorAssurance = MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
        requested_step_id: str = MILESTONE_9_WRITE_STEP_ID,
        requested_plan_digest: str,
    ) -> ProductOutcome:
        """The generalized ADR-028 five-state product operation. Identical
        algorithm and gate ordering to
        `ProductionAliasDescriptionRuntime.request_alias_description_change()`
        -- see that method's own docstring for the full rationale, which
        applies here unchanged. `request` must already be an instance of
        `self._registration.request_type` -- a mismatched type is refused
        by `WriteExecutionCoreV1.authorize_and_create()`'s own
        `_validate_inputs()` exactly as for the alias path, not re-checked
        here a second way."""

        if not isinstance(request, self._registration.request_type):
            return ProductOutcome(ProductOutcomeState.REFUSED)

        try:
            authorized_preparation = self._preparer.prepare(request)
            idempotency_key = self._core.compute_idempotency_key(authorized_preparation)
            existing = self._store.find_by_idempotency_key(idempotency_key)
        except Exception:
            return ProductOutcome(ProductOutcomeState.REFUSED)

        if existing is not None and existing.state is not RecoveryState.PREPARED:
            return ProductOutcome(_project_recovery_state(existing.state), contract_id=existing.contract_id)

        if existing is not None:
            try:
                handle = self._core.resume_prepared(existing.contract_id, request=request, now=now)
            except BoundExecutionError:
                return ProductOutcome(ProductOutcomeState.REFUSED, contract_id=existing.contract_id)
            contract = existing
        else:
            self._ensure_authorization_preview(
                request,
                authorized_preparation,
                requested_plan_digest=requested_plan_digest,
                requested_step_id=requested_step_id,
                target_capability_posture=target_capability_posture,
                target_anchor_assurance=target_anchor_assurance,
                now=now,
            )
            if not _artifact_present(self._paths.authorization_inbox_file):
                return ProductOutcome(ProductOutcomeState.REQUESTED)
            try:
                authorization = load_signed_plan_authorization_v2(self._paths.authorization_inbox_file)
            except ArtifactExchangeError:
                return ProductOutcome(ProductOutcomeState.REFUSED)
            # 2026-09-05 owner-directed retry/idempotency redesign, Slice 2:
            # parity with production_runtime.py's own
            # request_alias_description_change() -- see that method's
            # identical comment for the full rationale. `existing is None`
            # here means no currently-blocking contract, but terminal
            # historical attempts may still exist; never silently reuse
            # the fixed-inbox artifact that was already consumed for one
            # of them.
            for historical in self._store.find_historical_by_idempotency_key(idempotency_key):
                if (
                    historical.authorization_provenance is not None
                    and historical.authorization_provenance.authorization_id == authorization.authorization_id
                ):
                    return ProductOutcome(ProductOutcomeState.REFUSED, contract_id=historical.contract_id)
            try:
                handle = self._core.authorize_and_create(
                    request,
                    authorized_preparation=authorized_preparation,
                    authorization=authorization,
                    requested_plan_digest=requested_plan_digest,
                    requested_step_id=requested_step_id,
                    required_risk_class=required_risk_class,
                    target_capability_posture=target_capability_posture,
                    target_anchor_assurance=target_anchor_assurance,
                    now=now,
                    freshness_env=freshness_env,
                )
            except BoundExecutionError:
                return ProductOutcome(ProductOutcomeState.REFUSED)
            try:
                contract = self._store.load(handle.contract_id)
            except Exception:
                return ProductOutcome(ProductOutcomeState.AWAITING_CONFIRMATION, contract_id=handle.contract_id)

        self._ensure_pending_confirmation_request(
            contract, request=request, authorized_preparation=authorized_preparation
        )

        if not _artifact_present(self._paths.confirmation_signed_file):
            return ProductOutcome(ProductOutcomeState.AWAITING_CONFIRMATION, contract_id=handle.contract_id)
        try:
            confirmation = load_signed_confirmation_evidence(self._paths.confirmation_signed_file)
        except ArtifactExchangeError:
            return ProductOutcome(ProductOutcomeState.REFUSED, contract_id=handle.contract_id)
        try:
            outcome = self._core.confirm_and_handoff(
                handle, confirmation=confirmation, now=now, acceptance_context=acceptance_context
            )
        except BoundExecutionError:
            return ProductOutcome(ProductOutcomeState.REFUSED, contract_id=handle.contract_id)
        return ProductOutcome(_project_recovery_state(outcome.state), contract_id=handle.contract_id)

    def _ensure_authorization_preview(
        self,
        request: object,
        authorized_preparation: object,
        *,
        requested_plan_digest: str,
        requested_step_id: str,
        target_capability_posture: CapabilityPosture,
        target_anchor_assurance: AnchorAssurance,
        now: datetime,
    ) -> None:
        if _artifact_present(self._paths.authorization_preview_file):
            return
        try:
            preview = preview_from_preparation(
                capability_symbol=self.capability_symbol,
                request=request,
                prepared=authorized_preparation,
                requested_plan_digest=requested_plan_digest,
                requested_step_id=requested_step_id,
                target_capability_posture=target_capability_posture,
                target_anchor_assurance=target_anchor_assurance,
                generated_at=now,
            )
            write_secure_new(
                self._paths.authorization_preview_file,
                shape_a_authorization_preview_to_bytes(preview, integrity_key=self._artifact_integrity_key),
            )
        except ArtifactExchangeError:
            pass

    def _ensure_pending_confirmation_request(
        self, contract: object, *, request: object, authorized_preparation: object
    ) -> None:
        if _artifact_present(self._paths.confirmation_pending_file):
            return
        try:
            pending = pending_confirmation_request_from_contract(
                contract,  # type: ignore[arg-type]
                capability_symbol=self.capability_symbol,
                request=request,
                prepared=authorized_preparation,
                expected_authority_id=self._confirmation_authority_id,
            )
            write_secure_new(
                self._paths.confirmation_pending_file,
                shape_a_pending_confirmation_request_to_bytes(pending, integrity_key=self._artifact_integrity_key),
            )
        except ArtifactExchangeError:
            pass


def _artifact_present(path: Path) -> bool:
    return path.is_symlink() or path.exists()
