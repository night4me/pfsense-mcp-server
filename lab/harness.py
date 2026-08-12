"""Disposable-lab scenario driver. See
docs/tier1/specs/disposable_lab_execution_model.md.

Once pointed at a real lab VM (not authorized here — see this package's
`__init__.py`), this is the *only* place in the entire project where a
real `MutationExecutor` is constructed and actually allowed to send a
mutating request.

No production PREPARE endpoint exists yet in `pfsense_mcp.tier1` — that
lands with Phase 5's MCP tool wiring, per
`docs/tier1/IMPLEMENTATION_ROADMAP.md`. `prepare_contract()` below is a
lab-scoped equivalent (construct one `RecoveryContract` from an adapter's
pure projections plus a raw target/intent, exactly what a real PREPARE
step would do) — good enough for driving disposable-lab scenarios against
a throwaway store, but not a claim that this is (or should become
verbatim) the eventual production PREPARE implementation; that remains
Phase 5's design decision to make with a real adapter in hand.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from pfsense_mcp.tier1.canonical import CanonicalValue, DigestPurpose, canonical_json, digest_value
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.contract import ProtectedArtifact, RecoveryContract, derive_idempotency_key
from pfsense_mcp.tier1.crypto import ArtifactRole, build_nonce, encrypt_artifact
from pfsense_mcp.tier1.executor import CapabilityAdapter, MutationExecutor
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

from .fault_proxy import FaultProxy, FaultScenario


@dataclass(frozen=True)
class ScenarioSetup:
    """Everything one scenario needs to construct a fresh throwaway
    contract for a specific adapter/candidate. `intent_payload` and
    `snapshot_payload` are the plaintext that gets encrypted into the
    contract's protected artifacts; `raw_target_hint` is what the caller
    asserts the target currently looks like, matched against the
    adapter's own authoritative re-read during `execute()`."""

    raw_target_hint: CanonicalValue
    intent_payload: dict[str, CanonicalValue]
    snapshot_payload: dict[str, CanonicalValue]
    rollback_plan_version: str = "lab-v1"


@dataclass(frozen=True)
class ScenarioReport:
    scenario: FaultScenario
    passed: bool
    detail: str
    final_state: str | None = None


@dataclass(frozen=True)
class ExitConditionReport:
    permission_revoked: bool
    read_only_confirmed: bool

    @property
    def clean(self) -> bool:
        return self.permission_revoked and self.read_only_confirmed


@dataclass(frozen=True)
class AcceptanceReport:
    scenario_reports: tuple[ScenarioReport, ...]
    exit_condition: ExitConditionReport

    @property
    def all_passed(self) -> bool:
        return self.exit_condition.clean and all(report.passed for report in self.scenario_reports)


def _encrypt(
    payload: CanonicalValue, *, key: bytes, contract_id: str, role: ArtifactRole, counter: int
) -> ProtectedArtifact:
    nonce = build_nonce(epoch=0, counter=counter)
    plaintext = canonical_json(payload)
    return encrypt_artifact(
        key=key, key_id="lab-0001", contract_id=contract_id, role=role, plaintext=plaintext, nonce=nonce
    )


def prepare_contract(
    *,
    adapter: CapabilityAdapter,
    setup: ScenarioSetup,
    encryption_key: bytes,
    contract_id: str,
    operation_id: str,
    now: datetime | None = None,
    validity: timedelta = timedelta(minutes=5),
) -> tuple[RecoveryContract, dict[str, CanonicalValue]]:
    """Constructs one unconfirmed, `PREPARING`-state `RecoveryContract`
    ready for `store.create()`, plus the exact `intent` value `execute()`
    must later be called with to pass binding verification (see this
    module's docstring for why this lives here rather than in
    `pfsense_mcp.tier1`)."""

    created = now or datetime.now(timezone.utc)
    context = (adapter.capability.name, adapter.endpoint_symbol, adapter.http_method)
    identity = adapter.natural_identity(setup.raw_target_hint)
    fingerprint = adapter.fingerprint(setup.raw_target_hint)
    lifecycle_locator = adapter.transport_locator(setup.raw_target_hint)
    intent: dict[str, CanonicalValue] = {"raw_target_hint": setup.raw_target_hint, **setup.intent_payload}

    target_digest = digest_value(DigestPurpose.TARGET_IDENTITY, identity, context=(adapter.capability.name,))
    fingerprint_digest = digest_value(DigestPurpose.TARGET_FINGERPRINT, fingerprint, context=context)
    intent_digest = digest_value(DigestPurpose.INTENT, intent, context=context)
    snapshot_digest = digest_value(DigestPurpose.SNAPSHOT, setup.snapshot_payload, context=context)
    idempotency_key = derive_idempotency_key(
        capability=adapter.capability,
        endpoint_symbol=adapter.endpoint_symbol,
        http_method=adapter.http_method,
        target_identity_digest=target_digest,
        target_fingerprint=fingerprint_digest,
        lifecycle_locator=lifecycle_locator,
        intent_digest=intent_digest,
        snapshot_digest=snapshot_digest,
        rollback_plan_version=setup.rollback_plan_version,
    )

    contract = RecoveryContract(
        contract_id=contract_id,
        operation_id=operation_id,
        idempotency_key=idempotency_key,
        capability=adapter.capability,
        endpoint_symbol=adapter.endpoint_symbol,
        http_method=adapter.http_method,
        target_identity_digest=target_digest,
        target_fingerprint=fingerprint_digest,
        lifecycle_locator=lifecycle_locator,
        intent_digest=intent_digest,
        snapshot_digest=snapshot_digest,
        rollback_plan_version=setup.rollback_plan_version,
        created_at=created,
        expires_at=created + validity,
        state=RecoveryState.PREPARING,
        state_version=0,
        protected_target_identity=_encrypt(
            setup.raw_target_hint,
            key=encryption_key,
            contract_id=contract_id,
            role=ArtifactRole.TARGET_IDENTITY,
            counter=1,
        ),
        protected_intent=_encrypt(
            setup.intent_payload, key=encryption_key, contract_id=contract_id, role=ArtifactRole.INTENT, counter=2
        ),
        protected_snapshot=_encrypt(
            setup.snapshot_payload, key=encryption_key, contract_id=contract_id, role=ArtifactRole.SNAPSHOT, counter=3
        ),
    )
    return contract, intent


def run_scenario(
    *,
    store: SqliteRecoveryContractStore,
    executor: MutationExecutor,
    adapter: CapabilityAdapter,
    setup: ScenarioSetup,
    confirm: Callable[[RecoveryContract], RecoveryContract],
    scenario: FaultScenario,
    fault_proxy: FaultProxy,
    encryption_key: bytes,
    contract_id: str,
    operation_id: str,
) -> ScenarioReport:
    """Runs one full prepare -> confirm -> execute cycle under the given
    fault scenario, using the caller-supplied (fresh, throwaway per
    TIER1_LAB_PLAN.md) store. Never raises — every failure mode,
    including an unexpected exception, is captured in the returned
    ScenarioReport so one scenario's failure never aborts the batch (G2)."""

    fault_proxy.install(scenario)
    try:
        prepared, intent = prepare_contract(
            adapter=adapter,
            setup=setup,
            encryption_key=encryption_key,
            contract_id=contract_id,
            operation_id=operation_id,
        )
        store.create(prepared)
        awaiting_confirmation = store.transition(
            prepared.contract_id,
            expected_state=RecoveryState.PREPARING,
            expected_version=0,
            target_state=RecoveryState.PREPARED,
        )
        confirmed = confirm(awaiting_confirmation)
        outcome = executor.execute(confirmed.contract_id, adapter=adapter, intent=intent)
        return ScenarioReport(scenario=scenario, passed=True, detail=outcome.detail, final_state=outcome.state.value)
    except Exception as exc:
        return ScenarioReport(scenario=scenario, passed=False, detail=f"{type(exc).__name__}: {exc}")


def run_full_acceptance(
    *,
    scenario_runners: dict[FaultScenario, Callable[[], ScenarioReport]],
    verify_exit_conditions: Callable[[], ExitConditionReport],
) -> AcceptanceReport:
    """Runs every scenario the caller supplies (one runner per
    `docs/TIER1_LAB_PLAN.md` scenario the caller has wired up, plus the
    `CLEAN_PASSTHROUGH` baseline), aggregating results. Exit-condition
    verification (I5) always runs, even if a runner raises an exception
    `run_scenario`'s own try/except didn't itself catch — a
    `finally`-equivalent path, so a crashed run never silently leaves
    elevated lab permissions active."""

    reports: list[ScenarioReport] = []
    try:
        for scenario, runner in scenario_runners.items():
            try:
                reports.append(runner())
            except Exception as exc:
                reports.append(ScenarioReport(scenario=scenario, passed=False, detail=f"{type(exc).__name__}: {exc}"))
    finally:
        exit_condition = verify_exit_conditions()
    return AcceptanceReport(scenario_reports=tuple(reports), exit_condition=exit_condition)


def evidence_from_confirmation(
    *, contract: RecoveryContract, authority_id: str, algorithm: str, nonce: str, proof: bytes
) -> ConfirmationEvidence:
    """Convenience constructor a lab-run script can use to build the
    `ConfirmationEvidence` its own `confirm` callback needs — thin, not a
    new authority; still requires a real `ConfirmationVerifier` wired
    into the store to actually accept it (per confirmation_authority.md,
    unchanged by this package)."""

    return ConfirmationEvidence(
        authority_id=authority_id,
        algorithm=algorithm,
        nonce=nonce,
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        target_identity_digest=contract.target_identity_digest,
        target_fingerprint=contract.target_fingerprint,
        intent_digest=contract.intent_digest,
        expires_at=contract.expires_at,
        issued_at=contract.created_at,
        proof=proof,
    )
