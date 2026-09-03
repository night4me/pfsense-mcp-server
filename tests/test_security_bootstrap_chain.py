"""Mission II Mission A -- arbitrary-generation RESOLVE_UNPROVISIONED_INCIDENT
chain: `locate_bootstrap_chain_frontier()` (security_admin_composition.py)
and its two callers, `run_bootstrap_from_environment()`/`run_readonly_
bootstrap_from_environment()` (security_bootstrap_orchestration.py) and
`run_recovery_from_environment()` (security_recovery_orchestration.py).

Design recap (see `locate_bootstrap_chain_frontier()`'s own docstring for
the full contract): incident 0 lives at the fixed, original bootstrap
namespace. Each RESOLVE_UNPROVISIONED_INCIDENT resolution's own
`operation_id` is deterministic (`derive_resolution_operation_id()`,
already covered by test_security_operation_journal.py) and is reused as
the salt for *both* the next generation's bootstrap namespace *and* that
generation's own resolution namespace -- so an arbitrary-length chain
never collides with an earlier generation's already-`COMPLETED` files.
This file proves the chain-walk primitive is explicit (never silently
guesses), fail-closed on any ambiguity, and never lets a resolution
authorize a generation it was not computed for -- while never touching
`REVOKE_ORPHAN_KEY`/`DELETE_DEDICATED_USER` (unchanged, exhaustively
covered by test_security_recovery_orchestration.py already)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from pfsense_mcp.errors import BootstrapProvisioningError
from pfsense_mcp.security_admin_composition import (
    PfRestReadOnlyStatus,
    build_admin_context,
    locate_bootstrap_chain_frontier,
)
from pfsense_mcp.security_bootstrap_engine import ProvisioningOutcome, ProvisioningResult
from pfsense_mcp.security_bootstrap_orchestration import (
    BootstrapOrchestrationOutcome,
    run_bootstrap_from_environment,
)
from pfsense_mcp.security_bootstrap_recovery import UnprovisionedIncidentEvidence
from pfsense_mcp.security_operation_journal import (
    AdministrativeOperationType,
    AdministrativeTransactionState,
    DurableOperationState,
    RestartClassification,
    derive_resolution_operation_id,
)
from pfsense_mcp.security_readonly_admin_composition import build_readonly_admin_context
from pfsense_mcp.security_recovery_orchestration import (
    RecoveryAction,
    RecoveryOrchestrationOutcome,
    run_recovery_from_environment,
)


def _write_secure(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.write_bytes(value)
    path.chmod(mode)


@pytest.fixture
def admin_env(tmp_path: Path) -> dict[str, str]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    schema = tmp_path / "schema.json"
    fixture = Path(__file__).parent / "fixtures" / "pfsense_openapi_schema_trimmed.json"
    _write_secure(schema, fixture.read_bytes())
    _write_secure(tmp_path / "admin-api-key", b"synthetic-admin-key\n")
    _write_secure(tmp_path / "admin-password", b"synthetic-admin-password\n")
    _write_secure(tmp_path / "journal-key", b"j" * 32)
    _write_secure(tmp_path / "ca.pem", b"synthetic-ca", mode=0o644)
    return {
        "PFSENSE_API_URL": "https://lab.example.invalid",
        "PFSENSE_IDENTITY": "lab-appliance-one",
        "PFSENSE_API_KEY_FILE": str(tmp_path / "admin-api-key"),
        "PFSENSE_TLS_MODE": "auto",
        "PFSENSE_TLS_CA_FILE": str(tmp_path / "ca.pem"),
        "PFSENSE_API_VERSION": "v2",
        "PFSENSE_ADMIN_USERNAME": "admin",
        "PFSENSE_ADMIN_PASSWORD_FILE": str(tmp_path / "admin-password"),
        "PFSENSE_SERVICE_API_KEY_FILE": str(custody / "pfsense-mcp.key"),
        "PFSENSE_ADMIN_STATE_DIR": str(state),
        "PFSENSE_ADMIN_JOURNAL_KEY_FILE": str(tmp_path / "journal-key"),
        "PFSENSE_ADMIN_SCHEMA_FILE": str(schema),
        "PFSENSE_ADMIN_SCHEMA_VERSION": "restapi-v2.10",
        "PFSENSE_RESTAPI_PACKAGE_VERSION": "2.10.0",
    }


@dataclass
class _ChainSim:
    """Shared mutable state a wrapped `build_admin_context` reads on every
    call: the first `fail_until` real `bootstrap_call()` invocations
    raise (landing the journal at MUTATION_RESULT_UNKNOWN with
    `recovery_action=None`, exactly the shape a pre-flight-observation
    failure leaves); the next one reports COMPLETED. `identify_
    unprovisioned_incident_evidence_call()` mirrors this same state:
    "confirmed absent" only while the account has not yet actually been
    (synthetically) created."""

    fail_until: int
    attempts: int = 0


def _wrap_build(real_build, sim: _ChainSim):
    def build(source, **kwargs):
        context = real_build(source, **kwargs)

        def bootstrap_call() -> ProvisioningResult:
            sim.attempts += 1
            if sim.attempts <= sim.fail_until:
                raise RuntimeError(f"simulated pre-flight-observation failure #{sim.attempts}")
            return ProvisioningResult(ProvisioningOutcome.COMPLETED, "synthetic completed provisioning")

        def identify_absent() -> UnprovisionedIncidentEvidence:
            if sim.attempts > sim.fail_until:
                raise BootstrapProvisioningError("account now exists; not an unprovisioned incident")
            return UnprovisionedIncidentEvidence(
                account_username="pfsense-mcp",
                account_confirmed_absent=True,
                no_owned_key_confirmed=True,
                users_checked=1,
                keys_checked=0,
            )

        components = replace(
            context._mutation_components,
            check_pfrest_read_only_call=lambda: PfRestReadOnlyStatus.WRITABLE,
            bootstrap_call=bootstrap_call,
            identify_unprovisioned_incident_evidence_call=identify_absent,
        )
        return replace(context, _mutation_components=components)

    return build


def _install_chain_sim(monkeypatch, sim: _ChainSim, *, readonly: bool = False) -> None:
    real = build_readonly_admin_context if readonly else build_admin_context
    target = "build_readonly_admin_context" if readonly else "build_admin_context"
    wrapped = _wrap_build(real, sim)
    monkeypatch.setattr(f"pfsense_mcp.security_bootstrap_orchestration.{target}", wrapped)
    monkeypatch.setattr(f"pfsense_mcp.security_recovery_orchestration.{target}", wrapped)


# --- The full multi-generation happy path -----------------------------------


def test_full_three_generation_chain_resolves_generation_by_generation_and_terminates(admin_env, monkeypatch):
    """Covers: retry incident can be independently resolved, third-
    generation incident can also be resolved, arbitrary chain traversal
    terminates correctly, only the newest valid retry namespace becomes
    eligible."""

    sim = _ChainSim(fail_until=2)
    _install_chain_sim(monkeypatch, sim)

    # Generation 0: fails (pre-flight-observation-shaped failure).
    r0 = run_bootstrap_from_environment(admin_env)
    assert r0.outcome is BootstrapOrchestrationOutcome.PROVISIONING_FAILED

    inspect0 = run_recovery_from_environment(admin_env)
    assert inspect0.outcome is RecoveryOrchestrationOutcome.RECOVERY_NEEDED
    assert inspect0.recovery_action is RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT
    assert inspect0.generation == 0
    exec0 = run_recovery_from_environment(
        admin_env,
        execute_action=RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT,
        confirm_token=inspect0.confirmation_token,
    )
    assert exec0.outcome is RecoveryOrchestrationOutcome.RECOVERY_COMPLETED
    assert exec0.generation == 0

    # Generation 1 (the retry namespace derived from generation 0's
    # resolution): also fails.
    r1 = run_bootstrap_from_environment(admin_env)
    assert r1.outcome is BootstrapOrchestrationOutcome.PROVISIONING_FAILED

    inspect1 = run_recovery_from_environment(admin_env)
    assert inspect1.outcome is RecoveryOrchestrationOutcome.RECOVERY_NEEDED
    assert inspect1.generation == 1
    exec1 = run_recovery_from_environment(
        admin_env,
        execute_action=RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT,
        confirm_token=inspect1.confirmation_token,
    )
    assert exec1.outcome is RecoveryOrchestrationOutcome.RECOVERY_COMPLETED
    assert exec1.generation == 1

    # Generation 2 (derived from generation 1's resolution): succeeds --
    # the chain naturally terminates, exactly as bootstrap always has for
    # the un-chained case.
    r2 = run_bootstrap_from_environment(admin_env)
    assert r2.outcome is BootstrapOrchestrationOutcome.COMPLETED
    assert sim.attempts == 3

    # Every generation's namespace is genuinely distinct on disk.
    gen0 = build_admin_context(admin_env)
    incident0_snapshot = gen0._journal.load()
    resolution0_id = derive_resolution_operation_id(
        incident_operation_id=incident0_snapshot.latest.binding.operation_id,
        incident_record_mac=incident0_snapshot.latest.mac,
    )
    gen1 = build_admin_context(admin_env, resolution_operation_id=resolution0_id)
    incident1_snapshot = gen1._journal.load()
    resolution1_id = derive_resolution_operation_id(
        incident_operation_id=incident1_snapshot.latest.binding.operation_id,
        incident_record_mac=incident1_snapshot.latest.mac,
    )
    gen2 = build_admin_context(admin_env, resolution_operation_id=resolution1_id)
    assert len({gen0.journal_path, gen1.journal_path, gen2.journal_path}) == 3
    assert gen2._journal.load().latest.state is DurableOperationState.COMPLETED


# --- Explicit-addressing / cross-generation adversarial matrix --------------


def test_resolution_for_incident_0_cannot_resolve_incident_1(admin_env, monkeypatch):
    """A confirmation token computed for generation 0's own incident must
    never authorize generation 1's incident, even when both are
    RESOLVE_UNPROVISIONED_INCIDENT-shaped and `--execute` is repeated
    immediately after generation 0 was resolved."""

    sim = _ChainSim(fail_until=2)
    _install_chain_sim(monkeypatch, sim)

    run_bootstrap_from_environment(admin_env)  # generation 0 fails
    inspect0 = run_recovery_from_environment(admin_env)
    stale_token = inspect0.confirmation_token
    run_recovery_from_environment(
        admin_env,
        execute_action=RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT,
        confirm_token=stale_token,
    )  # resolves generation 0

    run_bootstrap_from_environment(admin_env)  # generation 1 fails -- new frontier

    # Replaying generation 0's own (now-stale) token against generation 1's
    # incident must fail closed before any mutation -- the token's
    # cryptographic binding to generation 0's own (operation_id, mac) can
    # never satisfy generation 1's freshly re-derived binding.
    replay = run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT, confirm_token=stale_token
    )
    assert replay.outcome is RecoveryOrchestrationOutcome.EXECUTE_TOKEN_INVALID
    assert replay.generation == 1

    # Generation 0's own resolution remains untouched and complete.
    gen0 = build_admin_context(admin_env)
    incident0_snapshot = gen0._journal.load()
    resolution0_id = derive_resolution_operation_id(
        incident_operation_id=incident0_snapshot.latest.binding.operation_id,
        incident_record_mac=incident0_snapshot.latest.mac,
    )
    resolution0 = build_admin_context(
        admin_env,
        operation_type=AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT,
        resolution_operation_id=None,
    )
    assert resolution0._journal.load().latest.state is DurableOperationState.COMPLETED
    assert resolution0._journal.load().latest.binding.operation_id == resolution0_id


def test_old_completed_resolution_cannot_be_replayed_against_a_later_retry_incident(admin_env, monkeypatch):
    """Generation 0's resolution journal, once COMPLETED, must never be
    (mis)recognized as satisfying generation 1's own hop condition --
    proven directly against `locate_bootstrap_chain_frontier()` by
    forcing the walk to re-check generation 1 after generation 0 alone
    is resolved."""

    sim = _ChainSim(fail_until=2)
    _install_chain_sim(monkeypatch, sim)

    run_bootstrap_from_environment(admin_env)  # generation 0 fails
    inspect0 = run_recovery_from_environment(admin_env)
    run_recovery_from_environment(
        admin_env,
        execute_action=RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT,
        confirm_token=inspect0.confirmation_token,
    )
    run_bootstrap_from_environment(admin_env)  # generation 1 fails, never resolved

    context0 = build_admin_context(admin_env)
    frontier = locate_bootstrap_chain_frontier(context0, source=admin_env, build_context=build_admin_context)
    assert frontier.generation == 1
    assert frontier.decision.classification is RestartClassification.RECOVERY_REQUIRED
    assert frontier.decision.recovery_action is None


def test_missing_intermediate_resolution_fails_closed(admin_env):
    """A generation-1 journal manually constructed at its real,
    cryptographically-derived namespace -- *without* generation 0's
    resolution ever completing -- must never be treated as reachable.
    The walk always re-verifies each hop from generation 0 forward; it
    never trusts that a file's mere existence at the "right" path proves
    the chain that should have created it actually ran."""

    context0 = build_admin_context(admin_env)
    context0._journal.create(
        context0.new_operation_binding(operation_id="incident-0", operation_type=AdministrativeOperationType.BOOTSTRAP),
        timestamp="2026-08-23T00:00:00Z",
    )
    incident0_snapshot = context0._journal.load()
    resolution0_id = derive_resolution_operation_id(
        incident_operation_id="incident-0", incident_record_mac=incident0_snapshot.latest.mac
    )
    # Generation 0's resolution was never completed (no journal at all for
    # it), yet a generation-1 journal is constructed directly at the exact
    # namespace it *would* occupy once resolved.
    gen1 = build_admin_context(admin_env, resolution_operation_id=resolution0_id)
    gen1._journal.create(
        gen1.new_operation_binding(operation_id="incident-1", operation_type=AdministrativeOperationType.BOOTSTRAP),
        timestamp="2026-08-23T00:00:00Z",
    )

    frontier = locate_bootstrap_chain_frontier(context0, source=admin_env, build_context=build_admin_context)

    assert frontier.generation == 0
    assert frontier.context.journal_path == context0.journal_path


def test_mismatched_incident_record_mac_fails_closed(admin_env):
    """A resolution journal present at generation 0's fixed namespace but
    bound to a fabricated (operation_id, mac) pair that does not match
    the real incident currently occupying that namespace must never be
    treated as resolving it."""

    context0 = build_admin_context(admin_env)
    context0._journal.create(
        context0.new_operation_binding(operation_id="incident-0", operation_type=AdministrativeOperationType.BOOTSTRAP),
        timestamp="2026-08-23T00:00:00Z",
    )

    resolution_context = build_admin_context(
        admin_env, operation_type=AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT
    )
    fabricated_id = "f" * 64  # not derived from the real incident's own (operation_id, mac)
    binding = resolution_context.new_operation_binding(
        operation_id=fabricated_id, operation_type=AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT
    )
    resolution_context._journal.create(binding, timestamp="2026-08-23T00:00:00Z")
    for state, transaction_state, ts in (
        (
            DurableOperationState.PRE_SEND_READY,
            AdministrativeTransactionState.RECOVERY_OBJECT_IDENTIFIED,
            "2026-08-23T00:00:01Z",
        ),
        (
            DurableOperationState.MUTATION_INTENT_RECORDED,
            AdministrativeTransactionState.RECOVERY_MUTATION_SENT,
            "2026-08-23T00:00:02Z",
        ),
        (
            DurableOperationState.FINAL_VERIFICATION_PENDING,
            AdministrativeTransactionState.RECOVERY_VERIFIED,
            "2026-08-23T00:00:03Z",
        ),
        (DurableOperationState.COMPLETED, AdministrativeTransactionState.RECOVERY_VERIFIED, "2026-08-23T00:00:04Z"),
    ):
        resolution_context._journal.append(
            operation_id=fabricated_id, state=state, transaction_state=transaction_state, mutation_index=1, timestamp=ts
        )

    frontier = locate_bootstrap_chain_frontier(context0, source=admin_env, build_context=build_admin_context)

    assert frontier.generation == 0
    assert frontier.context.journal_path == context0.journal_path


def test_wrong_target_profile_fails_closed(admin_env, monkeypatch):
    """A write_protected chain in progress must never be visible to, or
    influenced by, a `read_only`-profile inspection against the same
    admin configuration -- separate, structurally non-colliding
    namespaces (security_readonly_admin_composition.py's own docstring)."""

    sim = _ChainSim(fail_until=2)
    _install_chain_sim(monkeypatch, sim)
    run_bootstrap_from_environment(admin_env)  # write_protected generation 0 fails

    readonly_env = dict(admin_env)
    readonly_env["PFSENSE_READONLY_SERVICE_API_KEY_FILE"] = admin_env["PFSENSE_SERVICE_API_KEY_FILE"] + "-readonly"

    result = run_recovery_from_environment(readonly_env, target_profile="read_only")

    assert result.outcome is RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED
    assert result.generation == 0


def test_unrelated_namespace_remains_blocked(admin_env, monkeypatch, tmp_path):
    """A completely different target (different PFSENSE_API_URL, and
    hence a different namespace hash) must never be affected by, or
    report anything about, another target's chain state."""

    sim = _ChainSim(fail_until=2)
    _install_chain_sim(monkeypatch, sim)
    run_bootstrap_from_environment(admin_env)  # first target's generation 0 fails

    other_env = dict(admin_env)
    other_env["PFSENSE_API_URL"] = "https://other-lab.example.invalid"
    other_env["PFSENSE_ADMIN_STATE_DIR"] = str(tmp_path / "other-state")
    Path(other_env["PFSENSE_ADMIN_STATE_DIR"]).mkdir(mode=0o700)
    other_env["PFSENSE_SERVICE_API_KEY_FILE"] = str(tmp_path / "other-custody.key")

    result = run_recovery_from_environment(other_env)

    assert result.outcome is RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED
    assert result.generation == 0


# --- locate_bootstrap_chain_frontier() as a pure, isolated primitive -------


def test_arbitrary_chain_traversal_terminates_at_the_depth_cap():
    """A synthetic `build_context` that *always* reports a completed
    resolution (an adversarial/pathological input the real, honest
    on-disk chain can never produce -- see `locate_bootstrap_chain_
    frontier()`'s own docstring on why a genuine cycle is cryptographically
    infeasible) must never cause an unbounded walk. Proven directly
    against the pure primitive with fully synthetic contexts -- no real
    files, no network."""

    call_count = {"n": 0}

    class _FakeStatus:
        def __init__(self, hoppable: bool) -> None:
            self._hoppable = hoppable

        def classify(self, *, authoritative):
            from pfsense_mcp.security_operation_journal import RestartDecision

            if self._hoppable:
                return RestartDecision(RestartClassification.RECOVERY_REQUIRED, "op-x", None)
            return RestartDecision(RestartClassification.CLEAN_NO_OPERATION, None)

    class _FakeJournal:
        def load(self):
            from pfsense_mcp.security_operation_journal import (
                AdministrativeOperationType as _T,
            )
            from pfsense_mcp.security_operation_journal import (
                JournalRecord,
                JournalSnapshot,
                OperationBinding,
            )

            binding = OperationBinding(
                operation_id="op-x",
                operation_type=_T.BOOTSTRAP,
                target_identity="t",
                target_origin="https://x.invalid",
                account_identity="pfsense-mcp",
                approved_profile="write_protected",
                schema_version="v1",
                schema_evidence_digest="d",
                starting_auth_methods=("KeyAuth",),
            )
            record = JournalRecord(0, binding, DurableOperationState.CREATED, None, 0, None, "t", "0" * 64, "m" * 64)
            return JournalSnapshot((record,))

    class _FakeAdminStatusService:
        def __init__(self, hoppable: bool) -> None:
            self._inner = _FakeStatus(hoppable)

        def classify(self, *, authoritative):
            return self._inner.classify(authoritative=authoritative)

        def _load_bound_journal(self):
            return _FakeJournal().load(), True

    class _FakeContext:
        def __init__(self, *, hoppable: bool) -> None:
            self.status = _FakeAdminStatusService(hoppable)
            self._journal = _FakeJournal()

    def fake_build(source, *, operation_type=AdministrativeOperationType.BOOTSTRAP, resolution_operation_id=None):
        call_count["n"] += 1
        if operation_type is AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT:
            # Always report a COMPLETED resolution for whatever the
            # freshly re-derived operation_id happens to be -- an
            # adversarial fake `AdministrativeStatusService._load_bound_
            # journal()` bypassing the honest cryptographic check a real
            # one always performs.
            class _AlwaysComplete:
                def _load_bound_journal(self):
                    from pfsense_mcp.security_operation_journal import (
                        AdministrativeOperationType as _T,
                    )
                    from pfsense_mcp.security_operation_journal import (
                        JournalRecord,
                        JournalSnapshot,
                        OperationBinding,
                    )
                    from pfsense_mcp.security_operation_journal import derive_resolution_operation_id as _derive

                    expected = _derive(incident_operation_id="op-x", incident_record_mac="m" * 64)
                    binding = OperationBinding(
                        operation_id=expected,
                        operation_type=_T.RECOVER_UNPROVISIONED_INCIDENT,
                        target_identity="t",
                        target_origin="https://x.invalid",
                        account_identity="pfsense-mcp",
                        approved_profile="write_protected",
                        schema_version="v1",
                        schema_evidence_digest="d",
                        starting_auth_methods=("KeyAuth",),
                    )
                    record = JournalRecord(
                        0, binding, DurableOperationState.COMPLETED, None, 0, None, "t", "0" * 64, "r" * 64
                    )
                    return JournalSnapshot((record,)), True

            class _Ctx:
                status = _AlwaysComplete()

            return _Ctx()
        return _FakeContext(hoppable=True)

    context0 = _FakeContext(hoppable=True)
    frontier = locate_bootstrap_chain_frontier(context0, source={}, build_context=fake_build)

    from pfsense_mcp.security_admin_composition import _MAX_CHAIN_GENERATIONS

    assert frontier.generation == _MAX_CHAIN_GENERATIONS
    assert len(frontier.chain) == _MAX_CHAIN_GENERATIONS


def test_existing_recovery_actions_are_never_chain_walked(admin_env):
    """REVOKE_ORPHAN_KEY / DELETE_DEDICATED_USER incidents (a real
    recovery_action already recorded) must stop the walk immediately at
    whatever generation they occur, never advancing further or
    reinterpreting them as an unprovisioned-incident candidate -- the
    exact, unchanged behavior test_security_recovery_orchestration.py's
    own extensive matrix already exhaustively covers; this proves the
    chain-walk layer itself respects that boundary."""

    context0 = build_admin_context(admin_env)
    context0._journal.create(
        context0.new_operation_binding(operation_id="incident-0", operation_type=AdministrativeOperationType.BOOTSTRAP),
        timestamp="2026-08-23T00:00:00Z",
    )
    context0._journal.append(
        operation_id="incident-0",
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:01Z",
    )
    context0._journal.append(
        operation_id="incident-0",
        state=DurableOperationState.MUTATION_INTENT_RECORDED,
        transaction_state=AdministrativeTransactionState.BOOTSTRAP_PRIVILEGE_GRANTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:02Z",
    )
    context0._journal.append(
        operation_id="incident-0",
        state=DurableOperationState.RECOVERY_REQUIRED,
        transaction_state=AdministrativeTransactionState.BOOTSTRAP_PRIVILEGE_GRANTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:03Z",
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
    )

    frontier = locate_bootstrap_chain_frontier(context0, source=admin_env, build_context=build_admin_context)

    assert frontier.generation == 0
    assert frontier.decision.recovery_action is RecoveryAction.REVOKE_ORPHAN_KEY


# --- Historical-immutability proof -------------------------------------------


def test_all_historical_journals_remain_byte_identical_after_later_resolutions(admin_env, monkeypatch):
    sim = _ChainSim(fail_until=2)
    _install_chain_sim(monkeypatch, sim)

    run_bootstrap_from_environment(admin_env)
    inspect0 = run_recovery_from_environment(admin_env)
    run_recovery_from_environment(
        admin_env,
        execute_action=RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT,
        confirm_token=inspect0.confirmation_token,
    )
    gen0 = build_admin_context(admin_env)
    incident0_bytes_after_resolution0 = gen0.journal_path.read_bytes()
    resolution0 = build_admin_context(
        admin_env, operation_type=AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT
    )
    resolution0_bytes_after_resolution0 = resolution0.journal_path.read_bytes()

    run_bootstrap_from_environment(admin_env)
    inspect1 = run_recovery_from_environment(admin_env)
    run_recovery_from_environment(
        admin_env,
        execute_action=RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT,
        confirm_token=inspect1.confirmation_token,
    )
    run_bootstrap_from_environment(admin_env)  # generation 2 succeeds

    assert gen0.journal_path.read_bytes() == incident0_bytes_after_resolution0
    assert resolution0.journal_path.read_bytes() == resolution0_bytes_after_resolution0


def test_generation_field_reported_none_only_when_walk_never_ran(admin_env):
    bad_env = dict(admin_env)
    del bad_env["PFSENSE_ADMIN_SCHEMA_FILE"]
    result = run_recovery_from_environment(bad_env)
    assert result.outcome is RecoveryOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR
    assert result.generation is None
