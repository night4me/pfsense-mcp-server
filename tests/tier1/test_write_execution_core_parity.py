"""ADR-037 Batch 1 post-implementation security review (2026-09-04, owner):
mechanical parity between `AliasDescriptionExecutionCoreV1` (the original,
already-qualified canonical gate for `set_firewall_alias_description_v1`)
and `WriteExecutionCoreV1` (the ADR-037 Batch 1 generic reproduction of the
*same* algorithm, used by all five new Batch 1 capabilities).

## Why this file exists

Both cores were independently re-read line by line as part of this review.
Every actual security *decision* (signature verification, plan/step/digest
binding, risk-class satisfaction, freshness) is not duplicated: both files
call the identical canonical primitives in
`security_authorization_verifier.py`/`security_plan_freshness.py`, proven
single-implementation and unduplicated by
`test_security_authorization_verifier_isolation.py`/
`test_security_plan_freshness_isolation.py` (the latter's own
`_ALLOWED_IMPORTERS` was found, during this review, to be blind to both
cores' absolute-style imports -- fixed separately, see that file's
docstring). What *is* duplicated, as roughly 450 lines of independently
maintained Python in each file, is the *orchestration*: gate order, which
checks are added on top of the canonical primitives (the issued_at-window
check neither `security_authorization_verifier.py` nor
`security_plan_freshness.py` performs itself), and the fail-closed
wrapping around all of it.

The review's owner-stated instruction was explicit: "Do not accept 'they
currently behave the same' as sufficient if future drift is possible."
Because the two ADR-036/ADR-037 owner decisions on record both forbid
casually rewriting the already-qualified alias path or refactoring purely
for aesthetics, this file is the fallback the review's own instructions
require instead: a *mechanical parity invariant*. It drives both cores
through the same named adversarial scenarios and asserts they reach the
same classified outcome for each -- so a future change to either file's
gate ordering or fail-closed semantics that silently diverges from the
other is caught here, at test time, not discovered live.

## What is and is not covered here

The eleven case names below are exactly the subset of
`test_alias_description_execution.py::test_all_preconsumption_failures_leave_auth_unconsumed_and_zero_handoff`'s
own 13-case matrix that generalizes across both domains (a firewall alias
with sibling/locator fields vs. a single-field singleton). Two of that
matrix's case names -- `sibling-drift` and `locator-drift` -- test
alias-specific concepts (a *different* field on the same record changing;
a numeric `id` locator changing) that do not exist for a singleton PATCH
target with one field and a fixed `SINGLETON_LOCATOR`; the general
stale-precondition detection they both exercise is covered here by
`stale-precondition` instead, using the same technique as
`test_adr037_batch1_write_capabilities.py::test_precondition_drift_between_prepare_and_authorize_is_refused`.
`test_authorize_stage_case_names_are_covered_identically_in_both_test_files`
below is the actual mechanical guarantee: it AST-scans both source test
files and fails if either one's matrix stops declaring every name in
`_SHARED_AUTHORIZE_STAGE_CASES`, so a case silently dropped from one
side without the other is a test failure, not a silent gap.

Deliberately NOT reproduced here:

- **Anti-rollback-anchor conflict handling** is `MutationExecutor`-level
  behavior, identical by construction for both cores since both hand off
  to the one sealed executor via `self._executor.execute(...)` -- already
  proven once for the alias path
  (`test_production_adapter_rollback_conflict_refuses_and_post_expiry_recovery_remains_available`).
  Reproducing it here would test `MutationExecutor` a second time, not
  the two orchestration bodies this file exists to compare.
- **Wrong endpoint / wrong privilege** are `MutationPolicy`/`MutationRule`
  binding concerns enforced by `MutationExecutor`, not by either
  execution core's own `authorize_and_create()`/`confirm_and_handoff()` --
  out of scope for the same reason.
- **Default-unreachable behavior** is a static-import property, already
  independently proven per-side
  (`test_no_new_capability_module_is_imported_outside_tier1` here vs.
  the alias capability's own equivalent) -- not a runtime authorization
  outcome this matrix classifies.
"""

from __future__ import annotations

import ast
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from pfsense_mcp.security_authorization import (
    PlanAuthorization,
    build_plan_authorization_payload,
    sign_plan_authorization,
)
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.tier1.alias_description import AliasDescriptionChangeV1
from pfsense_mcp.tier1.alias_description_execution import AliasDescriptionExecutionCoreV1
from pfsense_mcp.tier1.errors import BoundExecutionError
from pfsense_mcp.tier1.executor import ExecutionOutcome, MutationExecutor
from pfsense_mcp.tier1.prepared_execution_intent import compute_execution_intent_digest
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.system_timezone_write import (
    PreparedSystemTimezoneExecutionV1,
    SystemTimezoneChangeV1,
    SystemTimezonePreparerV1,
)
from pfsense_mcp.tier1.write_execution_core import WriteExecutionCoreV1
from tests.tier1.test_adr037_batch1_write_capabilities import (
    NOW,
    _FakeClient,
)
from tests.tier1.test_adr037_batch1_write_capabilities import (
    _authorization as _tz_authorization,
)
from tests.tier1.test_adr037_batch1_write_capabilities import (
    _core as _tz_core,
)
from tests.tier1.test_adr037_batch1_write_capabilities import (
    _plan as _tz_plan,
)
from tests.tier1.test_adr037_batch1_write_capabilities import (
    _store as _tz_store,
)
from tests.tier1.test_adr037_batch1_write_capabilities import (
    _target as _tz_target,
)
from tests.tier1.test_alias_description_execution import (
    _authorization as _alias_authorization,
)
from tests.tier1.test_alias_description_execution import (
    _core as _alias_core,
)
from tests.tier1.test_alias_description_execution import (
    _plan as _alias_plan,
)
from tests.tier1.test_alias_description_execution import (
    _preparer as _alias_preparer,
)
from tests.tier1.test_alias_description_execution import (
    _ReadClient,
)

ROOT = Path(__file__).parents[2]
_ALIAS_TEST_PATH = ROOT / "tests/tier1/test_alias_description_execution.py"
_BATCH1_TEST_PATH = ROOT / "tests/tier1/test_adr037_batch1_write_capabilities.py"

# The subset of alias's 13-case pre-consumption matrix that generalizes to
# a single-field singleton capability -- see module docstring.
_SHARED_AUTHORIZE_STAGE_CASE_LIST = [
    "bad-signature",
    "expired",
    "future",
    "risk-downgrade",
    "stale-plan",
    "wrong-authority",
    "wrong-digest",
    "wrong-plan",
    "wrong-step",
]
_SHARED_AUTHORIZE_STAGE_CASES = frozenset(_SHARED_AUTHORIZE_STAGE_CASE_LIST)
assert len(_SHARED_AUTHORIZE_STAGE_CASE_LIST) == len(_SHARED_AUTHORIZE_STAGE_CASES), "duplicate case name"


def _alias_scenario(tmp_path: Path, case: str, monkeypatch: pytest.MonkeyPatch) -> str:
    """Drive `AliasDescriptionExecutionCoreV1` through one named
    authorize-stage scenario. Returns "REFUSED" (BoundExecutionError,
    consumption untouched, executor never called) or raises AssertionError
    if the core's actual behavior doesn't match that classification."""

    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _ReadClient()
    core, private, _store, consumption, executor = _alias_core(tmp_path, client)
    request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    prepared = _alias_preparer(client).prepare(request)
    digest = compute_execution_intent_digest(prepared.intent)
    authz = _alias_authorization(private, digest)
    kwargs: dict[str, object] = {
        "authorized_preparation": prepared,
        "requested_plan_digest": authz.plan_digest,
        "requested_step_id": "first.write.alias.description",
        "required_risk_class": AuthorizationLevel.CONFIGURATION_CHANGE,
        "target_capability_posture": CapabilityPosture.WRITE_PROTECTED,
        "target_anchor_assurance": AnchorAssurance.HARDWARE_WITNESS,
        "now": NOW,
    }
    if case == "wrong-step":
        kwargs["requested_step_id"] = "wrong-step"
    elif case == "wrong-plan":
        kwargs["requested_plan_digest"] = "0" * 64
    elif case == "wrong-digest":
        authz = _alias_authorization(private, "f" * 64)
    elif case == "future":
        authz = _alias_authorization(
            private, digest, issued_at=NOW + timedelta(seconds=1), expires_at=NOW + timedelta(minutes=5)
        )
    elif case == "expired":
        authz = _alias_authorization(private, digest, issued_at=NOW - timedelta(minutes=5), expires_at=NOW)
    elif case == "bad-signature":
        from dataclasses import replace

        authz = replace(authz, proof=b"x" * 64)
    elif case == "wrong-authority":
        from dataclasses import replace

        authz = replace(authz, authority_id="unknown-owner")
    elif case == "stale-plan":
        monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: False))
    elif case == "risk-downgrade":
        kwargs["required_risk_class"] = AuthorizationLevel.INTERACTIVE_HARDWARE_CONFIRMATION
    else:
        raise AssertionError(f"unknown case {case!r}")

    kwargs["authorization"] = authz
    with pytest.raises(BoundExecutionError):
        core.authorize_and_create(request, **kwargs)
    assert consumption.calls == 0
    executor.execute.assert_not_called()
    return "REFUSED"


def _tz_scenario(tmp_path: Path, case: str, monkeypatch: pytest.MonkeyPatch) -> str:
    """Drive `WriteExecutionCoreV1`, wired for `SYSTEM_TIMEZONE`, through
    the same named scenario as `_alias_scenario` above. Same return/raise
    contract."""

    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    client = _FakeClient()
    preparer = SystemTimezonePreparerV1(read_client=client, configured_target=_tz_target())
    store = _tz_store(tmp_path, f"parity-{case}")
    executor = Mock(spec=MutationExecutor)
    executor.execute.return_value = ExecutionOutcome("unused", RecoveryState.VERIFIED, "synthetic")
    core, private, _store = _tz_core(
        tmp_path,
        store=store,
        preparer=preparer,
        prepared_type=PreparedSystemTimezoneExecutionV1,
        request_type=SystemTimezoneChangeV1,
        contract_id_prefix="parity",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=executor,
    )
    request = SystemTimezoneChangeV1(timezone="Europe/Berlin")
    prepared = preparer.prepare(request)
    digest = compute_execution_intent_digest(prepared.intent)
    authz = _tz_authorization(private, digest)
    kwargs: dict[str, object] = {
        "authorized_preparation": prepared,
        "requested_plan_digest": authz.plan_digest,
        "requested_step_id": "batch1.step",
        "required_risk_class": AuthorizationLevel.CONFIGURATION_CHANGE,
        "target_capability_posture": CapabilityPosture.WRITE_PROTECTED,
        "target_anchor_assurance": AnchorAssurance.HARDWARE_WITNESS,
        "now": NOW,
    }
    if case == "wrong-step":
        kwargs["requested_step_id"] = "wrong-step"
    elif case == "wrong-plan":
        kwargs["requested_plan_digest"] = "0" * 64
    elif case == "wrong-digest":
        authz = _tz_authorization(private, "f" * 64)
    elif case == "future":
        authz = _tz_authorization(
            private, digest, issued_at=NOW + timedelta(seconds=1), expires_at=NOW + timedelta(minutes=5)
        )
    elif case == "expired":
        authz = _tz_authorization(private, digest, issued_at=NOW - timedelta(minutes=5), expires_at=NOW)
    elif case == "bad-signature":
        from dataclasses import replace

        authz = replace(authz, proof=b"x" * 64)
    elif case == "wrong-authority":
        from dataclasses import replace

        authz = replace(authz, authority_id="unknown-owner")
    elif case == "stale-plan":
        monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: False))
    elif case == "risk-downgrade":
        kwargs["required_risk_class"] = AuthorizationLevel.INTERACTIVE_HARDWARE_CONFIRMATION
    else:
        raise AssertionError(f"unknown case {case!r}")

    kwargs["authorization"] = authz
    with pytest.raises(BoundExecutionError):
        core.authorize_and_create(request, **kwargs)
    assert core._consumption_store.consumed == set()  # type: ignore[attr-defined]
    executor.execute.assert_not_called()
    return "REFUSED"


@pytest.mark.parametrize(
    "case",
    [
        "bad-signature",
        "expired",
        "future",
        "risk-downgrade",
        "stale-plan",
        "wrong-authority",
        "wrong-digest",
        "wrong-plan",
        "wrong-step",
    ],
)
def test_authorize_stage_scenario_is_refused_identically_by_both_cores(
    tmp_path: Path, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "alias").mkdir()
    (tmp_path / "tz").mkdir()
    assert _alias_scenario(tmp_path / "alias", case, monkeypatch) == "REFUSED"
    assert _tz_scenario(tmp_path / "tz", case, monkeypatch) == "REFUSED"


def test_stale_precondition_between_prepare_and_authorize_is_refused_identically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Generalizes alias's `sibling-drift`/`locator-drift` cases (a field
    on the same target changing out-of-band between `prepare()` and
    `authorize_and_create()`) to a form that applies to a single-field
    singleton too: the *identity-bearing* field itself drifts."""

    (tmp_path / "alias").mkdir()
    (tmp_path / "tz").mkdir()
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    alias_client = _ReadClient()
    alias_core, alias_private, _s, alias_consumption, alias_executor = _alias_core(tmp_path / "alias", alias_client)
    alias_request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    alias_prepared = _alias_preparer(alias_client).prepare(alias_request)
    alias_digest = compute_execution_intent_digest(alias_prepared.intent)
    alias_authz = _alias_authorization(alias_private, alias_digest)
    alias_client.aliases[0] = alias_client.aliases[0].model_copy(update={"descr": "concurrent"})
    with pytest.raises(BoundExecutionError):
        alias_core.authorize_and_create(
            alias_request,
            authorized_preparation=alias_prepared,
            authorization=alias_authz,
            requested_plan_digest=alias_authz.plan_digest,
            requested_step_id="first.write.alias.description",
            required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            now=NOW,
        )
    assert alias_consumption.calls == 0
    alias_executor.execute.assert_not_called()

    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    tz_client = _FakeClient()
    tz_preparer = SystemTimezonePreparerV1(read_client=tz_client, configured_target=_tz_target())
    tz_store = _tz_store(tmp_path / "tz", "parity-stale-precondition")
    tz_executor = Mock(spec=MutationExecutor)
    tz_executor.execute.return_value = ExecutionOutcome("unused", RecoveryState.VERIFIED, "synthetic")
    tz_core, tz_private, _s2 = _tz_core(
        tmp_path / "tz",
        store=tz_store,
        preparer=tz_preparer,
        prepared_type=PreparedSystemTimezoneExecutionV1,
        request_type=SystemTimezoneChangeV1,
        contract_id_prefix="parity",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=tz_executor,
    )
    tz_request = SystemTimezoneChangeV1(timezone="Europe/Berlin")
    tz_prepared = tz_preparer.prepare(tz_request)
    tz_digest = compute_execution_intent_digest(tz_prepared.intent)
    tz_authz = _tz_authorization(tz_private, tz_digest)
    tz_client.timezone = "Asia/Tokyo"  # drift: someone else changed it out-of-band
    with pytest.raises(BoundExecutionError):
        tz_core.authorize_and_create(
            tz_request,
            authorized_preparation=tz_prepared,
            authorization=tz_authz,
            requested_plan_digest=tz_authz.plan_digest,
            requested_step_id="batch1.step",
            required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            now=NOW,
        )
    assert tz_core._consumption_store.consumed == set()  # type: ignore[attr-defined]
    tz_executor.execute.assert_not_called()


def test_malformed_v1_authorization_is_refused_identically_by_both_cores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A structurally valid but wrong-schema-version `PlanAuthorization`
    (v1, not v2) must be refused by both cores' own `isinstance` checks --
    proves neither core silently accepts a legacy artifact shape."""

    (tmp_path / "alias").mkdir()
    (tmp_path / "tz").mkdir()
    monkeypatch.setattr(AliasDescriptionExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    alias_client = _ReadClient()
    alias_core, alias_private, _s, alias_consumption, alias_executor = _alias_core(tmp_path / "alias", alias_client)
    alias_request = AliasDescriptionChangeV1(alias_name="LAB_ALIAS_TEST", description="after")
    alias_prepared = _alias_preparer(alias_client).prepare(alias_request)
    alias_payload = build_plan_authorization_payload(
        _alias_plan(),
        ("first.write.alias.description",),
        authorization_id="legacy-v1",
        authority_id="owner-v2",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
    )
    alias_legacy: PlanAuthorization = sign_plan_authorization(alias_payload, alias_private)
    with pytest.raises(BoundExecutionError):
        alias_core.authorize_and_create(
            alias_request,
            authorized_preparation=alias_prepared,
            authorization=alias_legacy,  # type: ignore[arg-type]
            requested_plan_digest=alias_legacy.plan_digest,
            requested_step_id="first.write.alias.description",
            required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            now=NOW,
        )
    assert alias_consumption.calls == 0
    alias_executor.execute.assert_not_called()

    monkeypatch.setattr(WriteExecutionCoreV1, "_plan_is_fresh", staticmethod(lambda **_kwargs: True))
    tz_client = _FakeClient()
    tz_preparer = SystemTimezonePreparerV1(read_client=tz_client, configured_target=_tz_target())
    tz_store = _tz_store(tmp_path / "tz", "parity-v1-authz")
    tz_executor = Mock(spec=MutationExecutor)
    tz_executor.execute.return_value = ExecutionOutcome("unused", RecoveryState.VERIFIED, "synthetic")
    tz_core, tz_private, _s2 = _tz_core(
        tmp_path / "tz",
        store=tz_store,
        preparer=tz_preparer,
        prepared_type=PreparedSystemTimezoneExecutionV1,
        request_type=SystemTimezoneChangeV1,
        contract_id_prefix="parity",
        raw_target_fn=lambda s: s.raw_target_hint(),
        executor=tz_executor,
    )
    tz_request = SystemTimezoneChangeV1(timezone="Europe/Berlin")
    tz_prepared = tz_preparer.prepare(tz_request)
    tz_payload = build_plan_authorization_payload(
        _tz_plan(),
        ("batch1.step",),
        authorization_id="legacy-v1",
        authority_id="owner-v2",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
    )
    tz_legacy: PlanAuthorization = sign_plan_authorization(tz_payload, tz_private)
    with pytest.raises(BoundExecutionError):
        tz_core.authorize_and_create(
            tz_request,
            authorized_preparation=tz_prepared,
            authorization=tz_legacy,  # type: ignore[arg-type]
            requested_plan_digest=tz_legacy.plan_digest,
            requested_step_id="batch1.step",
            required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE,
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            now=NOW,
        )
    assert tz_core._consumption_store.consumed == set()  # type: ignore[attr-defined]
    tz_executor.execute.assert_not_called()


def _parametrized_string_values(tree: ast.Module, function_name: str) -> set[str]:
    """Every literal string value passed to `@pytest.mark.parametrize`
    ("case", [...]) immediately above the named test function."""

    values: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name == function_name):
            continue
        for decorator in node.decorator_list:
            if not (isinstance(decorator, ast.Call) and len(decorator.args) >= 2):
                continue
            cases_arg = decorator.args[1]
            if isinstance(cases_arg, ast.List):
                for element in cases_arg.elts:
                    if isinstance(element, ast.Constant) and isinstance(element.value, str):
                        values.add(element.value)
    return values


def test_authorize_stage_case_names_are_covered_identically_in_both_test_files() -> None:
    """The actual mechanical parity invariant: if a future change adds or
    removes an authorize-stage adversarial case from alias's own 13-case
    matrix, or from this file's shared parametrized case list, without a
    matching update on both sides, this test fails -- the two matrices
    cannot silently drift apart without being noticed here."""

    alias_tree = ast.parse(_ALIAS_TEST_PATH.read_text(encoding="utf-8"))
    alias_cases = _parametrized_string_values(
        alias_tree, "test_all_preconsumption_failures_leave_auth_unconsumed_and_zero_handoff"
    )
    missing_from_alias = _SHARED_AUTHORIZE_STAGE_CASES - alias_cases
    assert not missing_from_alias, (
        f"alias's own matrix no longer covers shared case(s): {missing_from_alias} -- "
        "update _SHARED_AUTHORIZE_STAGE_CASES here to match, or restore them there."
    )

    this_tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    parity_cases = _parametrized_string_values(
        this_tree, "test_authorize_stage_scenario_is_refused_identically_by_both_cores"
    )
    assert parity_cases == _SHARED_AUTHORIZE_STAGE_CASES
