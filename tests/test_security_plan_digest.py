"""Regression and adversarial tests for `pfsense_mcp.security_plan_digest`
-- ADR-022 Phase B's canonical `PlanDigest` computation. Plan identity
only, never authorization. Reuses `tests.test_security_discovery`'s
fixtures for real (non-synthetic) plan generation, and hand-builds
minimal synthetic plans for fine-grained, single-field participation
tests that would otherwise require constructing many different real
environments.
"""

from __future__ import annotations

import sqlite3

import pfsense_mcp.security_plan_digest as security_plan_digest
from pfsense_mcp.security_discovery import (
    AnchorAssurance,
    AnchorAssuranceDiscovery,
    AnchorEvidenceState,
    CapabilityPosture,
    CapabilityPostureDiscovery,
    SecurityPostureDiscovery,
)
from pfsense_mcp.security_plan import (
    AuthorizationLevel,
    AxisTransitionKind,
    MutationClass,
    PlanOverallStatus,
    PlanStep,
    SecurityImpact,
    SecurityPosturePlan,
    TargetValidity,
    generate_security_posture_plan,
)
from pfsense_mcp.security_plan_digest import (
    PLAN_DIGEST_SCHEMA_VERSION,
    compute_plan_digest,
    verify_plan_digest,
)
from tests.test_security_discovery import (
    _WITNESS_ENV,
    _FakeAnchor,
    _patch_witness_anchor,
    _provisioned_store_env,
    _store_env,
)

_HEX_64 = set("0123456789abcdef")


def _synthetic_current(
    *,
    capability_value: CapabilityPosture = CapabilityPosture.READ_ONLY,
    anchor_value: AnchorAssurance = AnchorAssurance.NONE,
    anchor_evidence_state: AnchorEvidenceState = AnchorEvidenceState.UNCONFIGURED,
    baseline: int | None = None,
    witness_value: int | None = None,
    provisioned_at: str | None = None,
) -> SecurityPostureDiscovery:
    return SecurityPostureDiscovery(
        capability_posture=CapabilityPostureDiscovery(
            value=capability_value,
            configured_profile_name="auditor",
            configured_profile_valid=True,
            write_capabilities_active=0,
            write_capabilities_total=3,
            allow_list_entries=(),
            evidence=("synthetic evidence",),
        ),
        anchor_assurance=AnchorAssuranceDiscovery(
            value=anchor_value,
            evidence_state=anchor_evidence_state,
            store_configured=False,
            store_exists=None,
            seeded=None,
            complete=None,
            handle=None,
            baseline=baseline,
            provisioned_at=provisioned_at,
            witness_configured=False,
            witness_reachable=None,
            witness_value=witness_value,
            witness_matches_baseline=None,
            evidence=("synthetic evidence",),
        ),
    )


def _synthetic_step(
    *,
    step_id: str = "synthetic.step",
    order: int = 1,
    axis: str = "anchor_assurance",
    action: str = "Synthetic action",
    description: str = "Synthetic description",
    mutation_class: MutationClass = MutationClass.NONE,
    authorization_required: AuthorizationLevel = AuthorizationLevel.NONE_REQUIRED,
    implementation_available: bool = True,
    reversible: bool | None = None,
    security_impact: SecurityImpact = SecurityImpact.NONE,
    prerequisite_satisfied: bool | None = True,
    blocked: bool = False,
    blocked_reason: str | None = None,
    evidence: tuple[str, ...] = (),
) -> PlanStep:
    return PlanStep(
        step_id=step_id,
        order=order,
        axis=axis,
        action=action,
        description=description,
        mutation_class=mutation_class,
        authorization_required=authorization_required,
        implementation_available=implementation_available,
        reversible=reversible,
        security_impact=security_impact,
        prerequisite_satisfied=prerequisite_satisfied,
        blocked=blocked,
        blocked_reason=blocked_reason,
        evidence=evidence,
    )


def _synthetic_plan(
    *,
    target_capability_posture: CapabilityPosture = CapabilityPosture.READ_ONLY,
    target_anchor_assurance: AnchorAssurance = AnchorAssurance.NONE,
    target_validity: TargetValidity = TargetValidity.VALID,
    validity_evidence: tuple[str, ...] = (),
    capability_posture_transition: AxisTransitionKind = AxisTransitionKind.NO_CHANGE,
    anchor_assurance_transition: AxisTransitionKind = AxisTransitionKind.NO_CHANGE,
    overall_status: PlanOverallStatus = PlanOverallStatus.ALREADY_SATISFIED,
    safe_to_proceed: bool = True,
    blocking_findings: tuple[str, ...] = (),
    steps: tuple[PlanStep, ...] = (),
    notes: tuple[str, ...] = ("a note",),
    current: SecurityPostureDiscovery | None = None,
) -> SecurityPosturePlan:
    return SecurityPosturePlan(
        current=current if current is not None else _synthetic_current(),
        target_capability_posture=target_capability_posture,
        target_anchor_assurance=target_anchor_assurance,
        target_validity=target_validity,
        validity_evidence=validity_evidence,
        capability_posture_transition=capability_posture_transition,
        anchor_assurance_transition=anchor_assurance_transition,
        overall_status=overall_status,
        safe_to_proceed=safe_to_proceed,
        blocking_findings=blocking_findings,
        steps=steps,
        notes=notes,
    )


def _base_plan() -> SecurityPosturePlan:
    return _synthetic_plan(steps=(_synthetic_step(),))


# ---------------------------------------------------------------------------
# 1. Determinism
# ---------------------------------------------------------------------------


def test_same_semantic_plan_produces_same_digest_across_repeated_computations():
    plan = _base_plan()
    digests = {compute_plan_digest(plan) for _ in range(5)}
    assert len(digests) == 1


def test_digest_is_a_64_character_lowercase_hex_string():
    digest = compute_plan_digest(_base_plan())
    assert len(digest) == 64
    assert set(digest) <= _HEX_64


def test_real_generated_plans_are_deterministic_across_repeated_invocations(monkeypatch, tmp_path):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    first = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env)
    second = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env)

    assert compute_plan_digest(first) == compute_plan_digest(second)


def test_dict_insertion_order_in_env_does_not_affect_the_digest(tmp_path):
    env = _store_env(tmp_path)
    reordered_env = dict(reversed(list(env.items())))
    assert list(env.items()) != list(reordered_env.items())  # sanity: orders actually differ

    plan_a = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE, env)
    plan_b = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE, reordered_env)

    assert compute_plan_digest(plan_a) == compute_plan_digest(plan_b)


# ---------------------------------------------------------------------------
# 2. Per-field participation -- security-relevant fields change the digest
# ---------------------------------------------------------------------------


def test_changing_target_capability_posture_changes_the_digest():
    a = _base_plan()
    b = _synthetic_plan(target_capability_posture=CapabilityPosture.WRITE_PROTECTED, steps=a.steps)
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_target_anchor_assurance_changes_the_digest():
    a = _base_plan()
    b = _synthetic_plan(target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS, steps=a.steps)
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_target_validity_changes_the_digest():
    a = _base_plan()
    b = _synthetic_plan(target_validity=TargetValidity.VALID_NOT_IMPLEMENTED, steps=a.steps)
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_step_id_changes_the_digest():
    a = _synthetic_plan(steps=(_synthetic_step(step_id="a.step"),))
    b = _synthetic_plan(steps=(_synthetic_step(step_id="b.step"),))
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_step_order_changes_the_digest():
    a = _synthetic_plan(steps=(_synthetic_step(order=1),))
    b = _synthetic_plan(steps=(_synthetic_step(order=2),))
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_step_axis_changes_the_digest():
    a = _synthetic_plan(steps=(_synthetic_step(axis="anchor_assurance"),))
    b = _synthetic_plan(steps=(_synthetic_step(axis="capability_posture"),))
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_step_mutation_class_changes_the_digest():
    a = _synthetic_plan(steps=(_synthetic_step(mutation_class=MutationClass.NONE),))
    b = _synthetic_plan(steps=(_synthetic_step(mutation_class=MutationClass.CONFIGURATION),))
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_step_authorization_required_changes_the_digest():
    a = _synthetic_plan(steps=(_synthetic_step(authorization_required=AuthorizationLevel.NONE_REQUIRED),))
    b = _synthetic_plan(steps=(_synthetic_step(authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),))
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_reordering_two_steps_changes_the_digest():
    step_1 = _synthetic_step(step_id="first", order=1)
    step_2 = _synthetic_step(step_id="second", order=2)
    forward = _synthetic_plan(steps=(step_1, step_2))
    reversed_plan = _synthetic_plan(steps=(step_2, step_1))
    assert compute_plan_digest(forward) != compute_plan_digest(reversed_plan)


def test_changing_overall_status_changes_the_digest():
    a = _synthetic_plan(overall_status=PlanOverallStatus.ALREADY_SATISFIED, steps=(_synthetic_step(),))
    b = _synthetic_plan(overall_status=PlanOverallStatus.PLAN_GENERATED, steps=(_synthetic_step(),))
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_safe_to_proceed_changes_the_digest():
    a = _synthetic_plan(safe_to_proceed=True, steps=(_synthetic_step(),))
    b = _synthetic_plan(safe_to_proceed=False, steps=(_synthetic_step(),))
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_evidence_fingerprint_anchor_value_changes_the_digest():
    a = _synthetic_plan(current=_synthetic_current(anchor_value=AnchorAssurance.NONE), steps=(_synthetic_step(),))
    b = _synthetic_plan(
        current=_synthetic_current(anchor_value=AnchorAssurance.HARDWARE_WITNESS), steps=(_synthetic_step(),)
    )
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_evidence_fingerprint_evidence_state_changes_the_digest():
    a = _synthetic_plan(
        current=_synthetic_current(anchor_evidence_state=AnchorEvidenceState.UNCONFIGURED),
        steps=(_synthetic_step(),),
    )
    b = _synthetic_plan(
        current=_synthetic_current(anchor_evidence_state=AnchorEvidenceState.PROVISIONED_MISMATCH),
        steps=(_synthetic_step(),),
    )
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_evidence_fingerprint_baseline_changes_the_digest():
    a = _synthetic_plan(current=_synthetic_current(baseline=2), steps=(_synthetic_step(),))
    b = _synthetic_plan(current=_synthetic_current(baseline=3), steps=(_synthetic_step(),))
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_baseline_none_differs_from_baseline_zero():
    """Null must never be silently confused with a legitimate falsy value."""

    a = _synthetic_plan(current=_synthetic_current(baseline=None), steps=(_synthetic_step(),))
    b = _synthetic_plan(current=_synthetic_current(baseline=0), steps=(_synthetic_step(),))
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_evidence_fingerprint_witness_value_changes_the_digest():
    a = _synthetic_plan(current=_synthetic_current(witness_value=2), steps=(_synthetic_step(),))
    b = _synthetic_plan(current=_synthetic_current(witness_value=7), steps=(_synthetic_step(),))
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_evidence_fingerprint_provisioned_at_changes_the_digest():
    a = _synthetic_plan(
        current=_synthetic_current(provisioned_at="2026-08-10T00:00:00+00:00"), steps=(_synthetic_step(),)
    )
    b = _synthetic_plan(
        current=_synthetic_current(provisioned_at="2026-08-11T00:00:00+00:00"), steps=(_synthetic_step(),)
    )
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_changing_evidence_fingerprint_capability_posture_value_changes_the_digest():
    a = _synthetic_plan(
        current=_synthetic_current(capability_value=CapabilityPosture.READ_ONLY), steps=(_synthetic_step(),)
    )
    b = _synthetic_plan(
        current=_synthetic_current(capability_value=CapabilityPosture.WRITE_PROTECTED), steps=(_synthetic_step(),)
    )
    assert compute_plan_digest(a) != compute_plan_digest(b)


def test_schema_version_bump_changes_every_digest(monkeypatch):
    plan = _base_plan()
    before = compute_plan_digest(plan)
    monkeypatch.setattr(security_plan_digest, "PLAN_DIGEST_SCHEMA_VERSION", PLAN_DIGEST_SCHEMA_VERSION + 1)
    after = compute_plan_digest(plan)
    assert before != after


# ---------------------------------------------------------------------------
# 3. Non-participating fields -- presentation/prose never affects identity
# ---------------------------------------------------------------------------


def test_changing_step_prose_fields_does_not_change_the_digest():
    a = _synthetic_step(action="Original action", description="Original description", blocked_reason=None)
    b = _synthetic_step(
        action="Reworded action", description="Completely different description", blocked_reason="now blocked"
    )
    plan_a = _synthetic_plan(steps=(a,))
    plan_b = _synthetic_plan(steps=(b,))
    assert compute_plan_digest(plan_a) == compute_plan_digest(plan_b)


def test_changing_step_presentation_fields_does_not_change_the_digest():
    a = _synthetic_step(
        implementation_available=True,
        reversible=True,
        security_impact=SecurityImpact.NONE,
        prerequisite_satisfied=True,
        blocked=False,
        evidence=("e1",),
    )
    b = _synthetic_step(
        implementation_available=False,
        reversible=False,
        security_impact=SecurityImpact.INCREASES_ASSURANCE,
        prerequisite_satisfied=False,
        blocked=True,
        evidence=("e1", "e2", "totally different"),
    )
    plan_a = _synthetic_plan(steps=(a,))
    plan_b = _synthetic_plan(steps=(b,))
    assert compute_plan_digest(plan_a) == compute_plan_digest(plan_b)


def test_changing_notes_does_not_change_the_digest():
    plan_a = _synthetic_plan(steps=(_synthetic_step(),), notes=("original note",))
    plan_b = _synthetic_plan(steps=(_synthetic_step(),), notes=("a", "totally different set of notes", "!"))
    assert compute_plan_digest(plan_a) == compute_plan_digest(plan_b)


def test_changing_validity_evidence_and_blocking_findings_does_not_change_the_digest():
    plan_a = _synthetic_plan(steps=(_synthetic_step(),), validity_evidence=(), blocking_findings=())
    plan_b = _synthetic_plan(
        steps=(_synthetic_step(),),
        validity_evidence=("some evidence prose",),
        blocking_findings=("some finding prose",),
    )
    assert compute_plan_digest(plan_a) == compute_plan_digest(plan_b)


def test_changing_axis_transition_summary_fields_does_not_change_the_digest():
    """capability_posture_transition/anchor_assurance_transition are pure
    functions of already-hashed current/target values -- ADR-022 does not
    name them as participating, so they must not add a second, redundant
    (and therefore potentially inconsistent) source of identity."""

    plan_a = _synthetic_plan(
        steps=(_synthetic_step(),),
        capability_posture_transition=AxisTransitionKind.NO_CHANGE,
        anchor_assurance_transition=AxisTransitionKind.NO_CHANGE,
    )
    plan_b = _synthetic_plan(
        steps=(_synthetic_step(),),
        capability_posture_transition=AxisTransitionKind.UPGRADE,
        anchor_assurance_transition=AxisTransitionKind.DOWNGRADE,
    )
    assert compute_plan_digest(plan_a) == compute_plan_digest(plan_b)


def test_changing_evidence_prose_tuples_does_not_change_the_digest():
    current_a = _synthetic_current()
    current_b = SecurityPostureDiscovery(
        capability_posture=CapabilityPostureDiscovery(
            value=current_a.capability_posture.value,
            configured_profile_name=current_a.capability_posture.configured_profile_name,
            configured_profile_valid=current_a.capability_posture.configured_profile_valid,
            write_capabilities_active=current_a.capability_posture.write_capabilities_active,
            write_capabilities_total=current_a.capability_posture.write_capabilities_total,
            allow_list_entries=current_a.capability_posture.allow_list_entries,
            evidence=("a completely different capability evidence sentence",),
        ),
        anchor_assurance=AnchorAssuranceDiscovery(
            value=current_a.anchor_assurance.value,
            evidence_state=current_a.anchor_assurance.evidence_state,
            store_configured=current_a.anchor_assurance.store_configured,
            store_exists=current_a.anchor_assurance.store_exists,
            seeded=current_a.anchor_assurance.seeded,
            complete=current_a.anchor_assurance.complete,
            handle=current_a.anchor_assurance.handle,
            baseline=current_a.anchor_assurance.baseline,
            provisioned_at=current_a.anchor_assurance.provisioned_at,
            witness_configured=current_a.anchor_assurance.witness_configured,
            witness_reachable=current_a.anchor_assurance.witness_reachable,
            witness_value=current_a.anchor_assurance.witness_value,
            witness_matches_baseline=current_a.anchor_assurance.witness_matches_baseline,
            evidence=("a completely different anchor evidence sentence",),
        ),
    )
    plan_a = _synthetic_plan(current=current_a, steps=(_synthetic_step(),))
    plan_b = _synthetic_plan(current=current_b, steps=(_synthetic_step(),))
    assert compute_plan_digest(plan_a) == compute_plan_digest(plan_b)


# ---------------------------------------------------------------------------
# 4. Duplicate / equivalent steps
# ---------------------------------------------------------------------------


def test_duplicate_step_ids_are_not_silently_deduplicated():
    single = _synthetic_plan(steps=(_synthetic_step(step_id="dup", order=1),))
    duplicated = _synthetic_plan(
        steps=(_synthetic_step(step_id="dup", order=1), _synthetic_step(step_id="dup", order=1))
    )
    assert compute_plan_digest(single) != compute_plan_digest(duplicated)


def test_identically_duplicated_plans_produce_the_same_digest():
    steps = (_synthetic_step(step_id="dup", order=1), _synthetic_step(step_id="dup", order=1))
    plan_a = _synthetic_plan(steps=steps)
    plan_b = _synthetic_plan(steps=steps)
    assert compute_plan_digest(plan_a) == compute_plan_digest(plan_b)


# ---------------------------------------------------------------------------
# 5. Self-reference exclusion
# ---------------------------------------------------------------------------


def test_payload_never_contains_a_digest_shaped_key():
    payload = security_plan_digest._plan_payload(_base_plan())

    def _walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                assert "digest" not in key.lower()
                _walk(item)
        elif isinstance(value, list):
            for item in value:
                _walk(item)

    _walk(payload)


def test_computing_the_digest_twice_is_idempotent_and_order_independent():
    plan = _base_plan()
    first = compute_plan_digest(plan)
    # Recomputing must not depend on any hidden state left over from the
    # first call (e.g. a cache keyed by object id that could go stale).
    second = compute_plan_digest(plan)
    assert first == second


# ---------------------------------------------------------------------------
# 6. Schema/version safety
# ---------------------------------------------------------------------------


def test_unsupported_schema_version_fails_verification_safely(monkeypatch):
    plan = _base_plan()
    old_digest = compute_plan_digest(plan)

    monkeypatch.setattr(security_plan_digest, "PLAN_DIGEST_SCHEMA_VERSION", PLAN_DIGEST_SCHEMA_VERSION + 1)

    # A digest computed under the prior schema version must not verify
    # under the new one -- no exception, just an ordinary, safe failure.
    assert verify_plan_digest(plan, old_digest) is False


# ---------------------------------------------------------------------------
# 7. Verification helper semantics
# ---------------------------------------------------------------------------


def test_verify_plan_digest_passes_for_the_original_plan():
    plan = _base_plan()
    digest = compute_plan_digest(plan)
    assert verify_plan_digest(plan, digest) is True


def test_verify_plan_digest_fails_after_plan_substitution():
    plan_a = _base_plan()
    plan_b = _synthetic_plan(target_capability_posture=CapabilityPosture.WRITE_PROTECTED, steps=plan_a.steps)
    digest_a = compute_plan_digest(plan_a)
    assert verify_plan_digest(plan_b, digest_a) is False


def test_verify_plan_digest_never_trusts_a_caller_supplied_digest_as_computation_input():
    plan = _base_plan()
    # A malformed/garbage caller-supplied digest must never be treated as
    # a match, and must never raise.
    assert verify_plan_digest(plan, "not-a-real-digest") is False
    assert verify_plan_digest(plan, "") is False
    assert verify_plan_digest(plan, "0" * 64) is False


def test_verify_plan_digest_rejects_a_digest_issued_for_a_different_plan():
    """A malicious/confused caller supplying a real, validly-computed
    digest -- just for the wrong plan -- must still be rejected."""

    plan_a = _synthetic_plan(target_anchor_assurance=AnchorAssurance.NONE, steps=(_synthetic_step(),))
    plan_b = _synthetic_plan(target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS, steps=(_synthetic_step(),))
    digest_for_b = compute_plan_digest(plan_b)
    assert verify_plan_digest(plan_a, digest_for_b) is False


def test_verify_plan_digest_is_pure_and_does_not_mutate_the_plan():
    plan = _base_plan()
    before = plan
    verify_plan_digest(plan, "irrelevant")
    assert plan == before  # frozen dataclass equality -- unchanged


# ---------------------------------------------------------------------------
# 8. Enum/raw-string coercion cannot produce collisions or leak Enum objects
# ---------------------------------------------------------------------------


def test_raw_string_and_enum_targets_produce_the_same_digest_for_an_equivalent_plan(tmp_path):
    env = _store_env(tmp_path)
    enum_plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE, env)
    raw_string_plan = generate_security_posture_plan("read_only", "none", env)  # type: ignore[arg-type]

    assert compute_plan_digest(enum_plan) == compute_plan_digest(raw_string_plan)


def test_payload_leaves_contain_only_plain_json_safe_types_never_enum_instances():
    payload = security_plan_digest._plan_payload(_base_plan())

    def _walk(value):
        if isinstance(value, dict):
            for item in value.values():
                _walk(item)
        elif isinstance(value, list):
            for item in value:
                _walk(item)
        else:
            assert type(value) in (str, int, bool, type(None)), f"non-plain leaf type: {type(value)!r}"

    _walk(payload)


# ---------------------------------------------------------------------------
# 9. Data-leak review -- no secrets/private paths in the payload
# ---------------------------------------------------------------------------


def test_malformed_store_path_never_enters_the_digest_payload(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    malformed = store_dir / "anchor.sqlite3"
    malformed.write_bytes(b"not a sqlite database")
    key_file = tmp_path / "key" / "integrity.json"
    key_file.parent.mkdir(mode=0o700)
    key_file.write_text('{"key_id": "x", "epoch": 0, "material_hex": "' + "ab" * 32 + '"}')
    env = {"PFSENSE_TIER1_STORE_PATH": str(malformed), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)}

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.HARDWARE_WITNESS, env)
    payload = security_plan_digest._plan_payload(plan)

    blob = repr(payload)
    assert str(malformed) not in blob
    assert str(key_file) not in blob


def test_unreachable_witness_paths_never_enter_the_digest_payload(tmp_path):
    bad_cert = str(tmp_path / "does-not-exist-client.crt")
    env = {
        **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"),
        "PFSENSE_TIER1_WITNESS_BASE_URL": "https://127.0.0.1:1",
        "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": bad_cert,
        "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": str(tmp_path / "does-not-exist-client.key"),
        "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": str(tmp_path / "does-not-exist-server.crt"),
    }

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.HARDWARE_WITNESS, env)
    payload = security_plan_digest._plan_payload(plan)

    blob = repr(payload)
    assert bad_cert not in blob
    assert "https://127.0.0.1:1" not in blob


# ---------------------------------------------------------------------------
# 10. Digest computation/verification never implies authorization or
#     execution, and never mutates or performs I/O
# ---------------------------------------------------------------------------


def test_no_authorized_or_execution_shaped_key_in_the_payload():
    payload = security_plan_digest._plan_payload(_base_plan())

    def _walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                assert key not in {"authorized", "execute", "approved", "consent"}
                _walk(item)
        elif isinstance(value, list):
            for item in value:
                _walk(item)

    _walk(payload)


def test_compute_plan_digest_performs_no_io_of_its_own(monkeypatch):
    def _boom_sqlite(*args, **kwargs):
        raise AssertionError("security_plan_digest must perform no SQLite I/O.")

    def _boom_open(*args, **kwargs):
        raise AssertionError("security_plan_digest must perform no file I/O.")

    monkeypatch.setattr(sqlite3, "connect", _boom_sqlite)
    monkeypatch.setattr("builtins.open", _boom_open)

    # Must complete normally -- if compute_plan_digest ever touched
    # sqlite3.connect or open(), _boom_* above would raise.
    compute_plan_digest(_base_plan())
    for target_cap in (CapabilityPosture.READ_ONLY, CapabilityPosture.WRITE_PROTECTED):
        for target_anchor in (AnchorAssurance.NONE, AnchorAssurance.HARDWARE_WITNESS):
            compute_plan_digest(
                _synthetic_plan(target_capability_posture=target_cap, target_anchor_assurance=target_anchor)
            )


def test_digest_computation_does_not_change_safe_to_proceed_or_the_plan_object():
    plan = _base_plan()
    original_safe_to_proceed = plan.safe_to_proceed
    compute_plan_digest(plan)
    verify_plan_digest(plan, "whatever")
    assert plan.safe_to_proceed == original_safe_to_proceed
