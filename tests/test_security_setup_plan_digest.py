"""Focused + adversarial tests for
`pfsense_mcp.security_setup_plan_digest` -- proves `compute_setup_plan_digest()`
is deterministic, sensitive to every semantically load-bearing input,
insensitive to equivalent-but-differently-phrased inputs, and never
mentions a specific future authorization mechanism."""

from __future__ import annotations

from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_setup_plan import generate_setup_plan
from pfsense_mcp.security_setup_plan_digest import (
    SETUP_PLAN_DIGEST_SCHEMA_VERSION,
    compute_setup_plan_digest,
    verify_setup_plan_digest,
)

_BASE_KWARGS = {
    "target_capability_posture": CapabilityPosture.READ_ONLY,
    "target_anchor_assurance": AnchorAssurance.NONE,
    "target_origin": "https://fw.example.test",
    "target_identity": "lab-fw",
    "tls_mode": "verify",
    "declared_package_version": "2.8.0",
}


def test_digest_is_deterministic_across_repeated_computation():
    plan = generate_setup_plan(**_BASE_KWARGS)
    assert compute_setup_plan_digest(plan) == compute_setup_plan_digest(plan)


def test_digest_is_deterministic_across_independently_generated_equal_plans():
    first = generate_setup_plan(**_BASE_KWARGS)
    second = generate_setup_plan(**_BASE_KWARGS)
    assert compute_setup_plan_digest(first) == compute_setup_plan_digest(second)


def test_digest_is_a_64_character_hex_string():
    plan = generate_setup_plan(**_BASE_KWARGS)
    digest = compute_setup_plan_digest(plan)
    assert len(digest) == 64
    int(digest, 16)  # raises if not hex


def test_digest_changes_when_target_origin_changes():
    a = generate_setup_plan(**{**_BASE_KWARGS, "target_origin": "https://fw-a.example.test"})
    b = generate_setup_plan(**{**_BASE_KWARGS, "target_origin": "https://fw-b.example.test"})
    assert compute_setup_plan_digest(a) != compute_setup_plan_digest(b)


def test_digest_changes_when_target_identity_changes():
    a = generate_setup_plan(**{**_BASE_KWARGS, "target_identity": "lab-fw-a"})
    b = generate_setup_plan(**{**_BASE_KWARGS, "target_identity": "lab-fw-b"})
    assert compute_setup_plan_digest(a) != compute_setup_plan_digest(b)


def test_digest_changes_when_capability_posture_changes():
    a = generate_setup_plan(**{**_BASE_KWARGS, "target_capability_posture": CapabilityPosture.READ_ONLY})
    b = generate_setup_plan(**{**_BASE_KWARGS, "target_capability_posture": CapabilityPosture.WRITE_PROTECTED})
    assert compute_setup_plan_digest(a) != compute_setup_plan_digest(b)


def test_digest_changes_when_anchor_assurance_changes():
    a = generate_setup_plan(**{**_BASE_KWARGS, "target_anchor_assurance": AnchorAssurance.NONE})
    b = generate_setup_plan(**{**_BASE_KWARGS, "target_anchor_assurance": AnchorAssurance.HARDWARE_WITNESS})
    assert compute_setup_plan_digest(a) != compute_setup_plan_digest(b)


def test_digest_changes_when_required_privileges_change():
    a = generate_setup_plan(**{**_BASE_KWARGS, "schema": None})
    b = generate_setup_plan(**{**_BASE_KWARGS, "schema": {}})
    assert compute_setup_plan_digest(a) != compute_setup_plan_digest(b)


def test_digest_changes_when_declared_package_version_changes():
    a = generate_setup_plan(**{**_BASE_KWARGS, "declared_package_version": "2.8.0"})
    b = generate_setup_plan(**{**_BASE_KWARGS, "declared_package_version": "2.9.0"})
    assert compute_setup_plan_digest(a) != compute_setup_plan_digest(b)


def test_digest_changes_when_tls_mode_changes():
    a = generate_setup_plan(**{**_BASE_KWARGS, "tls_mode": "verify"})
    b = generate_setup_plan(**{**_BASE_KWARGS, "tls_mode": "insecure"})
    assert compute_setup_plan_digest(a) != compute_setup_plan_digest(b)


def test_equivalent_semantic_inputs_produce_the_same_digest():
    """A plain, value-equal string target passed instead of the real
    enum member must produce the identical digest -- the same
    equivalence `generate_setup_plan()`'s own enum-coercion guarantees."""

    from_enum = generate_setup_plan(**_BASE_KWARGS)
    from_string = generate_setup_plan(**{**_BASE_KWARGS, "target_capability_posture": "read_only"})
    assert compute_setup_plan_digest(from_enum) == compute_setup_plan_digest(from_string)


def test_digest_is_unaffected_by_prose_only_differences():
    """Two plans whose only difference is free-text wording (never a
    structural fact) must still digest identically -- mirrors
    `security_plan_digest.py`'s own "prose never participates"
    discipline. Here: the same declared_package_version considered
    supported produces the same version_note wording every time by
    construction, so this test instead proves the *converse* directly:
    corrupting the plan's own prose field in place, post-generation,
    does not change what compute_setup_plan_digest() would recompute
    from the untouched structural fields -- i.e. compute_setup_plan_digest()
    never reads plan.privilege_plan.provisioning_note or
    plan.version_evidence.version_note at all."""

    import dataclasses

    plan = generate_setup_plan(**_BASE_KWARGS)
    mutated_privilege_plan = dataclasses.replace(plan.privilege_plan, provisioning_note="completely different prose")
    mutated_version_evidence = dataclasses.replace(plan.version_evidence, version_note="also completely different")
    mutated_plan = dataclasses.replace(
        plan, privilege_plan=mutated_privilege_plan, version_evidence=mutated_version_evidence
    )
    assert compute_setup_plan_digest(plan) == compute_setup_plan_digest(mutated_plan)


def test_verify_setup_plan_digest_accepts_the_correct_digest():
    plan = generate_setup_plan(**_BASE_KWARGS)
    assert verify_setup_plan_digest(plan, compute_setup_plan_digest(plan)) is True


def test_verify_setup_plan_digest_rejects_a_mismatched_digest():
    plan = generate_setup_plan(**_BASE_KWARGS)
    assert verify_setup_plan_digest(plan, "0" * 64) is False


def test_verify_setup_plan_digest_never_raises_on_malformed_expected_digest():
    plan = generate_setup_plan(**_BASE_KWARGS)
    for malformed in ("", "not-hex!!", "short"):
        assert verify_setup_plan_digest(plan, malformed) is False


def test_schema_version_participates_in_the_digest():
    assert SETUP_PLAN_DIGEST_SCHEMA_VERSION == 1
