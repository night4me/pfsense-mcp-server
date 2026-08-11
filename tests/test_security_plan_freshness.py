"""Regression and adversarial tests for
`pfsense_mcp.security_plan_freshness` -- ADR-022 Phase E, Slice E1.
Establishes and adversarially tests the one invariant this slice adds:
freshness is exact `plan_digest` equality against a freshly regenerated
plan, computed exclusively via `compute_plan_digest()`/`verify_plan_digest()`,
never a weaker proxy. No authorization consumption, no executor, no
state-machine interaction anywhere in this module or these tests.
"""

from __future__ import annotations

import sqlite3

import pytest

import pfsense_mcp.security_plan_freshness as security_plan_freshness
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import (
    AuthorizationLevel,
    MutationClass,
    generate_security_posture_plan,
)
from pfsense_mcp.security_plan_digest import compute_plan_digest
from pfsense_mcp.security_plan_freshness import PlanFreshnessError, plan_authorization_is_fresh
from tests.test_security_discovery import (
    _WITNESS_ENV,
    _FakeAnchor,
    _patch_witness_anchor,
    _provisioned_store_env,
    _store_env,
)
from tests.test_security_plan_digest import _synthetic_plan, _synthetic_step

# ---------------------------------------------------------------------------
# 1. Real-discovery freshness: identical env -> same generated plan -> fresh
# ---------------------------------------------------------------------------


def test_identical_fresh_discovery_is_fresh(tmp_path):
    env = _store_env(tmp_path)
    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE, env)
    digest = compute_plan_digest(plan)

    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest=digest,
            env=env,
        )
        is True
    )


def test_real_hardware_witness_target_is_fresh_against_itself(tmp_path, monkeypatch):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))
    plan = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env)
    digest = compute_plan_digest(plan)

    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            expected_plan_digest=digest,
            env=env,
        )
        is True
    )


# ---------------------------------------------------------------------------
# 2. Changed evidence that changes the generated plan -> stale
# ---------------------------------------------------------------------------


def test_changed_evidence_produces_stale(tmp_path):
    dir_a = tmp_path / "a"
    dir_a.mkdir()
    env_a = _store_env(dir_a)
    plan_a = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE, env_a)
    digest_a = compute_plan_digest(plan_a)

    dir_b = tmp_path / "b"
    dir_b.mkdir()
    env_b = _provisioned_store_env(dir_b, value=2, handle="0x01500000")

    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest=digest_a,
            env=env_b,
        )
        is False
    )


def test_different_target_produces_stale(tmp_path):
    env = _store_env(tmp_path)
    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE, env)
    digest = compute_plan_digest(plan)

    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            expected_plan_digest=digest,
            env=env,
        )
        is False
    )


# ---------------------------------------------------------------------------
# 3. evidence_fingerprint-insufficiency: step-list changes must be caught
#    even when the fingerprint-relevant fields are unchanged
# ---------------------------------------------------------------------------


def _authorized_synthetic_plan():
    return _synthetic_plan(
        steps=(
            _synthetic_step(
                step_id="s1",
                order=1,
                mutation_class=MutationClass.CONFIGURATION,
                authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE,
            ),
        )
    )


def _patched_freshness(monkeypatch, fresh_plan):
    monkeypatch.setattr(security_plan_freshness, "generate_security_posture_plan", lambda *a, **k: fresh_plan)


def test_unchanged_evidence_fingerprint_but_added_step_is_stale(monkeypatch):
    authorized_plan = _authorized_synthetic_plan()
    expected_digest = compute_plan_digest(authorized_plan)

    widened_plan = _synthetic_plan(
        current=authorized_plan.current,
        steps=(
            *authorized_plan.steps,
            _synthetic_step(step_id="s2", order=2, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),
        ),
    )
    # Sanity: current/evidence-derived fields are identical; only steps differ.
    assert widened_plan.current == authorized_plan.current

    _patched_freshness(monkeypatch, widened_plan)
    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest=expected_digest,
        )
        is False
    )


def test_removed_step_is_stale(monkeypatch):
    authorized_plan = _synthetic_plan(
        steps=(
            _synthetic_step(step_id="s1", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),
            _synthetic_step(step_id="s2", order=2, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),
        )
    )
    expected_digest = compute_plan_digest(authorized_plan)

    narrowed_plan = _synthetic_plan(current=authorized_plan.current, steps=(authorized_plan.steps[0],))

    _patched_freshness(monkeypatch, narrowed_plan)
    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest=expected_digest,
        )
        is False
    )


def test_modified_step_is_stale(monkeypatch):
    authorized_plan = _authorized_synthetic_plan()
    expected_digest = compute_plan_digest(authorized_plan)

    modified_plan = _synthetic_plan(
        current=authorized_plan.current,
        steps=(
            _synthetic_step(
                step_id="s1", order=1, authorization_required=AuthorizationLevel.INTERACTIVE_HARDWARE_CONFIRMATION
            ),
        ),
    )

    _patched_freshness(monkeypatch, modified_plan)
    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest=expected_digest,
        )
        is False
    )


def test_same_named_step_with_materially_different_content_is_stale(monkeypatch):
    """The exact scenario evidence_fingerprint alone would miss: a step
    with the same step_id/order/axis but a different mutation_class."""

    authorized_plan = _authorized_synthetic_plan()
    expected_digest = compute_plan_digest(authorized_plan)

    retyped_plan = _synthetic_plan(
        current=authorized_plan.current,
        steps=(
            _synthetic_step(
                step_id="s1",
                order=1,
                mutation_class=MutationClass.DEACTIVATION,
                authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE,
            ),
        ),
    )

    _patched_freshness(monkeypatch, retyped_plan)
    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest=expected_digest,
        )
        is False
    )


def test_unchanged_plan_via_patch_is_fresh_control_case(monkeypatch):
    """Control case proving the patching harness itself is correct: an
    unmodified re-supply of the exact same plan is fresh."""

    authorized_plan = _authorized_synthetic_plan()
    expected_digest = compute_plan_digest(authorized_plan)

    _patched_freshness(monkeypatch, authorized_plan)
    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest=expected_digest,
        )
        is True
    )


# ---------------------------------------------------------------------------
# 4. Caller cannot supply/trust a digest instead of recomputing
# ---------------------------------------------------------------------------


def test_no_api_accepts_a_precomputed_fresh_digest():
    """Structural proof: the public function's only digest-shaped
    parameter is the *expected* value to compare against -- there is no
    parameter through which a caller could supply an already-computed
    'fresh' digest that bypasses recomputation."""

    import inspect

    signature = inspect.signature(plan_authorization_is_fresh)
    assert set(signature.parameters) == {
        "target_capability_posture",
        "target_anchor_assurance",
        "expected_plan_digest",
        "env",
    }


def test_no_api_accepts_a_prebuilt_plan_either():
    """A caller cannot substitute a fake plan object for the freshly
    discovered one -- no parameter is plan-shaped."""

    import inspect

    signature = inspect.signature(plan_authorization_is_fresh)
    assert "plan" not in signature.parameters
    assert "fresh_plan" not in signature.parameters


# ---------------------------------------------------------------------------
# 5. Malformed input handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "malformed",
    [None, 12345, b"ab" * 32, ["a", "b"], {}, "", "not-a-real-digest", "0" * 64],
)
def test_malformed_or_wrong_expected_digest_returns_false(tmp_path, malformed):
    env = _store_env(tmp_path)
    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest=malformed,
            env=env,
        )
        is False
    )


# ---------------------------------------------------------------------------
# 6. Discovery / plan-generation / digest-generation failure -> fail closed
# ---------------------------------------------------------------------------


def test_discovery_failure_raises_plan_freshness_error(monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("simulated discovery failure containing /secret/path")

    monkeypatch.setattr(security_plan_freshness, "generate_security_posture_plan", _boom)

    with pytest.raises(PlanFreshnessError) as excinfo:
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest="ab" * 32,
        )
    assert "secret" not in str(excinfo.value)
    assert "/path" not in str(excinfo.value)


def test_plan_generation_failure_raises_plan_freshness_error(monkeypatch):
    def _boom(*args, **kwargs):
        raise ValueError("simulated plan-generation failure")

    monkeypatch.setattr(security_plan_freshness, "generate_security_posture_plan", _boom)

    with pytest.raises(PlanFreshnessError):
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest="ab" * 32,
        )


def test_digest_generation_failure_raises_plan_freshness_error(monkeypatch):
    plan = _authorized_synthetic_plan()
    monkeypatch.setattr(security_plan_freshness, "generate_security_posture_plan", lambda *a, **k: plan)

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated digest-generation failure")

    monkeypatch.setattr(security_plan_freshness, "verify_plan_digest", _boom)

    with pytest.raises(PlanFreshnessError):
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest="ab" * 32,
        )


def test_indeterminate_current_state_does_not_raise_and_is_handled_by_digest_mismatch(tmp_path):
    """An indeterminate/anomalous *current* evidence state is not a
    Python exception in this codebase's own discovery layer (it is a
    typed, non-raising outcome, e.g. PlanOverallStatus.BLOCKED_*) -- so
    it is naturally caught here as an ordinary digest mismatch (False),
    never a PlanFreshnessError, matching the layer it builds on."""

    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    malformed_store = store_dir / "anchor.sqlite3"
    malformed_store.write_bytes(b"not a sqlite database")
    key_file = tmp_path / "key" / "integrity.json"
    key_file.parent.mkdir(mode=0o700)
    key_file.write_text('{"key_id": "x", "epoch": 0, "material_hex": "' + "ab" * 32 + '"}')
    env = {"PFSENSE_TIER1_STORE_PATH": str(malformed_store), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)}

    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.HARDWARE_WITNESS,
            expected_plan_digest="ab" * 32,
            env=env,
        )
        is False
    )


# ---------------------------------------------------------------------------
# 7. No second digest/canonicalization path
# ---------------------------------------------------------------------------


def test_alternate_or_reconstructed_digest_never_matches_without_recomputation(tmp_path):
    """A caller who tries to precompute a digest 'the same way' by
    calling compute_plan_digest() themselves against a slightly
    different (but semantically-intended-to-be-equivalent) plan object
    gets no special treatment -- only exact recomputation against the
    real fresh plan can match."""

    env = _store_env(tmp_path)
    real_plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE, env)
    real_digest = compute_plan_digest(real_plan)

    # A plausible-looking but not-actually-fresh reconstruction (synthetic,
    # not from real discovery) must not be accepted as if it were real.
    lookalike = _synthetic_plan(steps=())
    lookalike_digest = compute_plan_digest(lookalike)
    assert lookalike_digest != real_digest

    assert (
        plan_authorization_is_fresh(
            target_capability_posture=CapabilityPosture.READ_ONLY,
            target_anchor_assurance=AnchorAssurance.NONE,
            expected_plan_digest=lookalike_digest,
            env=env,
        )
        is False
    )


def test_module_defines_no_second_digest_or_canonicalization_function():
    import inspect

    source = inspect.getsource(security_plan_freshness)
    for forbidden in ("hashlib.sha256(", "json.dumps(", "def compute_plan_digest", "def canonical_json"):
        assert forbidden not in source


# ---------------------------------------------------------------------------
# 8. No authorization-consumption / executor / state-machine side effects
# ---------------------------------------------------------------------------


def test_freshness_check_performs_no_sqlite_access_beyond_discovery(monkeypatch):
    """With no store configured (env={}), discovery itself touches no
    SQLite file -- confirming this module adds no I/O of its own beyond
    whatever generate_security_posture_plan() already legitimately
    performs."""

    def _boom_sqlite(*args, **kwargs):
        raise AssertionError("security_plan_freshness must perform no SQLite I/O of its own.")

    monkeypatch.setattr(sqlite3, "connect", _boom_sqlite)

    plan_authorization_is_fresh(
        target_capability_posture=CapabilityPosture.READ_ONLY,
        target_anchor_assurance=AnchorAssurance.NONE,
        expected_plan_digest="ab" * 32,
        env={},
    )


def test_freshness_check_never_mutates_the_module_globals_or_env_dict(tmp_path):
    env = _store_env(tmp_path)
    original_env = dict(env)
    plan_authorization_is_fresh(
        target_capability_posture=CapabilityPosture.READ_ONLY,
        target_anchor_assurance=AnchorAssurance.NONE,
        expected_plan_digest="ab" * 32,
        env=env,
    )
    assert env == original_env
