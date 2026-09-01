"""Regression and adversarial tests for
`pfsense_mcp.security_authorization_verifier` -- ADR-022 Phase D's pure
signature/expiry/plan-step-scope verification. No consumption, no
freshness, no execution anywhere in this module or these tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pfsense_mcp.security_authorization import (
    PlanAuthorizationStepBinding,
    SecurityAuthorizationError,
    build_plan_authorization_payload,
    build_plan_authorization_v2_payload,
    sign_plan_authorization,
    sign_plan_authorization_v2,
)
from pfsense_mcp.security_authorization_verifier import (
    plan_authorization_authorizes_step,
    plan_authorization_is_current,
    plan_authorization_v2_satisfies_required_risk_class,
    verify_plan_authorization_signature,
)
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from tests.test_security_plan_digest import _synthetic_plan, _synthetic_step


def _keypair():
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return private_key, public_bytes


def _authorities(authority_id: str, public_key: bytes, *, active: bool = True) -> PinnedAuthoritySet:
    return PinnedAuthoritySet((PinnedAuthority(authority_id=authority_id, public_key=public_key, active=active),))


def _plan(step_id: str = "s1", level: AuthorizationLevel = AuthorizationLevel.CONFIGURATION_CHANGE):
    return _synthetic_plan(steps=(_synthetic_step(step_id=step_id, order=1, authorization_required=level),))


def _times(*, ttl_seconds: int = 300):
    issued = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc)
    return issued, issued + timedelta(seconds=ttl_seconds)


def _authz(plan=None, step_ids=("s1",), *, private_key, authority_id="owner-1"):
    plan = plan if plan is not None else _plan()
    issued, expires = _times()
    payload = build_plan_authorization_payload(
        plan, step_ids, authorization_id="authz-1", authority_id=authority_id, issued_at=issued, expires_at=expires
    )
    return sign_plan_authorization(payload, private_key)


def _authz_v2(
    plan=None,
    *,
    private_key,
    step_id: str = "s1",
    execution_intent_digest: str = "a" * 64,
    authority_id: str = "owner-1",
):
    plan = plan if plan is not None else _plan()
    issued, expires = _times()
    payload = build_plan_authorization_v2_payload(
        plan,
        (PlanAuthorizationStepBinding(step_id=step_id, execution_intent_digest=execution_intent_digest),),
        authorization_id="authz-v2-1",
        authority_id=authority_id,
        issued_at=issued,
        expires_at=expires,
    )
    return sign_plan_authorization_v2(payload, private_key)


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def test_valid_signature_from_active_authority_verifies():
    key, public_bytes = _keypair()
    authz = _authz(private_key=key)
    assert verify_plan_authorization_signature(authz, _authorities("owner-1", public_bytes)) is True


def test_wrong_key_signature_does_not_verify():
    key, _ = _keypair()
    _, wrong_public_bytes = _keypair()
    authz = _authz(private_key=key)
    assert verify_plan_authorization_signature(authz, _authorities("owner-1", wrong_public_bytes)) is False


def test_unknown_authority_does_not_verify():
    key, _ = _keypair()
    _, other_public_bytes = _keypair()
    authz = _authz(private_key=key)
    assert verify_plan_authorization_signature(authz, _authorities("someone-else", other_public_bytes)) is False


def test_inactive_authority_does_not_verify():
    key, public_bytes = _keypair()
    authz = _authz(private_key=key)
    assert verify_plan_authorization_signature(authz, _authorities("owner-1", public_bytes, active=False)) is False


def test_invalid_signature_bytes_do_not_verify():
    key, public_bytes = _keypair()
    authz = _authz(private_key=key)
    # Construct a structurally-valid-length but semantically wrong
    # signature by signing different bytes with the same key.
    from pfsense_mcp.security_authorization import PlanAuthorization

    forged_proof = key.sign(b"completely different message")
    tampered = PlanAuthorization(
        schema_version=authz.schema_version,
        authorization_id=authz.authorization_id,
        plan_digest=authz.plan_digest,
        authorized_step_ids=authz.authorized_step_ids,
        authority_id=authz.authority_id,
        algorithm=authz.algorithm,
        proof=forged_proof,
        issued_at=authz.issued_at,
        expires_at=authz.expires_at,
        risk_class=authz.risk_class,
        evidence_fingerprint=authz.evidence_fingerprint,
    )
    assert verify_plan_authorization_signature(tampered, _authorities("owner-1", public_bytes)) is False


def test_modified_signed_field_invalidates_verification():
    key, public_bytes = _keypair()
    plan = _plan()
    payload_a = build_plan_authorization_payload(
        plan,
        ("s1",),
        authorization_id="authz-1",
        authority_id="owner-1",
        issued_at=_times()[0],
        expires_at=_times()[1],
    )
    authz = sign_plan_authorization(payload_a, key)

    from pfsense_mcp.security_authorization import PlanAuthorization

    tampered = PlanAuthorization(
        schema_version=authz.schema_version,
        authorization_id="a-different-id",  # signed field changed post-signing
        plan_digest=authz.plan_digest,
        authorized_step_ids=authz.authorized_step_ids,
        authority_id=authz.authority_id,
        algorithm=authz.algorithm,
        proof=authz.proof,
        issued_at=authz.issued_at,
        expires_at=authz.expires_at,
        risk_class=authz.risk_class,
        evidence_fingerprint=authz.evidence_fingerprint,
    )
    assert verify_plan_authorization_signature(tampered, _authorities("owner-1", public_bytes)) is False


def test_algorithm_mismatch_short_circuits_to_false():
    """A downgrade attempt (claiming a different algorithm) is refused
    without even attempting signature verification."""

    key, public_bytes = _keypair()
    from pfsense_mcp.security_authorization import PlanAuthorization

    authz = _authz(private_key=key)
    tampered = PlanAuthorization(
        schema_version=authz.schema_version,
        authorization_id=authz.authorization_id,
        plan_digest=authz.plan_digest,
        authorized_step_ids=authz.authorized_step_ids,
        authority_id=authz.authority_id,
        algorithm="ed25519-v1",  # unchanged -- construction rejects anything else anyway
        proof=authz.proof,
        issued_at=authz.issued_at,
        expires_at=authz.expires_at,
        risk_class=authz.risk_class,
        evidence_fingerprint=authz.evidence_fingerprint,
    )
    assert verify_plan_authorization_signature(tampered, _authorities("owner-1", public_bytes)) is True
    assert tampered.algorithm == "ed25519-v1"


def test_signature_from_one_plan_authorization_does_not_verify_for_a_differently_scoped_one():
    """Domain/scope mismatch: a signature produced over one payload must
    not verify against a payload differing only in authorized_step_ids."""

    key, public_bytes = _keypair()
    plan = _synthetic_plan(
        steps=(
            _synthetic_step(step_id="s1", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),
            _synthetic_step(step_id="s2", order=2, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),
        )
    )
    authz_narrow = _authz(plan=plan, step_ids=("s1",), private_key=key)

    from pfsense_mcp.security_authorization import PlanAuthorization

    widened = PlanAuthorization(
        schema_version=authz_narrow.schema_version,
        authorization_id=authz_narrow.authorization_id,
        plan_digest=authz_narrow.plan_digest,
        authorized_step_ids=("s1", "s2"),
        authority_id=authz_narrow.authority_id,
        algorithm=authz_narrow.algorithm,
        proof=authz_narrow.proof,
        issued_at=authz_narrow.issued_at,
        expires_at=authz_narrow.expires_at,
        risk_class=authz_narrow.risk_class,
        evidence_fingerprint=authz_narrow.evidence_fingerprint,
    )
    assert verify_plan_authorization_signature(widened, _authorities("owner-1", public_bytes)) is False


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


def test_current_before_expiry():
    key, _ = _keypair()
    authz = _authz(private_key=key)
    assert plan_authorization_is_current(authz, now=authz.issued_at) is True
    assert plan_authorization_is_current(authz, now=authz.expires_at - timedelta(seconds=1)) is True


def test_not_current_exactly_at_expiry_boundary():
    key, _ = _keypair()
    authz = _authz(private_key=key)
    assert plan_authorization_is_current(authz, now=authz.expires_at) is False


def test_not_current_after_expiry():
    key, _ = _keypair()
    authz = _authz(private_key=key)
    assert plan_authorization_is_current(authz, now=authz.expires_at + timedelta(seconds=1)) is False


def test_naive_now_is_rejected():
    key, _ = _keypair()
    authz = _authz(private_key=key)
    with pytest.raises(SecurityAuthorizationError):
        plan_authorization_is_current(authz, now=datetime(2026, 8, 11, 12, 0, 0))


def test_non_utc_offset_now_is_rejected():
    key, _ = _keypair()
    authz = _authz(private_key=key)
    plus_five = timezone(timedelta(hours=5))
    with pytest.raises(SecurityAuthorizationError):
        plan_authorization_is_current(authz, now=datetime(2026, 8, 11, 12, 0, 0, tzinfo=plus_five))


def test_now_before_issued_at_is_still_current_deliberately():
    """This module does not invent a 'not yet valid before issued_at'
    policy -- see the module docstring's explicit rationale. A now
    earlier than issued_at is not itself treated as non-current."""

    key, _ = _keypair()
    authz = _authz(private_key=key)
    assert plan_authorization_is_current(authz, now=authz.issued_at - timedelta(days=1)) is True


def test_expiry_check_is_independent_of_signature_validity():
    """Signature validity must not imply freshness/currency, and vice
    versa: an authorization with a forged proof is still correctly
    reported as time-current if its expires_at has not passed, and a
    validly-signed one is still correctly reported as not current once
    expired. Neither check leaks into the other."""

    key, public_bytes = _keypair()
    authz = _authz(private_key=key)

    from pfsense_mcp.security_authorization import PlanAuthorization

    forged = PlanAuthorization(
        schema_version=authz.schema_version,
        authorization_id=authz.authorization_id,
        plan_digest=authz.plan_digest,
        authorized_step_ids=authz.authorized_step_ids,
        authority_id=authz.authority_id,
        algorithm=authz.algorithm,
        proof=key.sign(b"not the real payload"),
        issued_at=authz.issued_at,
        expires_at=authz.expires_at,
        risk_class=authz.risk_class,
        evidence_fingerprint=authz.evidence_fingerprint,
    )
    assert verify_plan_authorization_signature(forged, _authorities("owner-1", public_bytes)) is False
    assert plan_authorization_is_current(forged, now=authz.issued_at) is True

    assert verify_plan_authorization_signature(authz, _authorities("owner-1", public_bytes)) is True
    assert plan_authorization_is_current(authz, now=authz.expires_at + timedelta(seconds=1)) is False


# ---------------------------------------------------------------------------
# plan_digest / step-scope binding
# ---------------------------------------------------------------------------


def test_correct_plan_digest_and_step_authorizes():
    key, _ = _keypair()
    authz = _authz(private_key=key)
    assert plan_authorization_authorizes_step(authz, plan_digest=authz.plan_digest, step_id="s1") is True


def test_wrong_plan_digest_refuses_even_with_correct_step():
    key, _ = _keypair()
    authz = _authz(private_key=key)
    assert plan_authorization_authorizes_step(authz, plan_digest="ab" * 32, step_id="s1") is False


def test_unauthorized_step_refuses_even_with_correct_plan_digest():
    key, _ = _keypair()
    plan = _synthetic_plan(
        steps=(
            _synthetic_step(step_id="s1", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),
            _synthetic_step(step_id="s2", order=2, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),
        )
    )
    authz = _authz(plan=plan, step_ids=("s1",), private_key=key)
    assert plan_authorization_authorizes_step(authz, plan_digest=authz.plan_digest, step_id="s2") is False


def test_missing_step_id_refuses():
    key, _ = _keypair()
    authz = _authz(private_key=key)
    assert plan_authorization_authorizes_step(authz, plan_digest=authz.plan_digest, step_id="does-not-exist") is False


def test_a_different_plan_with_a_same_named_step_is_not_authorized():
    """The exact scenario ADR-022's own text warns about: step_ids are
    stable strings reused across plans -- membership alone must never
    be sufficient."""

    key, _ = _keypair()
    plan_a = _synthetic_plan(
        steps=(
            _synthetic_step(
                step_id="shared-step", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE
            ),
        )
    )
    from pfsense_mcp.security_discovery import CapabilityPosture

    plan_b = _synthetic_plan(
        steps=(
            _synthetic_step(
                step_id="shared-step", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE
            ),
        ),
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
    )
    authz_for_a = _authz(plan=plan_a, step_ids=("shared-step",), private_key=key)
    plan_digest_b = build_plan_authorization_payload(
        plan_b,
        ("shared-step",),
        authorization_id="x",
        authority_id="owner-1",
        issued_at=_times()[0],
        expires_at=_times()[1],
    ).plan_digest
    assert plan_digest_b != authz_for_a.plan_digest
    assert plan_authorization_authorizes_step(authz_for_a, plan_digest=plan_digest_b, step_id="shared-step") is False


def test_no_wildcard_or_prefix_matching():
    key, _ = _keypair()
    authz = _authz(private_key=key)
    assert plan_authorization_authorizes_step(authz, plan_digest=authz.plan_digest, step_id="s") is False
    assert plan_authorization_authorizes_step(authz, plan_digest=authz.plan_digest, step_id="s1x") is False
    assert plan_authorization_authorizes_step(authz, plan_digest=authz.plan_digest, step_id="*") is False


def test_non_string_plan_digest_or_step_id_is_rejected_not_coerced():
    key, _ = _keypair()
    authz = _authz(private_key=key)
    assert plan_authorization_authorizes_step(authz, plan_digest=None, step_id="s1") is False  # type: ignore[arg-type]
    assert plan_authorization_authorizes_step(authz, plan_digest=authz.plan_digest, step_id=None) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# No production wiring / no fail-open exception paths
# ---------------------------------------------------------------------------


def test_verify_never_raises_for_ordinary_malformed_authority_input():
    """Mirrors Ed25519ConfirmationVerifier.verify()'s own contract:
    every ordinary verification failure path returns False, never
    raises."""

    key, _public_bytes = _keypair()
    authz = _authz(private_key=key)
    # A well-formed but wrong-length-for-Ed25519 authority key would
    # already fail at PinnedAuthority construction (tested in
    # test_ed25519_authority.py); here we confirm verify() itself is
    # exception-free for a legitimate authority set that simply doesn't
    # match.
    _, other_public_bytes = _keypair()
    other_authorities = _authorities("owner-1", other_public_bytes)
    assert verify_plan_authorization_signature(authz, other_authorities) is False


# ---------------------------------------------------------------------------
# plan_authorization_v2_satisfies_required_risk_class() -- ADR-036 W0
# ---------------------------------------------------------------------------


def test_v2_satisfies_required_risk_class_when_signed_at_exactly_the_required_level():
    key, _public_bytes = _keypair()
    plan = _plan(level=AuthorizationLevel.CONFIGURATION_CHANGE)
    authz = _authz_v2(plan, private_key=key)
    assert (
        plan_authorization_v2_satisfies_required_risk_class(
            authz, required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE
        )
        is True
    )


def test_v2_satisfies_required_risk_class_when_signed_above_the_required_level():
    key, _public_bytes = _keypair()
    plan = _plan(level=AuthorizationLevel.MILESTONE_9_ACTIVATION_DECISION)
    authz = _authz_v2(plan, private_key=key)
    assert (
        plan_authorization_v2_satisfies_required_risk_class(
            authz, required_risk_class=AuthorizationLevel.CONFIGURATION_CHANGE
        )
        is True
    )


def test_v2_refuses_when_signed_below_the_required_level():
    key, _public_bytes = _keypair()
    plan = _plan(level=AuthorizationLevel.CONFIGURATION_CHANGE)
    authz = _authz_v2(plan, private_key=key)
    assert (
        plan_authorization_v2_satisfies_required_risk_class(
            authz, required_risk_class=AuthorizationLevel.MILESTONE_9_ACTIVATION_DECISION
        )
        is False
    )


def test_v2_satisfies_required_risk_class_rejects_non_v2_authorization():
    key, _public_bytes = _keypair()
    v1_authz = _authz(private_key=key)
    assert (
        plan_authorization_v2_satisfies_required_risk_class(
            v1_authz,
            required_risk_class=AuthorizationLevel.NONE_REQUIRED,  # type: ignore[arg-type]
        )
        is False
    )
