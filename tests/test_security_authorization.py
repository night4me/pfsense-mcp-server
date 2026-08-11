"""Regression and adversarial tests for `pfsense_mcp.security_authorization`
-- ADR-022 Phase C's `PlanAuthorization`/`DeprovisionAuthorization` data
models, canonical signing payloads, and signature construction. No
verification/consumption/execution primitive exists in production; the
one Ed25519-verification helper in this file (`_verify`) exists solely
to prove signatures were constructed correctly, reusing `cryptography`'s
own low-level primitive directly rather than building a reusable
production verifier.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import pfsense_mcp.security_authorization as security_authorization
from pfsense_mcp.security_authorization import (
    DEPROVISION_AUTHORIZATION_SCHEMA_VERSION,
    PLAN_AUTHORIZATION_SCHEMA_VERSION,
    AuthorizationEvidenceFingerprint,
    DeprovisionAuthorization,
    PlanAuthorization,
    PlanAuthorizationPayload,
    SecurityAuthorizationError,
    build_deprovision_authorization_payload,
    build_plan_authorization_payload,
    deprovision_authorization_signing_payload,
    plan_authorization_signing_payload,
    sign_deprovision_authorization,
    sign_plan_authorization,
)
from pfsense_mcp.security_plan import AuthorizationLevel, MutationClass
from tests.test_security_plan_digest import _synthetic_plan, _synthetic_step

# ---------------------------------------------------------------------------
# Test-only fixtures. None of these values are production defaults --
# security_authorization.py itself supplies no default duration/key/id.
# ---------------------------------------------------------------------------

_HEX_64 = "ab" * 32


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _times(*, issued_offset_seconds: int = 0, ttl_seconds: int = 300) -> tuple[datetime, datetime]:
    issued = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=issued_offset_seconds)
    return issued, issued + timedelta(seconds=ttl_seconds)


def _plan_with_steps():
    steps = (
        _synthetic_step(
            step_id="s1",
            order=1,
            mutation_class=MutationClass.CONFIGURATION,
            authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE,
        ),
        _synthetic_step(
            step_id="s2",
            order=2,
            mutation_class=MutationClass.ANCHOR_PROVISIONING,
            authorization_required=AuthorizationLevel.INTERACTIVE_HARDWARE_CONFIRMATION,
        ),
        _synthetic_step(
            step_id="s3",
            order=3,
            mutation_class=MutationClass.NONE,
            authorization_required=AuthorizationLevel.NONE_REQUIRED,
        ),
    )
    return _synthetic_plan(steps=steps)


def _build_payload(plan=None, step_ids=("s1",), **overrides):
    plan = plan if plan is not None else _plan_with_steps()
    issued_at, expires_at = _times()
    kwargs = {
        "authorization_id": "authz-1",
        "authority_id": "owner-key-1",
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    kwargs.update(overrides)
    return build_plan_authorization_payload(plan, step_ids, **kwargs)


def _verify(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True


# ---------------------------------------------------------------------------
# 1. Determinism of canonical signing input
# ---------------------------------------------------------------------------


def test_signing_payload_is_deterministic_across_repeated_computations():
    payload = _build_payload()
    assert plan_authorization_signing_payload(payload) == plan_authorization_signing_payload(payload)


def test_deprovision_signing_payload_is_deterministic():
    issued_at, expires_at = _times()
    payload = build_deprovision_authorization_payload(
        target_identity_digest=_HEX_64,
        authorization_id="deprov-1",
        authority_id="owner-key-1",
        issued_at=issued_at,
        expires_at=expires_at,
    )
    assert deprovision_authorization_signing_payload(payload) == deprovision_authorization_signing_payload(payload)


# ---------------------------------------------------------------------------
# 2. Different PlanDigest / step-set / added-step / removed-step -> different payload
# ---------------------------------------------------------------------------


def test_different_plan_digest_produces_different_signing_payload():
    plan_a = _plan_with_steps()
    plan_b = _synthetic_plan(
        steps=(_synthetic_step(step_id="s1", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),),
        target_capability_posture=plan_a.target_capability_posture,
    )
    # give plan_b a differing target so its PlanDigest differs
    from pfsense_mcp.security_discovery import CapabilityPosture

    plan_b = _synthetic_plan(
        steps=(_synthetic_step(step_id="s1", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),),
        target_capability_posture=CapabilityPosture.WRITE_PROTECTED,
    )
    payload_a = _build_payload(plan=plan_a, step_ids=("s1",))
    payload_b = _build_payload(plan=plan_b, step_ids=("s1",))
    assert payload_a.plan_digest != payload_b.plan_digest
    assert plan_authorization_signing_payload(payload_a) != plan_authorization_signing_payload(payload_b)


def test_different_step_set_produces_different_signing_payload():
    plan = _plan_with_steps()
    payload_a = _build_payload(plan=plan, step_ids=("s1",))
    payload_b = _build_payload(plan=plan, step_ids=("s2",))
    assert plan_authorization_signing_payload(payload_a) != plan_authorization_signing_payload(payload_b)


def test_added_step_produces_different_signing_payload():
    plan = _plan_with_steps()
    payload_a = _build_payload(plan=plan, step_ids=("s1",))
    payload_b = _build_payload(plan=plan, step_ids=("s1", "s2"))
    assert plan_authorization_signing_payload(payload_a) != plan_authorization_signing_payload(payload_b)


def test_removed_step_produces_different_signing_payload():
    plan = _plan_with_steps()
    payload_a = _build_payload(plan=plan, step_ids=("s1", "s2"))
    payload_b = _build_payload(plan=plan, step_ids=("s1",))
    assert plan_authorization_signing_payload(payload_a) != plan_authorization_signing_payload(payload_b)


# ---------------------------------------------------------------------------
# 3. Step-set canonicalization -- reordering does not change identity
# ---------------------------------------------------------------------------


def test_reordering_authorized_step_ids_does_not_change_the_signing_payload():
    plan = _plan_with_steps()
    payload_forward = _build_payload(plan=plan, step_ids=("s1", "s2"))
    payload_reversed = _build_payload(plan=plan, step_ids=("s2", "s1"))
    assert plan_authorization_signing_payload(payload_forward) == plan_authorization_signing_payload(payload_reversed)
    # the dataclass itself retains caller-supplied order for display/audit
    assert payload_forward.authorized_step_ids == ("s1", "s2")
    assert payload_reversed.authorized_step_ids == ("s2", "s1")


# ---------------------------------------------------------------------------
# 4. Duplicate / empty step-set rejection
# ---------------------------------------------------------------------------


def test_duplicate_step_ids_are_rejected():
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(step_ids=("s1", "s1"))


def test_empty_step_set_is_rejected():
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(step_ids=())


def test_unknown_step_id_is_rejected():
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(step_ids=("does-not-exist",))


def test_step_requiring_separate_deprovision_authorization_is_rejected():
    plan = _synthetic_plan(
        steps=(
            _synthetic_step(
                step_id="destructive",
                order=1,
                authorization_required=AuthorizationLevel.SEPARATE_DEPROVISION_AUTHORIZATION,
            ),
        )
    )
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(plan=plan, step_ids=("destructive",))


def test_step_requiring_undetermined_not_implemented_is_rejected():
    plan = _synthetic_plan(
        steps=(
            _synthetic_step(
                step_id="undetermined", order=1, authorization_required=AuthorizationLevel.UNDETERMINED_NOT_IMPLEMENTED
            ),
        )
    )
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(plan=plan, step_ids=("undetermined",))


def test_no_wildcard_step_scope_sentinel_exists():
    assert not hasattr(security_authorization, "ALL_STEPS")
    assert not hasattr(security_authorization, "WILDCARD")


# ---------------------------------------------------------------------------
# 5. Malformed PlanDigest / schema version rejection
# ---------------------------------------------------------------------------


def test_plan_authorization_rejects_a_malformed_plan_digest():
    payload = _build_payload()
    key = _key()
    authz = sign_plan_authorization(payload, key)
    with pytest.raises(SecurityAuthorizationError):
        PlanAuthorization(
            schema_version=authz.schema_version,
            authorization_id=authz.authorization_id,
            plan_digest="not-a-real-digest",
            authorized_step_ids=authz.authorized_step_ids,
            authority_id=authz.authority_id,
            algorithm=authz.algorithm,
            proof=authz.proof,
            issued_at=authz.issued_at,
            expires_at=authz.expires_at,
            risk_class=authz.risk_class,
            evidence_fingerprint=authz.evidence_fingerprint,
        )


def test_build_plan_authorization_payload_rejects_unsupported_schema_version():
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(schema_version=PLAN_AUTHORIZATION_SCHEMA_VERSION + 1)


def test_plan_authorization_dataclass_rejects_unsupported_schema_version():
    payload = _build_payload()
    authz = sign_plan_authorization(payload, _key())
    with pytest.raises(SecurityAuthorizationError):
        PlanAuthorization(
            schema_version=PLAN_AUTHORIZATION_SCHEMA_VERSION + 1,
            authorization_id=authz.authorization_id,
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


def test_deprovision_authorization_schema_version_is_independent_of_plan_authorizations():
    assert DEPROVISION_AUTHORIZATION_SCHEMA_VERSION == 1
    assert PLAN_AUTHORIZATION_SCHEMA_VERSION == 1
    with pytest.raises(SecurityAuthorizationError):
        build_deprovision_authorization_payload(
            target_identity_digest=_HEX_64,
            authorization_id="deprov-1",
            authority_id="owner-key-1",
            issued_at=_times()[0],
            expires_at=_times()[1],
            schema_version=DEPROVISION_AUTHORIZATION_SCHEMA_VERSION + 1,
        )


# ---------------------------------------------------------------------------
# 6. Field participation: signer identity / authorization identity /
#    issued_at / expires_at
# ---------------------------------------------------------------------------


def test_different_authorization_id_produces_different_signing_payload():
    a = _build_payload(authorization_id="authz-a")
    b = _build_payload(authorization_id="authz-b")
    assert plan_authorization_signing_payload(a) != plan_authorization_signing_payload(b)


def test_different_authority_id_produces_different_signing_payload():
    a = _build_payload(authority_id="owner-key-a")
    b = _build_payload(authority_id="owner-key-b")
    assert plan_authorization_signing_payload(a) != plan_authorization_signing_payload(b)


def test_different_issued_at_produces_different_signing_payload():
    issued_1, expires_1 = _times(issued_offset_seconds=0)
    issued_2, expires_2 = _times(issued_offset_seconds=10)
    a = _build_payload(issued_at=issued_1, expires_at=expires_1)
    b = _build_payload(issued_at=issued_2, expires_at=expires_2)
    assert plan_authorization_signing_payload(a) != plan_authorization_signing_payload(b)


def test_different_expires_at_produces_different_signing_payload():
    issued, _ = _times()
    a = _build_payload(issued_at=issued, expires_at=issued + timedelta(seconds=60))
    b = _build_payload(issued_at=issued, expires_at=issued + timedelta(seconds=600))
    assert plan_authorization_signing_payload(a) != plan_authorization_signing_payload(b)


def test_risk_class_is_the_highest_authorization_level_among_selected_steps():
    plan = _plan_with_steps()
    low = _build_payload(plan=plan, step_ids=("s3",))  # NONE_REQUIRED
    high = _build_payload(plan=plan, step_ids=("s3", "s2"))  # NONE_REQUIRED + INTERACTIVE_HARDWARE_CONFIRMATION
    assert low.risk_class is AuthorizationLevel.NONE_REQUIRED
    assert high.risk_class is AuthorizationLevel.INTERACTIVE_HARDWARE_CONFIRMATION


def test_a_lower_friction_authorization_cannot_be_reused_for_a_higher_risk_step_set():
    """Threat-model row: 'a CONFIGURATION_CHANGE-scoped grant cannot
    satisfy an INTERACTIVE_HARDWARE_CONFIRMATION-class step's binding
    check' -- proved here by showing the two step sets sign different
    bytes and produce non-interchangeable signatures."""

    plan = _plan_with_steps()
    key = _key()
    low_payload = _build_payload(plan=plan, step_ids=("s1",))  # CONFIGURATION_CHANGE
    high_payload = _build_payload(plan=plan, step_ids=("s2",))  # INTERACTIVE_HARDWARE_CONFIRMATION
    low_authz = sign_plan_authorization(low_payload, key)

    assert low_authz.risk_class is AuthorizationLevel.CONFIGURATION_CHANGE
    assert not _verify(key.public_key(), plan_authorization_signing_payload(high_payload), low_authz.proof)


# ---------------------------------------------------------------------------
# 7. Timestamp safety
# ---------------------------------------------------------------------------


def test_naive_issued_at_is_rejected():
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(issued_at=datetime(2026, 8, 11, 12, 0, 0), expires_at=_times()[1])


def test_naive_expires_at_is_rejected():
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(issued_at=_times()[0], expires_at=datetime(2026, 8, 11, 12, 5, 0))


def test_non_utc_offset_is_rejected():
    from datetime import timezone as tz

    plus_five = tz(timedelta(hours=5))
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(
            issued_at=datetime(2026, 8, 11, 12, 0, 0, tzinfo=plus_five),
            expires_at=datetime(2026, 8, 11, 13, 0, 0, tzinfo=timezone.utc),
        )


def test_expires_at_must_be_strictly_after_issued_at():
    issued, _ = _times()
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(issued_at=issued, expires_at=issued)
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(issued_at=issued, expires_at=issued - timedelta(seconds=1))


def test_this_module_supplies_no_default_expiry_duration():
    """ADR-022 owner review, question 3: mechanism accepted, numeric
    defaults provisional -- this module must not invent one."""

    import inspect

    sig = inspect.signature(build_plan_authorization_payload)
    assert sig.parameters["issued_at"].default is inspect.Parameter.empty
    assert sig.parameters["expires_at"].default is inspect.Parameter.empty


# ---------------------------------------------------------------------------
# 8. Signature never signs itself
# ---------------------------------------------------------------------------


def test_proof_is_never_a_key_in_the_signing_payload():
    payload = _build_payload()
    message = plan_authorization_signing_payload(payload)
    assert b"proof" not in message


def test_deprovision_proof_is_never_a_key_in_the_signing_payload():
    issued_at, expires_at = _times()
    payload = build_deprovision_authorization_payload(
        target_identity_digest=_HEX_64,
        authorization_id="deprov-1",
        authority_id="owner-key-1",
        issued_at=issued_at,
        expires_at=expires_at,
    )
    message = deprovision_authorization_signing_payload(payload)
    assert b"proof" not in message


# ---------------------------------------------------------------------------
# 9. Real signature verification (test-only, low-level primitive)
# ---------------------------------------------------------------------------


def test_sign_plan_authorization_produces_a_verifiable_signature():
    key = _key()
    payload = _build_payload()
    authz = sign_plan_authorization(payload, key)
    assert _verify(key.public_key(), plan_authorization_signing_payload(payload), authz.proof)


def test_sign_deprovision_authorization_produces_a_verifiable_signature():
    key = _key()
    issued_at, expires_at = _times()
    payload = build_deprovision_authorization_payload(
        target_identity_digest=_HEX_64,
        authorization_id="deprov-1",
        authority_id="owner-key-1",
        issued_at=issued_at,
        expires_at=expires_at,
    )
    authz = sign_deprovision_authorization(payload, key)
    assert _verify(key.public_key(), deprovision_authorization_signing_payload(payload), authz.proof)


def test_wrong_key_signature_does_not_verify():
    key_a, key_b = _key(), _key()
    payload = _build_payload()
    authz = sign_plan_authorization(payload, key_a)
    assert not _verify(key_b.public_key(), plan_authorization_signing_payload(payload), authz.proof)


def test_changing_any_signed_field_invalidates_the_signature():
    key = _key()
    payload = _build_payload()
    authz = sign_plan_authorization(payload, key)
    message = plan_authorization_signing_payload(payload)
    assert _verify(key.public_key(), message, authz.proof)

    tampered = PlanAuthorizationPayload(
        schema_version=payload.schema_version,
        authorization_id=payload.authorization_id,
        plan_digest=payload.plan_digest,
        authorized_step_ids=payload.authorized_step_ids,
        authority_id="a-different-authority",
        algorithm=payload.algorithm,
        issued_at=payload.issued_at,
        expires_at=payload.expires_at,
        risk_class=payload.risk_class,
        evidence_fingerprint=payload.evidence_fingerprint,
    )
    assert not _verify(key.public_key(), plan_authorization_signing_payload(tampered), authz.proof)


def test_post_signing_artifact_modification_invalidates_verification():
    """A frozen dataclass cannot be mutated in place, but a *new* object
    built from tampered fields (simulating an attacker reconstructing a
    modified artifact) must fail verification against the original
    signature."""

    key = _key()
    payload = _build_payload(step_ids=("s1",))
    authz = sign_plan_authorization(payload, key)

    widened_payload = PlanAuthorizationPayload(
        schema_version=payload.schema_version,
        authorization_id=payload.authorization_id,
        plan_digest=payload.plan_digest,
        authorized_step_ids=("s1", "s2"),
        authority_id=payload.authority_id,
        algorithm=payload.algorithm,
        issued_at=payload.issued_at,
        expires_at=payload.expires_at,
        risk_class=payload.risk_class,
        evidence_fingerprint=payload.evidence_fingerprint,
    )
    assert not _verify(key.public_key(), plan_authorization_signing_payload(widened_payload), authz.proof)


# ---------------------------------------------------------------------------
# 10. PlanAuthorization <-> DeprovisionAuthorization: structural distinctness
# ---------------------------------------------------------------------------


def test_plan_authorization_and_deprovision_authorization_are_unrelated_types():
    assert not issubclass(PlanAuthorization, DeprovisionAuthorization)
    assert not issubclass(DeprovisionAuthorization, PlanAuthorization)
    key = _key()
    plan_authz = sign_plan_authorization(_build_payload(), key)
    issued_at, expires_at = _times()
    deprov_authz = sign_deprovision_authorization(
        build_deprovision_authorization_payload(
            target_identity_digest=_HEX_64,
            authorization_id="deprov-1",
            authority_id="owner-key-1",
            issued_at=issued_at,
            expires_at=expires_at,
        ),
        key,
    )
    assert not isinstance(plan_authz, DeprovisionAuthorization)
    assert not isinstance(deprov_authz, PlanAuthorization)


def test_deprovision_authorization_has_no_plan_scoped_fields():
    fields = set(DeprovisionAuthorization.__dataclass_fields__)
    assert "plan_digest" not in fields
    assert "authorized_step_ids" not in fields
    assert "risk_class" not in fields
    assert "evidence_fingerprint" not in fields


def test_plan_authorization_signature_does_not_verify_as_a_deprovision_signature():
    """Domain separation: a PlanAuthorization's proof must never verify
    against a DeprovisionAuthorization signing payload, even one built to
    superficially resemble it (same authorization_id/authority_id/
    algorithm/timestamps)."""

    key = _key()
    plan_payload = _build_payload(authorization_id="shared-id", authority_id="shared-authority")
    plan_authz = sign_plan_authorization(plan_payload, key)

    deprovision_payload = build_deprovision_authorization_payload(
        target_identity_digest=plan_authz.plan_digest,  # deliberately reuse the hex digest value
        authorization_id="shared-id",
        authority_id="shared-authority",
        issued_at=plan_payload.issued_at,
        expires_at=plan_payload.expires_at,
    )
    assert not _verify(
        key.public_key(), deprovision_authorization_signing_payload(deprovision_payload), plan_authz.proof
    )


def test_deprovision_authorization_signature_does_not_verify_as_a_plan_authorization_signature():
    key = _key()
    issued_at, expires_at = _times()
    deprovision_payload = build_deprovision_authorization_payload(
        target_identity_digest=_HEX_64,
        authorization_id="shared-id",
        authority_id="shared-authority",
        issued_at=issued_at,
        expires_at=expires_at,
    )
    deprov_authz = sign_deprovision_authorization(deprovision_payload, key)

    plan_payload = _build_payload(
        authorization_id="shared-id", authority_id="shared-authority", issued_at=issued_at, expires_at=expires_at
    )
    assert not _verify(key.public_key(), plan_authorization_signing_payload(plan_payload), deprov_authz.proof)


def test_no_construction_path_coerces_a_plan_authorization_into_a_deprovision_authorization():
    key = _key()
    plan_authz = sign_plan_authorization(_build_payload(), key)
    with pytest.raises(TypeError):
        DeprovisionAuthorization(**vars(plan_authz))  # type: ignore[arg-type]


def test_no_production_path_ever_constructs_a_deprovision_authorization_from_real_infrastructure():
    """No function in this module derives target_identity_digest from a
    real TPM NV index or store key -- it is always caller-supplied, and
    no caller anywhere in this repository supplies one (grep-level
    structural claim; see test_security_authorization_isolation.py for
    the AST-backed no-importer proof)."""

    import inspect

    sig = inspect.signature(build_deprovision_authorization_payload)
    assert "target_identity_digest" in sig.parameters
    assert sig.parameters["target_identity_digest"].default is inspect.Parameter.empty


def test_target_identity_digest_omission_raises_type_error():
    issued_at, expires_at = _times()
    with pytest.raises(TypeError):
        build_deprovision_authorization_payload(  # type: ignore[call-arg]
            authorization_id="deprov-1", authority_id="owner-key-1", issued_at=issued_at, expires_at=expires_at
        )


@pytest.mark.parametrize(
    "malformed",
    [
        "AB" * 32,  # uppercase hex rejected -- lowercase only
        "ab" * 31,  # too short
        "ab" * 33,  # too long
        "not-hex-at-all-" + "0" * 49,
        "",
    ],
)
def test_malformed_target_identity_digest_is_rejected(malformed):
    issued_at, expires_at = _times()
    with pytest.raises(SecurityAuthorizationError):
        build_deprovision_authorization_payload(
            target_identity_digest=malformed,
            authorization_id="deprov-1",
            authority_id="owner-key-1",
            issued_at=issued_at,
            expires_at=expires_at,
        )


# ---------------------------------------------------------------------------
# 11. Confirmation/reconciliation domain separation
# ---------------------------------------------------------------------------


def test_plan_authorization_purpose_tag_differs_from_plan_digest_purpose():
    from pfsense_mcp.tier1.canonical import DigestPurpose

    assert DigestPurpose.PLAN_AUTHORIZATION.value != DigestPurpose.PLAN.value
    assert DigestPurpose.PLAN_AUTHORIZATION.value != DigestPurpose.DEPROVISION_AUTHORIZATION.value
    assert DigestPurpose.PLAN_AUTHORIZATION.value != DigestPurpose.CONFIRMATION.value
    assert DigestPurpose.PLAN_AUTHORIZATION.value != DigestPurpose.RECONCILIATION.value


# ---------------------------------------------------------------------------
# 12. Raw-string / Enum coercion, bool/int ambiguity
# ---------------------------------------------------------------------------


def test_algorithm_string_case_mismatch_is_rejected():
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(algorithm="ED25519-V1")


def test_authorization_id_must_be_a_string_not_an_arbitrary_object():
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(authorization_id=12345)  # type: ignore[arg-type]


def test_schema_version_bool_is_rejected_not_coerced_to_int():
    payload = _build_payload()
    authz = sign_plan_authorization(payload, _key())
    with pytest.raises(SecurityAuthorizationError):
        PlanAuthorization(
            schema_version=True,  # bool is a subclass of int -- must not silently pass as 1
            authorization_id=authz.authorization_id,
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


def test_risk_class_raw_string_equal_to_a_member_value_is_rejected():
    """AuthorizationLevel is a (str, Enum) hybrid: a raw string equal to a
    member's value hashes and compares equal to that member, so a naive
    `not in <rank dict>` check alone would silently accept it. This must
    be rejected -- risk_class must be the real enum type, not a
    string that merely happens to match its value."""

    payload = _build_payload()
    authz = sign_plan_authorization(payload, _key())
    assert AuthorizationLevel.CONFIGURATION_CHANGE == "configuration_change"  # sanity: the collision is real
    with pytest.raises(SecurityAuthorizationError):
        PlanAuthorization(
            schema_version=authz.schema_version,
            authorization_id=authz.authorization_id,
            plan_digest=authz.plan_digest,
            authorized_step_ids=authz.authorized_step_ids,
            authority_id=authz.authority_id,
            algorithm=authz.algorithm,
            proof=authz.proof,
            issued_at=authz.issued_at,
            expires_at=authz.expires_at,
            risk_class="configuration_change",  # raw str, not AuthorizationLevel
            evidence_fingerprint=authz.evidence_fingerprint,
        )


def test_evidence_fingerprint_baseline_bool_is_rejected():
    with pytest.raises(SecurityAuthorizationError):
        AuthorizationEvidenceFingerprint(
            capability_posture_value="read_only",
            anchor_assurance_value="none",
            anchor_evidence_state="unconfigured",
            anchor_baseline=True,  # bool is not a legitimate integer baseline
            anchor_witness_value=None,
            anchor_provisioned_at=None,
        )


def test_step_ids_must_be_strings_not_enum_or_other_objects():
    with pytest.raises(SecurityAuthorizationError):
        _build_payload(step_ids=(AuthorizationLevel.NONE_REQUIRED,))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 13. Unknown/critical field safety
# ---------------------------------------------------------------------------


def test_unknown_keyword_argument_is_rejected_by_the_dataclass():
    payload = _build_payload()
    authz = sign_plan_authorization(payload, _key())
    with pytest.raises(TypeError):
        PlanAuthorization(
            schema_version=authz.schema_version,
            authorization_id=authz.authorization_id,
            plan_digest=authz.plan_digest,
            authorized_step_ids=authz.authorized_step_ids,
            authority_id=authz.authority_id,
            algorithm=authz.algorithm,
            proof=authz.proof,
            issued_at=authz.issued_at,
            expires_at=authz.expires_at,
            risk_class=authz.risk_class,
            evidence_fingerprint=authz.evidence_fingerprint,
            unexpected_field="should not be accepted",  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# 14. Proof shape / length
# ---------------------------------------------------------------------------


def test_proof_must_be_exactly_64_bytes():
    payload = _build_payload()
    authz = sign_plan_authorization(payload, _key())
    with pytest.raises(SecurityAuthorizationError):
        PlanAuthorization(
            schema_version=authz.schema_version,
            authorization_id=authz.authorization_id,
            plan_digest=authz.plan_digest,
            authorized_step_ids=authz.authorized_step_ids,
            authority_id=authz.authority_id,
            algorithm=authz.algorithm,
            proof=authz.proof[:-1],  # truncated
            issued_at=authz.issued_at,
            expires_at=authz.expires_at,
            risk_class=authz.risk_class,
            evidence_fingerprint=authz.evidence_fingerprint,
        )


def test_empty_proof_is_rejected():
    payload = _build_payload()
    authz = sign_plan_authorization(payload, _key())
    with pytest.raises(SecurityAuthorizationError):
        PlanAuthorization(
            schema_version=authz.schema_version,
            authorization_id=authz.authorization_id,
            plan_digest=authz.plan_digest,
            authorized_step_ids=authz.authorized_step_ids,
            authority_id=authz.authority_id,
            algorithm=authz.algorithm,
            proof=b"",
            issued_at=authz.issued_at,
            expires_at=authz.expires_at,
            risk_class=authz.risk_class,
            evidence_fingerprint=authz.evidence_fingerprint,
        )


# ---------------------------------------------------------------------------
# 15. No private key material anywhere in either artifact
# ---------------------------------------------------------------------------


def test_no_field_on_either_dataclass_is_named_or_shaped_like_key_material():
    plan_fields = set(PlanAuthorization.__dataclass_fields__)
    deprov_fields = set(DeprovisionAuthorization.__dataclass_fields__)
    for fields in (plan_fields, deprov_fields):
        for name in fields:
            assert "private" not in name.lower()
            assert "secret" not in name.lower()


def test_signing_never_persists_or_leaks_the_private_key_bytes():
    key = _key()
    private_bytes = key.private_bytes_raw()
    payload = _build_payload()
    authz = sign_plan_authorization(payload, key)
    blob = repr(authz) + repr(payload) + repr(plan_authorization_signing_payload(payload))
    assert private_bytes.hex() not in blob
    assert private_bytes not in authz.proof


# ---------------------------------------------------------------------------
# 16. No I/O of any kind
# ---------------------------------------------------------------------------


def test_build_and_sign_perform_no_io(monkeypatch):
    def _boom_sqlite(*args, **kwargs):
        raise AssertionError("security_authorization must perform no SQLite I/O.")

    def _boom_open(*args, **kwargs):
        raise AssertionError("security_authorization must perform no file I/O.")

    monkeypatch.setattr(sqlite3, "connect", _boom_sqlite)
    monkeypatch.setattr("builtins.open", _boom_open)

    payload = _build_payload()
    sign_plan_authorization(payload, _key())

    issued_at, expires_at = _times()
    deprovision_payload = build_deprovision_authorization_payload(
        target_identity_digest=_HEX_64,
        authorization_id="deprov-1",
        authority_id="owner-key-1",
        issued_at=issued_at,
        expires_at=expires_at,
    )
    sign_deprovision_authorization(deprovision_payload, _key())


# ---------------------------------------------------------------------------
# 17. Round-trip / presentation-order stability of the evidence fingerprint
# ---------------------------------------------------------------------------


def test_evidence_fingerprint_matches_the_plan_digest_computation_exactly():
    from pfsense_mcp.security_plan_digest import evidence_fingerprint_payload

    plan = _plan_with_steps()
    payload = _build_payload(plan=plan, step_ids=("s1",))
    expected = evidence_fingerprint_payload(plan)
    assert payload.evidence_fingerprint.to_payload() == expected


def test_evidence_fingerprint_participates_in_the_signing_payload():
    plan_a = _plan_with_steps()
    from pfsense_mcp.security_discovery import AnchorAssurance
    from tests.test_security_plan_digest import _synthetic_current

    plan_b = _synthetic_plan(
        steps=plan_a.steps, current=_synthetic_current(anchor_value=AnchorAssurance.HARDWARE_WITNESS)
    )
    payload_a = _build_payload(plan=plan_a, step_ids=("s1",))
    payload_b = _build_payload(plan=plan_b, step_ids=("s1",))
    assert plan_authorization_signing_payload(payload_a) != plan_authorization_signing_payload(payload_b)
