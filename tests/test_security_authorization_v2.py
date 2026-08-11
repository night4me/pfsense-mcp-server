from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.security_authorization import (
    PLAN_AUTHORIZATION_V2_SCHEMA_VERSION,
    PlanAuthorization,
    PlanAuthorizationStepBinding,
    PlanAuthorizationV2,
    PlanAuthorizationV2Payload,
    SecurityAuthorizationError,
    build_plan_authorization_payload,
    build_plan_authorization_v2_payload,
    plan_authorization_signing_payload,
    plan_authorization_v2_payload_of,
    plan_authorization_v2_signing_payload,
    sign_plan_authorization,
    sign_plan_authorization_v2,
)
from pfsense_mcp.security_authorization_verifier import (
    plan_authorization_is_current,
    plan_authorization_v2_authorizes_execution,
    verify_plan_authorization_signature,
    verify_plan_authorization_v2_signature,
)
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.security_plan_digest import compute_plan_digest
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.prepared_execution_intent import (
    PREPARED_EXECUTION_INTENT_SCHEMA_VERSION,
    PreparedExecutionIntentV1,
    compute_execution_intent_digest,
)
from tests.test_security_plan_digest import _synthetic_plan, _synthetic_step

_DIGEST_X = "a" * 64
_DIGEST_Y = "b" * 64
_DIGEST_Z = "c" * 64


def _plan():
    return _synthetic_plan(
        steps=(
            _synthetic_step(step_id="step.a", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),
            _synthetic_step(step_id="step.b", order=2, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),
            _synthetic_step(step_id="step.c", order=3, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),
        )
    )


def _times() -> tuple[datetime, datetime]:
    issued = datetime(2026, 8, 11, 20, 0, tzinfo=timezone.utc)
    return issued, issued + timedelta(minutes=5)


def _binding(step_id: str = "step.a", digest: str = _DIGEST_X) -> PlanAuthorizationStepBinding:
    return PlanAuthorizationStepBinding(step_id=step_id, execution_intent_digest=digest)


def _payload(
    bindings: tuple[PlanAuthorizationStepBinding, ...] | None = None,
    **changes: object,
) -> PlanAuthorizationV2Payload:
    issued, expires = _times()
    values: dict[str, object] = {
        "plan": _plan(),
        "authorized_executions": bindings if bindings is not None else (_binding(),),
        "authorization_id": "authz-v2-1",
        "authority_id": "owner-1",
        "issued_at": issued,
        "expires_at": expires,
    }
    values.update(changes)
    return build_plan_authorization_v2_payload(**values)  # type: ignore[arg-type]


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def _authorities(public: bytes, *, authority_id: str = "owner-1", active: bool = True) -> PinnedAuthoritySet:
    return PinnedAuthoritySet((PinnedAuthority(authority_id=authority_id, public_key=public, active=active),))


def _authz(
    private: Ed25519PrivateKey,
    bindings: tuple[PlanAuthorizationStepBinding, ...] | None = None,
) -> PlanAuthorizationV2:
    return sign_plan_authorization_v2(_payload(bindings), private)


def test_valid_v2_schema_and_exact_fields():
    payload = _payload()
    private, _ = _keypair()
    authz = sign_plan_authorization_v2(payload, private)

    assert authz.schema_version == PLAN_AUTHORIZATION_V2_SCHEMA_VERSION == 2
    assert not hasattr(authz, "authorized_step_ids")
    assert authz.authorized_executions == (_binding(),)
    assert plan_authorization_v2_payload_of(authz) == payload


def test_real_b1_execution_intent_digest_is_accepted_without_recomputation():
    intent = PreparedExecutionIntentV1(
        schema_version=PREPARED_EXECUTION_INTENT_SCHEMA_VERSION,
        capability=Capability.ALIAS_WRITE,
        endpoint_symbol="SYNTHETIC_ALIAS_DESCRIPTION",
        http_method="PATCH",
        adapter_version="alias-description-v1",
        resource_target={"name": "synthetic.invalid"},
        target_precondition={"revision": "1"},
        normalized_mutation_intent={"raw_target_hint": {}, "parameters": {"description": "after"}},
        rollback_snapshot={"description": "before"},
        rollback_plan_version="rollback-v1",
    )
    digest = compute_execution_intent_digest(intent)

    assert _binding(digest=digest).execution_intent_digest == digest


@pytest.mark.parametrize("bindings", [(), [], None])
def test_empty_or_missing_binding_set_is_rejected(bindings):
    if bindings is None:
        with pytest.raises(TypeError):
            build_plan_authorization_v2_payload(  # type: ignore[call-arg]
                _plan(),
                authorization_id="authz",
                authority_id="owner",
                issued_at=_times()[0],
                expires_at=_times()[1],
            )
        return
    with pytest.raises(SecurityAuthorizationError):
        _payload(bindings)  # type: ignore[arg-type]


def test_duplicate_exact_pair_and_duplicate_step_with_two_digests_are_rejected():
    with pytest.raises(SecurityAuthorizationError, match="duplicate step IDs"):
        _payload((_binding(), _binding()))
    with pytest.raises(SecurityAuthorizationError, match="duplicate step IDs"):
        _payload((_binding(digest=_DIGEST_X), _binding(digest=_DIGEST_Y)))


@pytest.mark.parametrize("step_id", ["", "*", "step.*", "step/child", " x", 1, None])
def test_malformed_wildcard_prefix_or_non_string_step_id_is_rejected(step_id):
    with pytest.raises(SecurityAuthorizationError, match="step_id"):
        PlanAuthorizationStepBinding(step_id=step_id, execution_intent_digest=_DIGEST_X)


@pytest.mark.parametrize("digest", ["", "a" * 63, "A" * 64, "g" * 64, 1, None, b"a" * 64])
def test_malformed_execution_intent_digest_is_rejected(digest):
    with pytest.raises(SecurityAuthorizationError, match="execution_intent_digest"):
        PlanAuthorizationStepBinding(step_id="step.a", execution_intent_digest=digest)


@pytest.mark.parametrize("version", [0, 1, 3, True, "2", None])
def test_unsupported_v2_schema_fails_closed(version):
    with pytest.raises(SecurityAuthorizationError, match="schema version"):
        _payload(schema_version=version)


def test_unexpected_binding_field_and_missing_digest_fail_by_typed_constructor():
    with pytest.raises(TypeError):
        PlanAuthorizationStepBinding(step_id="step.a")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        PlanAuthorizationStepBinding(  # type: ignore[call-arg]
            step_id="step.a", execution_intent_digest=_DIGEST_X, wildcard=False
        )


def test_unknown_step_is_rejected_against_exact_plan():
    with pytest.raises(SecurityAuthorizationError, match="not part"):
        _payload((_binding("step.unknown"),))


def test_binding_order_is_semantically_irrelevant_and_canonicalized():
    forward = _payload((_binding("step.a", _DIGEST_X), _binding("step.b", _DIGEST_Y)))
    reverse = _payload((_binding("step.b", _DIGEST_Y), _binding("step.a", _DIGEST_X)))

    assert plan_authorization_v2_signing_payload(forward) == plan_authorization_v2_signing_payload(reverse)


def test_step_digest_reassignment_changes_canonical_payload():
    original = _payload((_binding("step.a", _DIGEST_X), _binding("step.b", _DIGEST_Y)))
    swapped = _payload((_binding("step.a", _DIGEST_Y), _binding("step.b", _DIGEST_X)))

    assert plan_authorization_v2_signing_payload(original) != plan_authorization_v2_signing_payload(swapped)


def test_plan_digest_and_pair_set_are_independently_signed():
    original = _payload((_binding("step.a", _DIGEST_X),))
    different_pairs = _payload((_binding("step.a", _DIGEST_Y),))
    different_plan = replace(original, plan_digest=_DIGEST_Z)

    assert plan_authorization_v2_signing_payload(original) != plan_authorization_v2_signing_payload(different_pairs)
    assert plan_authorization_v2_signing_payload(original) != plan_authorization_v2_signing_payload(different_plan)


def test_v2_signing_payload_has_explicit_domain_and_no_v1_step_field():
    payload = plan_authorization_v2_signing_payload(_payload())

    assert b'"digest_purpose":"plan-authorization-v2"' in payload
    assert b'"schema_version":2' in payload
    assert b'"authorized_executions"' in payload
    assert b'"authorized_step_ids"' not in payload


def test_same_semantic_v2_payload_signs_deterministically_with_same_key():
    private, public = _keypair()
    bindings = (_binding("step.a", _DIGEST_X), _binding("step.b", _DIGEST_Y))
    first = _authz(private, bindings)
    second = _authz(private, tuple(reversed(bindings)))

    assert first.proof == second.proof
    assert verify_plan_authorization_v2_signature(first, _authorities(public))
    assert verify_plan_authorization_v2_signature(second, _authorities(public))


def test_valid_v2_signature_uses_active_pinned_authority():
    private, public = _keypair()
    assert verify_plan_authorization_v2_signature(_authz(private), _authorities(public))


def test_wrong_unknown_or_inactive_authority_is_rejected():
    private, public = _keypair()
    _, wrong_public = _keypair()
    authz = _authz(private)

    assert not verify_plan_authorization_v2_signature(authz, _authorities(wrong_public))
    assert not verify_plan_authorization_v2_signature(authz, _authorities(public, authority_id="other"))
    assert not verify_plan_authorization_v2_signature(authz, _authorities(public, active=False))


def test_unsigned_or_differently_signed_proof_is_rejected():
    private, public = _keypair()
    authz = _authz(private)
    assert not verify_plan_authorization_v2_signature(replace(authz, proof=b"\0" * 64), _authorities(public))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda a: replace(a, plan_digest=_DIGEST_Z),
        lambda a: replace(a, authorized_executions=(_binding("step.b", _DIGEST_X),)),
        lambda a: replace(a, authorized_executions=(_binding("step.a", _DIGEST_Y),)),
        lambda a: replace(a, authorized_executions=(_binding("step.a", _DIGEST_X), _binding("step.b", _DIGEST_Y))),
        lambda a: replace(a, authorization_id="other-authz"),
        lambda a: replace(a, expires_at=a.expires_at + timedelta(seconds=1)),
    ],
)
def test_mutating_any_signed_scope_field_invalidates_signature(mutation):
    private, public = _keypair()
    authz = _authz(private)

    assert not verify_plan_authorization_v2_signature(mutation(authz), _authorities(public))


def test_removed_pair_and_swapped_digests_invalidate_signature():
    private, public = _keypair()
    authz = _authz(private, (_binding("step.a", _DIGEST_X), _binding("step.b", _DIGEST_Y)))
    removed = replace(authz, authorized_executions=(_binding("step.a", _DIGEST_X),))
    swapped = replace(authz, authorized_executions=(_binding("step.a", _DIGEST_Y), _binding("step.b", _DIGEST_X)))

    assert not verify_plan_authorization_v2_signature(removed, _authorities(public))
    assert not verify_plan_authorization_v2_signature(swapped, _authorities(public))


def test_algorithm_downgrade_is_rejected_at_construction():
    with pytest.raises(SecurityAuthorizationError, match="algorithm"):
        _payload(algorithm="ed25519-v0")


def test_v1_and_v2_signatures_are_non_interchangeable():
    private, public = _keypair()
    issued, expires = _times()
    v1_payload = build_plan_authorization_payload(
        _plan(),
        ("step.a",),
        authorization_id="authz-v1",
        authority_id="owner-1",
        issued_at=issued,
        expires_at=expires,
    )
    v1 = sign_plan_authorization(v1_payload, private)
    v2 = _authz(private)

    assert plan_authorization_signing_payload(v1_payload) != plan_authorization_v2_signing_payload(_payload())
    assert not verify_plan_authorization_v2_signature(v1, _authorities(public))  # type: ignore[arg-type]
    assert not verify_plan_authorization_signature(v2, _authorities(public))  # type: ignore[arg-type]


def test_v1_cannot_be_relabelled_v2_or_v2_stripped_to_v1():
    private, _ = _keypair()
    v2 = _authz(private)
    with pytest.raises(TypeError):
        PlanAuthorizationV2(  # type: ignore[call-arg]
            schema_version=2,
            authorization_id=v2.authorization_id,
            plan_digest=v2.plan_digest,
            authority_id=v2.authority_id,
            algorithm=v2.algorithm,
            proof=v2.proof,
            issued_at=v2.issued_at,
            expires_at=v2.expires_at,
            risk_class=v2.risk_class,
            evidence_fingerprint=v2.evidence_fingerprint,
        )
    with pytest.raises(TypeError):
        PlanAuthorization(  # type: ignore[call-arg]
            schema_version=1,
            authorization_id=v2.authorization_id,
            plan_digest=v2.plan_digest,
            authority_id=v2.authority_id,
            algorithm=v2.algorithm,
            proof=v2.proof,
            issued_at=v2.issued_at,
            expires_at=v2.expires_at,
            risk_class=v2.risk_class,
            evidence_fingerprint=v2.evidence_fingerprint,
        )


def test_exact_v2_scope_requires_plan_step_and_digest_together():
    private, _ = _keypair()
    authz = _authz(private, (_binding("step.a", _DIGEST_X), _binding("step.b", _DIGEST_Y)))

    assert plan_authorization_v2_authorizes_execution(
        authz, plan_digest=authz.plan_digest, step_id="step.a", execution_intent_digest=_DIGEST_X
    )
    assert not plan_authorization_v2_authorizes_execution(
        authz, plan_digest=authz.plan_digest, step_id="step.a", execution_intent_digest=_DIGEST_Y
    )
    assert not plan_authorization_v2_authorizes_execution(
        authz, plan_digest=authz.plan_digest, step_id="step.b", execution_intent_digest=_DIGEST_X
    )
    assert not plan_authorization_v2_authorizes_execution(
        authz, plan_digest=_DIGEST_Z, step_id="step.a", execution_intent_digest=_DIGEST_X
    )
    assert not plan_authorization_v2_authorizes_execution(
        authz, plan_digest=authz.plan_digest, step_id="step", execution_intent_digest=_DIGEST_X
    )


def test_v2_reuses_exact_exclusive_expiry_semantics():
    private, _ = _keypair()
    authz = _authz(private)

    assert plan_authorization_is_current(authz, now=authz.expires_at - timedelta(microseconds=1))
    assert not plan_authorization_is_current(authz, now=authz.expires_at)
    assert not plan_authorization_is_current(authz, now=authz.expires_at + timedelta(seconds=1))


def test_signature_validity_implies_no_freshness_consumption_contract_or_recomputation(monkeypatch):
    private, public = _keypair()
    authz = _authz(private)
    monkeypatch.setattr(
        "pfsense_mcp.tier1.prepared_execution_intent.compute_execution_intent_digest",
        lambda _intent: pytest.fail("B2 verifier must not recompute B1 digest"),
    )

    assert verify_plan_authorization_v2_signature(authz, _authorities(public))
    assert not hasattr(authz, "fresh")
    assert not hasattr(authz, "consumed")
    assert not hasattr(authz, "recovery_contract")


def test_other_domain_digest_is_only_shape_valid_until_b3_b5_recomputation():
    plan_digest = compute_plan_digest(_plan())
    binding = _binding(digest=plan_digest)

    assert binding.execution_intent_digest == plan_digest
    # B2 authenticates this exact claimed value but intentionally cannot prove
    # its semantic origin. B3/B5 must recompute the B1 domain and compare it.
