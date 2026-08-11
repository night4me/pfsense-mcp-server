"""Cross-module adversarial tests proving Phase D's three verification
primitives (`security_authorization_verifier.py`) and its consumption
store (`tier1/authorization_consumption_store.py`) remain genuinely
independent -- signature verification success must not imply
consumption, and consumption must not imply signature validity. No
production caller composes these two modules anywhere in this
repository; these tests are the only place they are used together, and
only to prove independence, never to build a combined "verify and
execute" primitive.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pfsense_mcp.security_authorization import build_plan_authorization_payload, sign_plan_authorization
from pfsense_mcp.security_authorization_verifier import verify_plan_authorization_signature
from pfsense_mcp.security_plan import AuthorizationLevel
from pfsense_mcp.tier1.authorization_consumption_store import SqliteAuthorizationConsumptionStore
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from tests.test_security_plan_digest import _synthetic_plan, _synthetic_step

_KEY_MATERIAL = b"synthetic-test-integrity-key-32bytes!"


def _keypair():
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return private_key, public_bytes


def _store(tmp_path):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return SqliteAuthorizationConsumptionStore(
        tmp_path / "consumed.sqlite3", integrity_key=_KEY_MATERIAL, store_id="integration-store"
    )


def _signed_authorization(private_key, *, authorization_id="authz-1"):
    plan = _synthetic_plan(
        steps=(_synthetic_step(step_id="s1", order=1, authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE),)
    )
    issued = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc)
    payload = build_plan_authorization_payload(
        plan,
        ("s1",),
        authorization_id=authorization_id,
        authority_id="owner-1",
        issued_at=issued,
        expires_at=issued + timedelta(seconds=300),
    )
    return sign_plan_authorization(payload, private_key)


def test_signature_verification_success_does_not_consume_anything(tmp_path):
    """Verifying a signature must have zero effect on consumption
    state -- calling verify_plan_authorization_signature() any number
    of times must never itself mark an authorization_id as consumed."""

    key, public_bytes = _keypair()
    authorities = PinnedAuthoritySet((PinnedAuthority(authority_id="owner-1", public_key=public_bytes),))
    authz = _signed_authorization(key)
    store = _store(tmp_path)

    for _ in range(5):
        assert verify_plan_authorization_signature(authz, authorities) is True

    # Verification alone never touched the consumption store -- the
    # authorization_id must still be available for a genuine first
    # consumption.
    assert store.try_consume(authz.authorization_id) is True


def test_consumption_cannot_make_an_invalid_signature_valid(tmp_path):
    """Consuming an authorization_id (a pure bookkeeping operation on an
    opaque string) must have zero effect on whether a *different*,
    forged PlanAuthorization's signature verifies. The two checks never
    influence each other in either direction."""

    key, public_bytes = _keypair()
    authorities = PinnedAuthoritySet((PinnedAuthority(authority_id="owner-1", public_key=public_bytes),))
    authz = _signed_authorization(key)
    store = _store(tmp_path)

    from pfsense_mcp.security_authorization import PlanAuthorization

    forged = PlanAuthorization(
        schema_version=authz.schema_version,
        authorization_id=authz.authorization_id,
        plan_digest=authz.plan_digest,
        authorized_step_ids=authz.authorized_step_ids,
        authority_id=authz.authority_id,
        algorithm=authz.algorithm,
        proof=key.sign(b"not the real signing payload"),
        issued_at=authz.issued_at,
        expires_at=authz.expires_at,
        risk_class=authz.risk_class,
        evidence_fingerprint=authz.evidence_fingerprint,
    )
    assert verify_plan_authorization_signature(forged, authorities) is False

    # Consuming the (shared) authorization_id string has no bearing on
    # the forged artifact's own signature validity -- it remains False
    # before and after.
    assert store.try_consume(authz.authorization_id) is True
    assert verify_plan_authorization_signature(forged, authorities) is False


def test_verification_and_consumption_are_two_separately_required_gates(tmp_path):
    """A caller (still unbuilt anywhere in this repository) that wanted
    to require 'signed by a trusted authority AND not yet consumed'
    would need both checks to independently pass -- this test proves
    each can independently fail while the other independently
    succeeds, exactly as Phase D's own invariants require."""

    key, public_bytes = _keypair()
    authorities = PinnedAuthoritySet((PinnedAuthority(authority_id="owner-1", public_key=public_bytes),))
    authz = _signed_authorization(key)
    store = _store(tmp_path)

    # Valid signature, not yet consumed -- both gates pass.
    assert verify_plan_authorization_signature(authz, authorities) is True
    assert store.try_consume(authz.authorization_id) is True

    # Valid signature, but now already consumed -- signature gate still
    # passes; consumption gate now fails.
    assert verify_plan_authorization_signature(authz, authorities) is True
    assert store.try_consume(authz.authorization_id) is False

    # A different, never-consumed authorization_id with an invalid
    # signature -- consumption gate would pass; signature gate fails.
    _, wrong_public_bytes = _keypair()
    wrong_authorities = PinnedAuthoritySet((PinnedAuthority(authority_id="owner-1", public_key=wrong_public_bytes),))
    other_authz = _signed_authorization(key, authorization_id="authz-2")
    assert verify_plan_authorization_signature(other_authz, wrong_authorities) is False
    assert store.try_consume(other_authz.authorization_id) is True
