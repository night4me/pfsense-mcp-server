from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.tier1.contract import ProtectedArtifact
from pfsense_mcp.tier1.errors import ContractBindingError, ContractValidationError
from pfsense_mcp.tier1.state_machine import RecoveryState


def test_exact_bindings_pass(contract_factory):
    contract = contract_factory()

    contract.verify_bindings(
        capability=Capability.ALIAS_WRITE,
        endpoint_symbol="SYNTHETIC_ENDPOINT",
        http_method="PATCH",
        target_identity={"name": "synthetic-target.invalid"},
        target_precondition={
            "identity": {"name": "synthetic-target.invalid"},
            "revision": "synthetic-1",
        },
        normalized_intent={"enabled": True},
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("capability", Capability.FIREWALL_WRITE),
        ("endpoint_symbol", "OTHER_ENDPOINT"),
        ("http_method", "DELETE"),
        ("target_identity", {"name": "other.invalid"}),
        ("target_precondition", {"revision": "stale"}),
        ("normalized_intent", {"enabled": False}),
    ],
)
def test_any_binding_drift_is_refused(contract_factory, field, value):
    contract = contract_factory()
    supplied = {
        "capability": Capability.ALIAS_WRITE,
        "endpoint_symbol": "SYNTHETIC_ENDPOINT",
        "http_method": "PATCH",
        "target_identity": {"name": "synthetic-target.invalid"},
        "target_precondition": {
            "identity": {"name": "synthetic-target.invalid"},
            "revision": "synthetic-1",
        },
        "normalized_intent": {"enabled": True},
    }
    supplied[field] = value

    with pytest.raises(ContractBindingError, match="does not match"):
        contract.verify_bindings(**supplied)


def test_confirmation_is_digest_bound_and_single_use(contract_factory):
    contract = contract_factory(state=RecoveryState.PREPARED)
    confirmed = contract.with_confirmation(
        authority_id="owner-approval",
        evidence_digest="e" * 64,
        confirmed_at=datetime.now(timezone.utc),
    )

    assert confirmed.is_confirmed
    assert confirmed.state == RecoveryState.PREPARED
    assert confirmed.state_version == 1
    assert len(confirmed.confirmation_digest) == 64
    with pytest.raises(ContractBindingError):
        confirmed.with_confirmation(
            authority_id="replay", evidence_digest="e" * 64, confirmed_at=datetime.now(timezone.utc)
        )


@pytest.mark.parametrize("authority_id", ["", "owner\nforged", "x" * 129])
def test_confirmation_authority_identifier_is_bounded_and_safe(contract_factory, authority_id):
    contract = contract_factory(state=RecoveryState.PREPARED)
    with pytest.raises(ContractValidationError, match="authority identifier"):
        contract.with_confirmation(
            authority_id=authority_id, evidence_digest="e" * 64, confirmed_at=contract.created_at
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"contract_id": "unsafe/id"},
        {"capability": Capability.SYSTEM_READ},
        {"http_method": "GET"},
        {"intent_digest": "not-a-digest"},
        {"created_at": datetime.now()},
        {"expires_at": datetime.now(timezone.utc) - timedelta(minutes=1)},
        {"state_version": -1},
        {"lifecycle_locator": -1},
        {"lifecycle_locator": True},
        {"lifecycle_locator": "7"},
        {"lifecycle_locator": 7.0},
        {"lifecycle_locator": 2_147_483_648},
        {"confirmation_digest": "a" * 64},
    ],
)
def test_invalid_contract_boundaries_fail_closed(contract_factory, changes):
    with pytest.raises(ContractValidationError):
        replace(contract_factory(), **changes)


def test_confirmation_must_be_inside_contract_window(contract_factory):
    contract = contract_factory(state=RecoveryState.PREPARED)
    with pytest.raises(ContractValidationError, match="validity window"):
        contract.with_confirmation(authority_id="owner", evidence_digest="e" * 64, confirmed_at=contract.expires_at)


def test_contract_times_must_be_utc(contract_factory):
    non_utc = timezone(timedelta(hours=1))
    with pytest.raises(ContractValidationError, match="timestamps must be UTC"):
        replace(contract_factory(), created_at=datetime.now(non_utc))

    contract = contract_factory()
    with pytest.raises(ContractValidationError, match="comparison time must be UTC"):
        contract.is_expired(now=datetime.now(non_utc))


def test_is_permanently_unresumable_false_for_fresh_prepared_contract(contract_factory):
    contract = contract_factory(state=RecoveryState.PREPARED)
    assert contract.is_permanently_unresumable(now=contract.created_at) is False


def test_is_permanently_unresumable_true_for_expired_prepared_contract(contract_factory):
    contract = contract_factory(state=RecoveryState.PREPARED)
    assert contract.is_permanently_unresumable(now=contract.expires_at) is True


@pytest.mark.parametrize(
    "state",
    [
        RecoveryState.PREPARING,
        RecoveryState.EXECUTING,
        RecoveryState.ROLLBACK_FAILED,
    ],
)
def test_is_permanently_unresumable_false_for_non_prepared_states_even_if_expired(contract_factory, state):
    # This mirrors resume_prepared()'s own gate exactly: only a PREPARED
    # contract is ever eligible for resumption at all, so expiry alone
    # never marks a non-PREPARED contract "permanently unresumable" via
    # this helper -- that concept only applies to the PREPARED state.
    # (VERIFIED/ROLLING_BACK are exercised in
    # test_is_permanently_unresumable_false_for_verified_even_if_expired
    # below -- the factory can't build them without a
    # verified_target_fingerprint.)
    contract = contract_factory(state=state)
    assert contract.is_permanently_unresumable(now=contract.expires_at) is False


def test_is_permanently_unresumable_false_for_verified_even_if_expired(contract_factory):
    contract = contract_factory(state=RecoveryState.PREPARED)
    verified = replace(contract, state=RecoveryState.VERIFIED, verified_target_fingerprint="a" * 64)
    assert verified.is_permanently_unresumable(now=verified.expires_at) is False


def test_is_permanently_unresumable_requires_utc_now(contract_factory):
    non_utc = timezone(timedelta(hours=1))
    contract = contract_factory(state=RecoveryState.PREPARED)
    with pytest.raises(ContractValidationError, match="comparison time must be UTC"):
        contract.is_permanently_unresumable(now=datetime.now(non_utc))


def test_idempotency_key_is_derived_from_all_mutation_bindings(contract_factory):
    contract = contract_factory()
    for field in (
        "target_identity_digest",
        "target_fingerprint",
        "intent_digest",
        "snapshot_digest",
        "rollback_plan_version",
        "lifecycle_locator",
    ):
        changed = (
            "f" * 64
            if field.endswith("digest") or field == "target_fingerprint"
            else 9
            if field == "lifecycle_locator"
            else "other-v1"
        )
        with pytest.raises(ContractValidationError, match="idempotency binding"):
            replace(contract, **{field: changed})


@pytest.mark.parametrize(
    "artifact",
    [
        lambda: ProtectedArtifact(key_id="key", algorithm="alg", ciphertext=b""),
        lambda: ProtectedArtifact(key_id="key", algorithm="alg", ciphertext=b"x" * 1_048_577),
        lambda: ProtectedArtifact(key_id="unsafe/key", algorithm="alg", ciphertext=b"x"),
        lambda: ProtectedArtifact(key_id="key", algorithm="alg", ciphertext=bytearray(b"x")),
    ],
)
def test_protected_artifact_rejects_unsafe_or_unbounded_values(artifact):
    with pytest.raises(ContractValidationError):
        artifact()


def test_verified_target_fingerprint_is_optional_but_structurally_validated(contract_factory):
    contract = contract_factory()
    assert contract.verified_target_fingerprint is None
    verified = replace(
        contract,
        state=RecoveryState.VERIFIED,
        verified_target_fingerprint="a" * 64,
    )
    assert verified.verified_target_fingerprint == "a" * 64
    with pytest.raises(ContractValidationError, match="Verified target fingerprint"):
        replace(contract, state=RecoveryState.VERIFIED, verified_target_fingerprint="not-a-digest")


def test_verified_target_fingerprint_cannot_be_injected_before_execution(contract_factory):
    with pytest.raises(ContractValidationError, match="state and verified target fingerprint"):
        replace(contract_factory(), verified_target_fingerprint="a" * 64)
    with pytest.raises(ContractValidationError, match="state and verified target fingerprint"):
        replace(contract_factory(), state=RecoveryState.VERIFIED)


@pytest.mark.parametrize("locator", [False, True, -1, 2_147_483_648, "7", 7.0, None])
def test_resolved_transport_target_rejects_ambiguous_or_unbounded_locator(locator):
    from pfsense_mcp.tier1.executor import ResolvedTransportTarget

    with pytest.raises(Exception, match="transport locator") as exc_info:
        ResolvedTransportTarget(numeric_locator=locator, target_identity_digest="a" * 64)
    assert type(exc_info.value).__name__ == "ContractValidationError"


@pytest.mark.parametrize("identity_digest", ["A" * 64, "a" * 63, "a" * 65, "not-hex", b"a" * 64])
def test_resolved_transport_target_requires_exact_canonical_identity_digest(identity_digest):
    from pfsense_mcp.tier1.executor import ResolvedTransportTarget

    with pytest.raises(Exception, match="target identity") as exc_info:
        ResolvedTransportTarget(numeric_locator=7, target_identity_digest=identity_digest)
    assert type(exc_info.value).__name__ == "ContractValidationError"
