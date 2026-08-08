from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.tier1.errors import ContractBindingError, ContractValidationError
from pfsense_mcp.tier1.state_machine import RecoveryState


def test_exact_bindings_pass(contract_factory):
    contract = contract_factory()

    contract.verify_bindings(
        capability=Capability.ALIAS_WRITE,
        endpoint_symbol="SYNTHETIC_ENDPOINT",
        http_method="PATCH",
        target_identity={"name": "synthetic-target.invalid"},
        normalized_intent={"enabled": True},
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("capability", Capability.FIREWALL_WRITE),
        ("endpoint_symbol", "OTHER_ENDPOINT"),
        ("http_method", "DELETE"),
        ("target_identity", {"name": "other.invalid"}),
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
        "normalized_intent": {"enabled": True},
    }
    supplied[field] = value

    with pytest.raises(ContractBindingError, match="does not match"):
        contract.verify_bindings(**supplied)


def test_confirmation_is_digest_bound_and_single_use(contract_factory):
    contract = contract_factory()
    confirmed = contract.with_confirmation(actor_id="owner-approval", confirmed_at=datetime.now(timezone.utc))

    assert confirmed.is_confirmed
    assert confirmed.state == RecoveryState.PREPARED
    assert confirmed.state_version == 1
    assert len(confirmed.confirmation_digest) == 64
    with pytest.raises(ContractBindingError):
        confirmed.with_confirmation(actor_id="replay", confirmed_at=datetime.now(timezone.utc))


@pytest.mark.parametrize("actor_id", ["", "owner\nforged", "x" * 129])
def test_confirmation_actor_identifier_is_bounded_and_safe(contract_factory, actor_id):
    contract = contract_factory()
    with pytest.raises(ContractValidationError, match="actor identifier"):
        contract.with_confirmation(actor_id=actor_id, confirmed_at=contract.created_at)


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
        {"confirmation_digest": "a" * 64},
    ],
)
def test_invalid_contract_boundaries_fail_closed(contract_factory, changes):
    with pytest.raises(ContractValidationError):
        replace(contract_factory(), **changes)


def test_confirmation_must_be_inside_contract_window(contract_factory):
    contract = contract_factory()
    with pytest.raises(ContractValidationError, match="validity window"):
        contract.with_confirmation(actor_id="owner", confirmed_at=contract.expires_at)


def test_contract_times_must_be_utc(contract_factory):
    non_utc = timezone(timedelta(hours=1))
    with pytest.raises(ContractValidationError, match="timestamps must be UTC"):
        replace(contract_factory(), created_at=datetime.now(non_utc))

    contract = contract_factory()
    with pytest.raises(ContractValidationError, match="comparison time must be UTC"):
        contract.is_expired(now=datetime.now(non_utc))
