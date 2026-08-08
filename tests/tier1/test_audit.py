from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.tier1.audit import Tier1AuditEvent
from pfsense_mcp.tier1.state_machine import RecoveryState


def _event(exception_class: str | None = None) -> Tier1AuditEvent:
    return Tier1AuditEvent(
        timestamp=datetime.now(timezone.utc),
        event_id="event-001",
        contract_id="contract-001",
        operation_id="operation-001",
        capability=Capability.ALIAS_WRITE,
        endpoint_symbol="SYNTHETIC_ENDPOINT",
        http_method="PATCH",
        target_identity_digest="a" * 64,
        intent_digest="b" * 64,
        outcome="refused",
        previous_state=RecoveryState.PREPARED,
        current_state=RecoveryState.FAILED,
        failure_class="binding_mismatch",
        exception_class=exception_class,
    )


def test_audit_event_is_single_line_value_free_json():
    encoded = _event("ContractBindingError").to_json()
    parsed = json.loads(encoded)

    assert "\n" not in encoded
    assert parsed["capability"] == "ALIAS_WRITE"
    assert parsed["exception_class"] == "ContractBindingError"
    for prohibited in ("payload", "snapshot", "credential", "response", "message"):
        assert prohibited not in parsed


@pytest.mark.parametrize("unsafe", ["Error\nforged", "module.Error", "", "x" * 129])
def test_audit_refuses_unsafe_exception_class(unsafe):
    with pytest.raises(ValueError):
        _event(unsafe)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("outcome", "failed\nsecret"),
        ("failure_class", "transport payload"),
        ("event_id", "event/value"),
    ],
)
def test_untrusted_audit_metadata_cannot_inject_values(field, value):
    with pytest.raises(ValueError, match="unsafe token"):
        replace(_event(), **{field: value})


@pytest.mark.parametrize(
    "changes",
    [
        {"timestamp": datetime.now()},
        {"capability": Capability.SYSTEM_READ},
        {"http_method": "GET"},
        {"target_identity_digest": "bad"},
        {"intent_digest": "bad"},
    ],
)
def test_invalid_audit_authority_metadata_is_refused(changes):
    with pytest.raises(ValueError):
        replace(_event(), **changes)
