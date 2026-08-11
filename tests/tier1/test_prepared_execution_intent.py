from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.tier1.canonical import DigestPurpose, digest_value
from pfsense_mcp.tier1.errors import PreparedExecutionIntentError
from pfsense_mcp.tier1.prepared_execution_intent import (
    PREPARED_EXECUTION_INTENT_SCHEMA_VERSION,
    PreparedExecutionIntentV1,
    compute_execution_intent_digest,
    prepared_execution_intent_payload_of,
)


def _values(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "schema_version": PREPARED_EXECUTION_INTENT_SCHEMA_VERSION,
        "capability": Capability.ALIAS_WRITE,
        "endpoint_symbol": "SYNTHETIC_ALIAS_DESCRIPTION",
        "http_method": "PATCH",
        "adapter_version": "alias-description-v1",
        "resource_target": {"name": "synthetic-target.invalid", "type": "host"},
        "target_precondition": {
            "name": "synthetic-target.invalid",
            "revision": "synthetic-1",
            "description": "before",
        },
        "normalized_mutation_intent": {
            "raw_target_hint": {"name": "synthetic-target.invalid", "revision": "synthetic-1"},
            "parameters": {"description": "after"},
        },
        "rollback_snapshot": {"description": "before"},
        "rollback_plan_version": "alias-description-rollback-v1",
    }
    values.update(changes)
    return values


def _intent(**changes: object) -> PreparedExecutionIntentV1:
    return PreparedExecutionIntentV1(**_values(**changes))  # type: ignore[arg-type]


def test_valid_complete_prepared_execution_intent():
    intent = _intent()

    assert intent.schema_version == 1
    assert intent.capability is Capability.ALIAS_WRITE
    assert intent.normalized_mutation_intent["parameters"] == {"description": "after"}
    assert len(compute_execution_intent_digest(intent)) == 64


def test_model_is_frozen_and_nested_values_are_defensive_copies():
    intent = _intent()

    with pytest.raises(FrozenInstanceError):
        intent.http_method = "DELETE"  # type: ignore[misc]

    target = intent.resource_target
    assert isinstance(target, dict)
    target["name"] = "mutated.invalid"
    nested_intent = intent.normalized_mutation_intent
    parameters = nested_intent["parameters"]
    assert isinstance(parameters, dict)
    parameters["description"] = "mutated"

    assert intent.resource_target == {"name": "synthetic-target.invalid", "type": "host"}
    assert intent.normalized_mutation_intent["parameters"] == {"description": "after"}


def test_mutating_constructor_inputs_after_creation_cannot_change_model_or_digest():
    selectors = ["a", "b"]
    parameters = {"description": "after"}
    resource_target = {"name": "synthetic-target.invalid", "selectors": selectors}
    mutation_intent = {"raw_target_hint": {}, "parameters": parameters}
    intent = _intent(resource_target=resource_target, normalized_mutation_intent=mutation_intent)
    digest = compute_execution_intent_digest(intent)

    resource_target["name"] = "mutated.invalid"
    selectors.reverse()
    parameters["description"] = "mutated"

    assert intent.resource_target == {"name": "synthetic-target.invalid", "selectors": ["a", "b"]}
    assert intent.normalized_mutation_intent["parameters"] == {"description": "after"}
    assert compute_execution_intent_digest(intent) == digest


@pytest.mark.parametrize("schema_version", [0, 2, True, "1", None])
def test_unsupported_schema_versions_fail_closed(schema_version):
    with pytest.raises(PreparedExecutionIntentError, match="schema version"):
        _intent(schema_version=schema_version)


@pytest.mark.parametrize("capability", [Capability.SYSTEM_READ, "ALIAS_WRITE", 1, None])
def test_malformed_or_non_write_capability_is_rejected(capability):
    with pytest.raises(PreparedExecutionIntentError, match="WRITE capability"):
        _intent(capability=capability)


@pytest.mark.parametrize("endpoint_symbol", ["", "unsafe/path", "x" * 129, 1, None])
def test_malformed_endpoint_is_rejected(endpoint_symbol):
    with pytest.raises(PreparedExecutionIntentError, match="identifier"):
        _intent(endpoint_symbol=endpoint_symbol)


@pytest.mark.parametrize("method", ["GET", "patch", "TRACE", "", 1, None])
def test_malformed_or_non_mutating_method_is_rejected(method):
    with pytest.raises(PreparedExecutionIntentError, match="HTTP method"):
        _intent(http_method=method)


@pytest.mark.parametrize("field", ["adapter_version", "rollback_plan_version"])
@pytest.mark.parametrize("value", ["", "unsafe/version", "x" * 129, 1, None])
def test_malformed_semantics_versions_are_rejected(field, value):
    with pytest.raises(PreparedExecutionIntentError, match="identifier"):
        _intent(**{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("resource_target", None),
        ("resource_target", 1.5),
        ("resource_target", b"target"),
        ("target_precondition", None),
        ("target_precondition", {1: "bad-key"}),
        ("normalized_mutation_intent", None),
        ("normalized_mutation_intent", ["not", "an", "object"]),
        ("normalized_mutation_intent", {"value": object()}),
        ("rollback_snapshot", None),
        ("rollback_snapshot", {"value": 1.5}),
    ],
)
def test_malformed_canonical_fields_are_rejected(field, value):
    with pytest.raises(PreparedExecutionIntentError):
        _intent(**{field: value})


def test_unknown_constructor_field_is_rejected():
    values = _values()
    values["authorization_id"] = "must-not-enter-b1"
    with pytest.raises(TypeError):
        PreparedExecutionIntentV1(**values)  # type: ignore[arg-type]


def test_repeated_payload_and_digest_are_deterministic():
    intent = _intent()

    assert prepared_execution_intent_payload_of(intent) == prepared_execution_intent_payload_of(intent)
    assert compute_execution_intent_digest(intent) == compute_execution_intent_digest(intent)


def test_semantically_irrelevant_object_insertion_order_normalizes_identically():
    forward = _intent(
        resource_target={"name": "synthetic-target.invalid", "type": "host"},
        normalized_mutation_intent={
            "raw_target_hint": {"name": "synthetic-target.invalid", "revision": "synthetic-1"},
            "parameters": {"description": "after", "enabled": True},
        },
    )
    reversed_order = _intent(
        resource_target={"type": "host", "name": "synthetic-target.invalid"},
        normalized_mutation_intent={
            "parameters": {"enabled": True, "description": "after"},
            "raw_target_hint": {"revision": "synthetic-1", "name": "synthetic-target.invalid"},
        },
    )

    assert prepared_execution_intent_payload_of(forward) == prepared_execution_intent_payload_of(reversed_order)
    assert compute_execution_intent_digest(forward) == compute_execution_intent_digest(reversed_order)


def test_semantic_list_order_remains_distinct():
    forward = _intent(normalized_mutation_intent={"raw_target_hint": {}, "parameters": {"members": ["a", "b"]}})
    reversed_order = _intent(normalized_mutation_intent={"raw_target_hint": {}, "parameters": {"members": ["b", "a"]}})

    assert compute_execution_intent_digest(forward) != compute_execution_intent_digest(reversed_order)


def test_explicit_null_and_missing_remain_distinct():
    explicit_null = _intent(normalized_mutation_intent={"raw_target_hint": {}, "parameters": {"description": None}})
    missing = _intent(normalized_mutation_intent={"raw_target_hint": {}, "parameters": {}})

    assert compute_execution_intent_digest(explicit_null) != compute_execution_intent_digest(missing)


def test_empty_collection_and_missing_field_remain_distinct():
    empty = _intent(normalized_mutation_intent={"raw_target_hint": {}, "parameters": {"members": []}})
    missing = _intent(normalized_mutation_intent={"raw_target_hint": {}, "parameters": {}})

    assert compute_execution_intent_digest(empty) != compute_execution_intent_digest(missing)


def test_unicode_is_normalized_without_repr_dependence():
    composed = _intent(normalized_mutation_intent={"raw_target_hint": {}, "parameters": {"value": "é"}})
    decomposed = _intent(normalized_mutation_intent={"raw_target_hint": {}, "parameters": {"value": "e\u0301"}})

    assert compute_execution_intent_digest(composed) == compute_execution_intent_digest(decomposed)
    assert "_FrozenCanonical" not in str(prepared_execution_intent_payload_of(composed))


def test_unicode_normalization_duplicate_keys_fail_closed():
    with pytest.raises(PreparedExecutionIntentError):
        _intent(normalized_mutation_intent={"raw_target_hint": {}, "é": 1, "e\u0301": 2})


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("1", 1),
        (True, 1),
        (None, ""),
    ],
)
def test_canonical_collision_traps_remain_distinct(left, right):
    a = _intent(normalized_mutation_intent={"raw_target_hint": {}, "parameters": {"value": left}})
    b = _intent(normalized_mutation_intent={"raw_target_hint": {}, "parameters": {"value": right}})

    assert compute_execution_intent_digest(a) != compute_execution_intent_digest(b)


def test_enum_name_string_cannot_replace_enum_value():
    with pytest.raises(PreparedExecutionIntentError):
        _intent(capability="ALIAS_WRITE")


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("schema_version", 2),
        ("capability", Capability.FIREWALL_WRITE),
        ("endpoint_symbol", "OTHER_SYNTHETIC_ENDPOINT"),
        ("http_method", "DELETE"),
        ("adapter_version", "alias-description-v2"),
        ("resource_target", {"name": "other.invalid", "type": "host"}),
        ("target_precondition", {"revision": "synthetic-2"}),
        (
            "normalized_mutation_intent",
            {"raw_target_hint": {"name": "synthetic-target.invalid"}, "parameters": {"description": "other"}},
        ),
        (
            "normalized_mutation_intent",
            {
                "raw_target_hint": {"name": "synthetic-target.invalid"},
                "parameters": {"description": "after", "enabled": True},
            },
        ),
        ("rollback_snapshot", {"description": "different-before"}),
        ("rollback_plan_version", "alias-description-rollback-v2"),
    ],
)
def test_every_security_critical_field_is_digest_load_bearing(field, changed):
    baseline = _intent()
    if field == "schema_version":
        with pytest.raises(PreparedExecutionIntentError):
            _intent(**{field: changed})
        return

    assert compute_execution_intent_digest(baseline) != compute_execution_intent_digest(_intent(**{field: changed}))


def test_digest_uses_exact_execution_intent_domain_and_version_context():
    intent = _intent()
    payload = prepared_execution_intent_payload_of(intent)

    assert compute_execution_intent_digest(intent) == digest_value(
        DigestPurpose.EXECUTION_INTENT,
        payload,
        context=("PreparedExecutionIntentV1",),
    )


@pytest.mark.parametrize(
    "other_purpose",
    [
        DigestPurpose.PLAN,
        DigestPurpose.INTENT,
        DigestPurpose.TARGET_IDENTITY,
        DigestPurpose.TARGET_FINGERPRINT,
        DigestPurpose.SNAPSHOT,
        DigestPurpose.IDEMPOTENCY,
        DigestPurpose.CONFIRMATION,
        DigestPurpose.PLAN_AUTHORIZATION,
    ],
)
def test_existing_digest_domains_are_not_execution_intent_domain(other_purpose):
    intent = _intent()
    payload = prepared_execution_intent_payload_of(intent)

    assert compute_execution_intent_digest(intent) != digest_value(
        other_purpose,
        payload,
        context=("PreparedExecutionIntentV1",),
    )


def test_digest_api_never_accepts_a_precomputed_digest_or_payload():
    digest = compute_execution_intent_digest(_intent())
    with pytest.raises(PreparedExecutionIntentError):
        compute_execution_intent_digest(digest)  # type: ignore[arg-type]
    with pytest.raises(PreparedExecutionIntentError):
        compute_execution_intent_digest(_values())  # type: ignore[arg-type]


def test_payload_api_returns_fresh_nested_values():
    intent = _intent()
    payload = prepared_execution_intent_payload_of(intent)
    target = payload["resource_target"]
    assert isinstance(target, dict)
    target["name"] = "mutated.invalid"

    assert prepared_execution_intent_payload_of(intent)["resource_target"] == {
        "name": "synthetic-target.invalid",
        "type": "host",
    }


def test_payload_excludes_authorization_provenance_lifecycle_and_appliance_identity():
    payload = prepared_execution_intent_payload_of(_intent())

    assert set(payload) == {
        "schema_version",
        "capability",
        "endpoint_symbol",
        "http_method",
        "adapter_version",
        "resource_target",
        "target_precondition",
        "normalized_mutation_intent",
        "rollback_snapshot",
        "rollback_plan_version",
    }
    assert not set(payload) & {
        "authorization_id",
        "plan_digest",
        "step_id",
        "expires_at",
        "contract_id",
        "state",
        "target_identity_digest",
        "appliance_identity",
    }
