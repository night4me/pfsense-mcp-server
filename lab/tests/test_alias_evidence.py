from __future__ import annotations

import pytest
from pydantic import ValidationError

from lab.alias_evidence import _DESCRIPTION_CASES, AliasDescriptionAdapter, AliasDescriptionRequest, AliasState
from pfsense_mcp.tier1.executor import ResolvedTransportTarget


def _state(*, name: str = "LAB_ALIAS_TEST", locator: int = 7, descr: str = "before") -> AliasState:
    return AliasState(
        name=name,
        numeric_locator=locator,
        alias_type="host",
        descr=descr,
        address=("192.0.2.1",),
        detail=("synthetic",),
    )


def test_request_is_closed_frozen_and_defaults_apply_false() -> None:
    request = AliasDescriptionRequest(id=7, descr="after")

    assert request.model_dump() == {"id": 7, "descr": "after", "apply": False}
    with pytest.raises(ValidationError):
        request.descr = "substituted"
    with pytest.raises(ValidationError):
        AliasDescriptionRequest(id=7, descr="after", payload={})  # type: ignore[call-arg]


@pytest.mark.parametrize("locator", [True, "7"])
def test_request_rejects_ambiguous_locator_type(locator: object) -> None:
    with pytest.raises(ValidationError):
        AliasDescriptionRequest(id=locator, descr="after")  # type: ignore[arg-type]


@pytest.mark.parametrize("field,value", [("descr", 1), ("apply", "false"), ("id", "0")])
def test_request_rejects_malformed_field_types(field: str, value: object) -> None:
    payload: dict[str, object] = {"id": 0, "descr": "after", "apply": False}
    payload[field] = value
    with pytest.raises(ValidationError):
        AliasDescriptionRequest.model_validate(payload)


def test_fingerprint_binds_complete_ordered_adr026_tuple() -> None:
    original = _state()
    fingerprint = original.fingerprint()

    assert tuple(fingerprint) == ("name", "type", "descr", "address", "detail")
    assert fingerprint["address"] == ["192.0.2.1"]
    assert fingerprint["detail"] == ["synthetic"]
    changed_order = AliasState(
        original.name,
        original.numeric_locator,
        original.alias_type,
        original.descr,
        ("192.0.2.2", "192.0.2.1"),
        ("second", "synthetic"),
    )
    assert changed_order.fingerprint() != original.fingerprint()


def test_request_uses_only_executor_resolved_transport_locator() -> None:
    adapter = AliasDescriptionAdapter()
    target = ResolvedTransportTarget(numeric_locator=9, target_identity_digest="a" * 64)

    request = adapter.build_request({"descr": "after"}, target)

    assert request == AliasDescriptionRequest(id=9, descr="after", apply=False)


def test_stateless_adapter_does_not_retain_locator() -> None:
    adapter = AliasDescriptionAdapter()
    target_7 = ResolvedTransportTarget(numeric_locator=7, target_identity_digest="a" * 64)
    target_9 = ResolvedTransportTarget(numeric_locator=9, target_identity_digest="a" * 64)

    request_7 = adapter.build_request({"descr": "one"}, target_7)
    request_9 = adapter.build_request({"descr": "two"}, target_9)
    assert isinstance(request_7, AliasDescriptionRequest)
    assert isinstance(request_9, AliasDescriptionRequest)
    assert request_7.id == 7
    assert request_9.id == 9
    assert vars(adapter) == {}


def test_semantic_verification_rejects_every_forbidden_field_change() -> None:
    adapter = AliasDescriptionAdapter()
    before = _state()
    expected = _state(descr="after")
    assert adapter.is_semantically_verified(before, expected, {"descr": "after"})

    variants = (
        AliasState("OTHER", 7, "host", "after", before.address, before.detail),
        AliasState(before.name, 7, "network", "after", before.address, before.detail),
        AliasState(before.name, 7, "host", "after", ("192.0.2.2",), before.detail),
        AliasState(before.name, 7, "host", "after", before.address, ("changed",)),
    )
    assert all(not adapter.is_semantically_verified(before, item, {"descr": "after"}) for item in variants)


def test_rollback_verification_requires_exact_original_fingerprint() -> None:
    adapter = AliasDescriptionAdapter()
    original = _state()

    assert adapter.is_rollback_verified(original.fingerprint(), original)
    assert not adapter.is_rollback_verified(original.fingerprint(), _state(descr="not-restored"))


def test_stage3_cases_are_closed_named_values() -> None:
    assert len(_DESCRIPTION_CASES) == 25
    assert _DESCRIPTION_CASES["empty"] == ""
    assert len(_DESCRIPTION_CASES["length-1024"]) == 1024
    assert len(_DESCRIPTION_CASES["length-1025"]) == 1025
    assert len(_DESCRIPTION_CASES["length-4096"]) == 4096


def test_decomposed_case_is_distinct_before_the_canonical_boundary() -> None:
    assert _DESCRIPTION_CASES["nfd"] != _DESCRIPTION_CASES["nfc"]
    assert len(_DESCRIPTION_CASES["nfd"]) == len(_DESCRIPTION_CASES["nfc"]) + 1
