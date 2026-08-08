from __future__ import annotations

import pytest

from pfsense_mcp.tier1.canonical import DigestPurpose, canonical_json, digest_value
from pfsense_mcp.tier1.errors import CanonicalizationError


def test_canonical_json_is_key_order_independent_and_unicode_normalized():
    composed = {"é": [1, True, None], "a": "value"}
    decomposed = {"a": "value", "e\u0301": [1, True, None]}

    assert canonical_json(composed) == canonical_json(decomposed)


@pytest.mark.parametrize("value", [1.5, b"bytes", {1: "not-a-string-key"}, {"x": object()}])
def test_canonical_json_rejects_ambiguous_or_unsupported_values(value):
    with pytest.raises(CanonicalizationError):
        canonical_json(value)


def test_normalized_duplicate_keys_are_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_json({"é": 1, "e\u0301": 2})


def test_digest_is_stable_and_domain_separated():
    value = {"target": "synthetic.invalid", "enabled": True}
    first = digest_value(DigestPurpose.INTENT, value, context=("ALIAS_WRITE",))
    second = digest_value(DigestPurpose.INTENT, value, context=("ALIAS_WRITE",))
    target = digest_value(DigestPurpose.TARGET_IDENTITY, value, context=("ALIAS_WRITE",))

    assert first == second
    assert first != target
    assert len(first) == 64


def test_digest_context_uses_unambiguous_framing():
    value = {"intent": "same"}
    assert digest_value(DigestPurpose.INTENT, value, context=("A\0B", "C")) != digest_value(
        DigestPurpose.INTENT, value, context=("A", "B\0C")
    )


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (True, 1),
        (None, ""),
        (["a", "b"], ["b", "a"]),
        ({"present": None}, {}),
        ("paypal", "pаypal"),  # second value contains Cyrillic 'a'
        (" ", ""),
    ],
)
def test_meaningfully_different_values_remain_distinct(left, right):
    assert canonical_json(left) != canonical_json(right)


def test_nested_object_order_is_deterministic():
    assert canonical_json({"z": {"b": 2, "a": 1}, "a": [3, 2, 1]}) == canonical_json(
        {"a": [3, 2, 1], "z": {"a": 1, "b": 2}}
    )


@pytest.mark.parametrize(
    "value",
    [
        2**63,
        -(2**63) - 1,
        "\ud800",
        "x" * 65_537,
        [None] * 4_097,
    ],
)
def test_resource_and_utf8_boundaries_fail_closed(value):
    with pytest.raises(CanonicalizationError):
        canonical_json(value)


def test_excessive_nesting_fails_closed():
    value: object = None
    for _ in range(34):
        value = [value]
    with pytest.raises(CanonicalizationError, match="nesting"):
        canonical_json(value)
