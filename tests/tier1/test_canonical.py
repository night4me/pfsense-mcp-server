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
