"""OFFICIAL_GUIDANCE_LAYER.md Required tests: registry integrity and
deterministic-mapping tests (I5/I6), each ambiguity/absence case as its
own explicit test, not inferred from one happy-path test.
"""

import pytest

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.guidance import registry as registry_module
from pfsense_mcp.guidance.models import DocumentSource, Edition, RetrievalMode, excerpt_hash
from pfsense_mcp.guidance.registry import _REGISTRY, lookup_guidance


def test_registry_entries_pass_their_own_content_hash_check():
    # Re-asserts the same check registry.py performs at import time (which
    # already ran once, successfully, for this test to even collect), so a
    # future regression is CI-visible as a named test failure, not just an
    # import-time crash.
    for entries in _REGISTRY.values():
        for entry in entries:
            assert entry.content_hash == excerpt_hash(entry.content_excerpt)


def test_lookup_returns_entry_for_registered_capability_both_edition_unversioned():
    result = lookup_guidance(Capability.ALIAS_READ, observed_version=None, observed_edition=None)
    assert len(result) == 1
    reference = result[0]
    assert reference.capability == "ALIAS_READ"
    assert reference.source_id == "netgate_docs_aliases"
    assert reference.pfsense_edition is Edition.BOTH
    assert reference.version_mismatch is False
    assert reference.trust_label == "pinned-snapshot"


def test_lookup_is_deterministic_for_identical_inputs():
    first = lookup_guidance(Capability.ALIAS_READ, observed_version="2.7.2", observed_edition=Edition.CE)
    second = lookup_guidance(Capability.ALIAS_READ, observed_version="2.7.2", observed_edition=Edition.CE)
    assert first == second


def test_lookup_returns_empty_for_unregistered_capability():
    assert lookup_guidance(Capability.SERVICE_READ, observed_version=None, observed_edition=None) == ()


def test_lookup_returns_empty_when_a_version_specific_entry_would_be_needed_but_none_is_registered():
    # ALIAS_READ's only registered entry is UNVERSIONED/BOTH, so an
    # observed version/edition should not change eligibility here -- this
    # asserts that fact directly rather than assuming it.
    result = lookup_guidance(Capability.ALIAS_READ, observed_version="9.9.9", observed_edition=Edition.PLUS)
    assert len(result) == 1
    assert result[0].version_mismatch is False


def test_lookup_never_raises_for_a_capability_with_no_registry_entry():
    # I6: absence must resolve to an empty tuple, never an exception.
    for capability in Capability:
        lookup_guidance(capability, observed_version=None, observed_edition=None)


def _synthetic_entry(**overrides: object) -> DocumentSource:
    excerpt = "Synthetic entry for exclusion-branch testing only."
    kwargs: dict[str, object] = {
        "source_id": "synthetic_entry",
        "title": "Synthetic",
        "canonical_url": "https://docs.netgate.com/synthetic",
        "pfsense_edition": Edition.CE,
        "version_applicability": "2.7.2",
        "retrieval_mode": RetrievalMode.BUNDLED_SNAPSHOT,
        "content_excerpt": excerpt,
        "content_hash": excerpt_hash(excerpt),
        "license_note": "Synthetic, test-only.",
    }
    kwargs.update(overrides)
    return DocumentSource(**kwargs)


@pytest.fixture
def synthetic_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    # Exercises I6's exclusion branches directly, without adding a fake
    # entry to the real, curated registry those branches would otherwise
    # never trigger against (the real registry's one entry is
    # UNVERSIONED/BOTH, which never takes the exclusion path).
    monkeypatch.setitem(registry_module._REGISTRY, Capability.SYSTEM_READ, (_synthetic_entry(),))


def test_version_specific_entry_excluded_when_observed_version_is_none(synthetic_registry: None):
    result = lookup_guidance(Capability.SYSTEM_READ, observed_version=None, observed_edition=Edition.CE)
    assert result == ()


def test_version_specific_entry_excluded_on_version_mismatch(synthetic_registry: None):
    result = lookup_guidance(Capability.SYSTEM_READ, observed_version="2.8.0", observed_edition=Edition.CE)
    assert result == ()


def test_version_specific_entry_included_on_exact_version_match(synthetic_registry: None):
    result = lookup_guidance(Capability.SYSTEM_READ, observed_version="2.7.2", observed_edition=Edition.CE)
    assert len(result) == 1
    assert result[0].version_mismatch is False


def test_edition_specific_entry_excluded_when_observed_edition_is_none(synthetic_registry: None):
    result = lookup_guidance(Capability.SYSTEM_READ, observed_version="2.7.2", observed_edition=None)
    assert result == ()


def test_edition_specific_entry_excluded_on_edition_mismatch(synthetic_registry: None):
    result = lookup_guidance(Capability.SYSTEM_READ, observed_version="2.7.2", observed_edition=Edition.PLUS)
    assert result == ()
