"""Offline unit tests for the pure logic in
`scripts/guidance_corpus_audit.py` (task Phase 18). No network access --
`_fetch()`/`main()` are exercised only by manual, maintainer-invoked runs
(`make guidance-corpus-audit`), never by the default test suite (same
reasoning as `release-check`'s own separation from `quick`)."""

from __future__ import annotations

import unicodedata

from scripts.guidance_corpus_audit import _extract_visible_text, _normalize


def test_extract_visible_text_drops_script_and_style_content():
    html = "<p>Real text</p><script>evil()</script><style>.x{color:red}</style><p>More text</p>"
    extracted = _extract_visible_text(html)
    assert "evil()" not in extracted
    assert "color:red" not in extracted
    assert "Real text" in extracted
    assert "More text" in extracted


def test_normalize_collapses_whitespace_before_punctuation_from_inline_markup_boundaries():
    # The exact artifact found live against docs.netgate.com: an inline
    # <code>/<strong> element boundary extracts as "word , rest" -- a
    # rendering artifact, not a real wording difference.
    artifact = "utilizes unbound , which is a validating , recursive resolver ."
    assert _normalize(artifact) == "utilizes unbound, which is a validating, recursive resolver."


def test_normalize_never_removes_or_reorders_words():
    text = "Firewall rules control traffic passing through the firewall."
    assert _normalize(text) == text


def test_normalize_applies_nfc_unicode_normalization():
    # "e" + a combining acute accent (NFD form) must normalize to the
    # same result as the single precomposed code point (NFC form) --
    # otherwise an identical visible page could fail the presence check
    # purely on Unicode representation, never real content.
    precomposed = unicodedata.normalize("NFC", "café")
    nfd_form = unicodedata.normalize("NFD", precomposed)
    assert nfd_form != precomposed
    assert _normalize(nfd_form) == _normalize(precomposed) == precomposed
