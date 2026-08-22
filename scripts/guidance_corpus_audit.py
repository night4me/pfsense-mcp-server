#!/usr/bin/env python3
"""Maintainer-invoked audit: verify every guidance registry entry's pinned
`source_verification_excerpt` (a short, genuinely verbatim anchor phrase --
2026-08-22 provenance revision, see `guidance/models.py`'s module
docstring) is still present, verbatim, on the live page its `canonical_url`
points to. Deliberately does NOT check `summary`/`caveat_summary` for
presence -- those are project-authored text and are never expected to
appear verbatim on the source page.

This is a **maintenance/CI tool, not runtime code** — matching
`docs/VERSION_AWARE_GUIDANCE.md`'s TB-G3 design's own explicit
requirement that "a documentation website redesign should cause a
visible maintenance failure, not silent wrong guidance" (task Phase 18).
It never runs as part of server startup or any MCP tool call; nothing in
`src/pfsense_mcp/guidance/` imports it or anything it imports.

Reuses TB-G3's *design* discipline where it applies to a one-shot audit
(HTTPS-only, exact-canonical-URL-after-redirect, a hard size bound, a
hard timeout, its own transport entirely separate from
`pfsense_client.py`'s pfSense-facing transport) without claiming to be
TB-G3 itself — TB-G3 (live serving of fetched content to a consumer,
in-memory caching, freshness labeling) remains unactivated; this script
only ever prints a pass/fail report and exits non-zero on drift. It never
mutates the registry, never returns fetched content to any caller, and
is not imported by anything under `src/`.

Usage: `python scripts/guidance_corpus_audit.py` (or `make guidance-corpus-audit`).
Network access required; not run in the default `make validate`/`make
quick` chain for that reason (same rationale as `release-check`'s
separation from `quick`).
"""

from __future__ import annotations

import re
import sys
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pfsense_mcp.guidance.models import ALLOWED_DOCUMENT_HOSTS  # noqa: E402
from pfsense_mcp.guidance.registry import _REGISTRY, _all_overlays  # noqa: E402

_TIMEOUT_SECONDS = 10
_MAX_BYTES = 2 * 1024 * 1024
_MAX_REDIRECTS = 3
_USER_AGENT = "pfsense-mcp-server-guidance-corpus-audit/1 (maintainer tool, not runtime)"


class _TextExtractor(HTMLParser):
    """Minimal visible-text extractor -- stdlib only, no new dependency
    for a maintainer-invoked, non-runtime tool. Drops script/style
    content; does not attempt full HTML5 parsing correctness."""

    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self.chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self.chunks.append(data)


def _extract_visible_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    return " ".join(parser.chunks)


def _normalize(text: str) -> str:
    """NFC-normalize, then collapse whitespace introduced purely by an
    inline HTML element boundary (e.g. `<code>unbound</code>, which`
    extracts as `unbound , which` -- a rendering artifact of adjacent
    text nodes, not a real content difference; a browser renders both
    identically). Only whitespace immediately before a punctuation mark
    is collapsed -- this does not paper over an actual wording
    difference, since it never removes or reorders any word."""
    collapsed = re.sub(r"\s+([,.;:!?)])", r"\1", text)
    return unicodedata.normalize("NFC", collapsed)


@dataclass(frozen=True)
class _AuditResult:
    entry_id: str
    canonical_url: str
    outcome: str  # "present" | "drifted" | "fetch_error"
    detail: str = ""


def _fetch(url: str) -> str:
    """Single fetch, following redirects up to `_MAX_REDIRECTS`, checking
    the final URL matches exactly and the host stays allow-listed at
    every hop -- same discipline TB-G3's design specifies for a real
    live fetch, applied here to a one-shot maintainer check."""
    current = url
    for _ in range(_MAX_REDIRECTS + 1):
        parts = urlsplit(current)
        if parts.scheme != "https" or parts.hostname not in ALLOWED_DOCUMENT_HOSTS:
            raise ValueError(f"refusing to fetch non-allow-listed URL: {current!r}")
        request = urllib.request.Request(current, headers={"User-Agent": _USER_AGENT})
        response = urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS)  # nosec B310 (scheme+host already checked above, every loop iteration)
        with response:
            if response.status in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    raise ValueError(f"redirect with no Location header from {current!r}")
                current = location
                continue
            content_type = response.headers.get("Content-Type", "")
            if "html" not in content_type and "text" not in content_type:
                raise ValueError(f"unexpected content-type {content_type!r} from {current!r}")
            body = response.read(_MAX_BYTES + 1)
            if len(body) > _MAX_BYTES:
                raise ValueError(f"response exceeded {_MAX_BYTES} bytes: {current!r}")
            if current != url and urlsplit(current).path != urlsplit(url).path:
                # Only reached if the loop above followed a redirect;
                # the final URL must be the registered one, not merely
                # same-host (TB-G3 Finding 3(1) discipline).
                raise ValueError(f"final URL {current!r} does not match registered {url!r}")
            return body.decode("utf-8", errors="replace")
    raise ValueError(f"too many redirects fetching {url!r}")


def _audit_one(entry_id: str, canonical_url: str, pinned_excerpt: str) -> _AuditResult:
    try:
        html = _fetch(canonical_url)
    except (urllib.error.URLError, ValueError, TimeoutError) as exc:
        return _AuditResult(entry_id, canonical_url, "fetch_error", str(exc))

    visible_text = _normalize(re.sub(r"\s+", " ", _extract_visible_text(html)))
    needle = _normalize(re.sub(r"\s+", " ", pinned_excerpt)).strip()
    if needle in visible_text:
        return _AuditResult(entry_id, canonical_url, "present")
    return _AuditResult(entry_id, canonical_url, "drifted", "pinned excerpt not found verbatim in fetched page text")


def main() -> int:
    results: list[_AuditResult] = []
    for entries in _REGISTRY.values():
        for entry in entries:
            results.append(_audit_one(entry.source_id, entry.canonical_url, entry.source_verification_excerpt))
    for overlay in _all_overlays():
        results.append(_audit_one(overlay.overlay_id, overlay.canonical_url, overlay.source_verification_excerpt))

    for result in results:
        print(f"[{result.outcome:11s}] {result.entry_id:40s} {result.canonical_url}")
        if result.detail:
            print(f"              {result.detail}")

    failures = [r for r in results if r.outcome != "present"]
    print(f"\n{len(results) - len(failures)}/{len(results)} entries verified present.")
    if failures:
        print(f"{len(failures)} entries need maintainer review (drifted or unreachable) -- see above.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
