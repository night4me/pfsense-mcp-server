"""In-memory, bounded, process-lifetime cache for `fetch.FetchResult`
(pfREST_LIVE_GUIDANCE_ARC Phase 5).

Deliberately NOT a persistent (on-disk) cache -- the mission itself
offers this as an acceptable first-version simplification when
persistent caching would add disproportionate complexity, and it does
here: this package caches at most a handful of distinct URLs (the one
OpenAPI document plus five guide-topic pages, as of the 2026-08-28
live research), so a small in-memory dict with a hard entry cap already
gives every practical benefit (avoiding a multi-megabyte re-fetch on
every tool call within one server process's lifetime) without any of
persistent caching's own concerns (file permissions, corruption
detection, concurrent-writer safety, disk exhaustion). A future arc MAY
add persistence if operational experience shows the in-memory-only
behavior (a full re-fetch on every server restart) is a real problem --
not assumed here.

No entry ever changes `Provenance` or fabricates freshness: this module
only ever answers "is what I already fetched still usable, or do I need
to fetch again" -- it never invents content and never silently serves
stale data without labeling it `STALE_BUT_USABLE` (see
`.models.FreshnessState`).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from .fetch import FetchResult
from .models import FreshnessState

#: Small, fixed cap: this package will only ever cache a handful of
#: distinct URLs (see module docstring). A cap this size is pure
#: defense-in-depth against a future bug constructing unbounded distinct
#: cache keys, not a tuning knob for expected load.
MAX_CACHE_ENTRIES = 32

#: Used when the upstream response has no parseable Cache-Control
#: max-age (pfrest.org has always sent one in live testing, 2026-08-28:
#: `max-age=600` on every response checked -- this is a defensive
#: fallback, not the expected common case).
DEFAULT_TTL_SECONDS = 300.0

#: How much longer, past TTL expiry, a stale entry remains usable as a
#: `STALE_BUT_USABLE` fallback if a fresh re-fetch fails -- reliability
#: over strict freshness for read-only documentation content, bounded
#: so a genuinely dead cache entry does not linger forever.
STALE_GRACE_SECONDS = 6 * 3600.0

_MAX_AGE_PATTERN = re.compile(r"max-age=(\d+)", re.IGNORECASE)


def _ttl_from_cache_control(cache_control: str | None) -> float:
    if not cache_control:
        return DEFAULT_TTL_SECONDS
    match = _MAX_AGE_PATTERN.search(cache_control)
    if not match:
        return DEFAULT_TTL_SECONDS
    try:
        seconds = int(match.group(1))
    except ValueError:
        return DEFAULT_TTL_SECONDS
    return float(seconds) if seconds > 0 else DEFAULT_TTL_SECONDS


@dataclass(frozen=True)
class CacheEntry:
    result: FetchResult
    inserted_at_monotonic: float
    ttl_seconds: float


@dataclass(frozen=True)
class CacheLookup:
    entry: CacheEntry | None
    state: FreshnessState


class DocumentCache:
    """A tiny bounded LRU-by-insertion cache. Not thread-safe by
    contract (the MCP server this package serves is single-process,
    stdio-transport, one request handled at a time per the existing
    architecture) -- if that ever changes, this class would need a
    lock, added deliberately, not assumed to already be safe."""

    def __init__(self) -> None:
        self._entries: dict[str, CacheEntry] = {}

    def get(self, url: str) -> CacheLookup:
        entry = self._entries.get(url)
        if entry is None:
            return CacheLookup(entry=None, state=FreshnessState.MISS)
        age = time.monotonic() - entry.inserted_at_monotonic
        if age <= entry.ttl_seconds:
            return CacheLookup(entry=entry, state=FreshnessState.FRESH)
        if age <= entry.ttl_seconds + STALE_GRACE_SECONDS:
            return CacheLookup(entry=entry, state=FreshnessState.STALE_BUT_USABLE)
        del self._entries[url]
        return CacheLookup(entry=None, state=FreshnessState.MISS)

    def put(self, url: str, result: FetchResult) -> None:
        if len(self._entries) >= MAX_CACHE_ENTRIES and url not in self._entries:
            oldest_url = next(iter(self._entries))
            del self._entries[oldest_url]
        self._entries[url] = CacheEntry(
            result=result,
            inserted_at_monotonic=time.monotonic(),
            ttl_seconds=_ttl_from_cache_control(result.cache_control),
        )

    def __len__(self) -> int:
        return len(self._entries)
