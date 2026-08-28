"""pfREST_LIVE_GUIDANCE_ARC Phase 16 CACHE matrix coverage for
pfrest_docs.cache.DocumentCache."""

from __future__ import annotations

from datetime import datetime, timezone

from pfsense_mcp.pfrest_docs.cache import DEFAULT_TTL_SECONDS, STALE_GRACE_SECONDS, DocumentCache
from pfsense_mcp.pfrest_docs.fetch import FetchResult
from pfsense_mcp.pfrest_docs.models import FreshnessState


def _result(*, cache_control: str | None = "max-age=600", body: str = "{}") -> FetchResult:
    return FetchResult(
        url="https://pfrest.org/api-docs/openapi.json",
        status_code=200,
        content_type="application/json",
        body=body,
        content_hash="deadbeef",
        fetched_at=datetime.now(timezone.utc).isoformat(),
        cache_control=cache_control,
        etag=None,
        last_modified=None,
    )


def test_miss_on_empty_cache():
    cache = DocumentCache()
    lookup = cache.get("https://pfrest.org/api-docs/openapi.json")
    assert lookup.state == FreshnessState.MISS
    assert lookup.entry is None


def test_hit_is_fresh_immediately_after_put():
    cache = DocumentCache()
    cache.put("https://pfrest.org/api-docs/openapi.json", _result())
    lookup = cache.get("https://pfrest.org/api-docs/openapi.json")
    assert lookup.state == FreshnessState.FRESH
    assert lookup.entry is not None
    assert lookup.entry.result.body == "{}"


def test_ttl_derived_from_cache_control_max_age():
    cache = DocumentCache()
    cache.put("u", _result(cache_control="max-age=1"))
    entry = cache.get("u").entry
    assert entry is not None
    assert entry.ttl_seconds == 1.0


def test_ttl_falls_back_to_default_when_cache_control_missing():
    cache = DocumentCache()
    cache.put("u", _result(cache_control=None))
    entry = cache.get("u").entry
    assert entry is not None
    assert entry.ttl_seconds == DEFAULT_TTL_SECONDS


def test_ttl_falls_back_to_default_when_cache_control_unparseable():
    cache = DocumentCache()
    cache.put("u", _result(cache_control="no-cache, private"))
    entry = cache.get("u").entry
    assert entry is not None
    assert entry.ttl_seconds == DEFAULT_TTL_SECONDS


def test_ttl_falls_back_to_default_on_zero_max_age():
    cache = DocumentCache()
    cache.put("u", _result(cache_control="max-age=0"))
    entry = cache.get("u").entry
    assert entry is not None
    assert entry.ttl_seconds == DEFAULT_TTL_SECONDS


def test_expired_entry_within_grace_window_is_stale_but_usable(monkeypatch):
    import time as time_module

    cache = DocumentCache()
    fake_now = [1000.0]
    monkeypatch.setattr(time_module, "monotonic", lambda: fake_now[0])
    cache.put("u", _result(cache_control="max-age=10"))
    fake_now[0] = 1000.0 + 10.0 + 1.0  # just past TTL, well within grace
    lookup = cache.get("u")
    assert lookup.state == FreshnessState.STALE_BUT_USABLE
    assert lookup.entry is not None


def test_entry_past_grace_window_is_evicted_as_miss(monkeypatch):
    import time as time_module

    cache = DocumentCache()
    fake_now = [1000.0]
    monkeypatch.setattr(time_module, "monotonic", lambda: fake_now[0])
    cache.put("u", _result(cache_control="max-age=10"))
    fake_now[0] = 1000.0 + 10.0 + STALE_GRACE_SECONDS + 1.0
    lookup = cache.get("u")
    assert lookup.state == FreshnessState.MISS
    assert lookup.entry is None
    assert len(cache) == 0


def test_cache_is_bounded_and_evicts_oldest_first():
    from pfsense_mcp.pfrest_docs.cache import MAX_CACHE_ENTRIES

    cache = DocumentCache()
    for i in range(MAX_CACHE_ENTRIES + 5):
        cache.put(f"https://pfrest.org/{i}", _result())
    assert len(cache) == MAX_CACHE_ENTRIES
    # the earliest-inserted entries should have been evicted
    assert cache.get("https://pfrest.org/0").state == FreshnessState.MISS
    assert cache.get(f"https://pfrest.org/{MAX_CACHE_ENTRIES + 4}").state == FreshnessState.FRESH


def test_put_never_changes_provenance_or_fabricates_content():
    cache = DocumentCache()
    original = _result(body='{"real":true}')
    cache.put("u", original)
    entry = cache.get("u").entry
    assert entry is not None
    assert entry.result.body == '{"real":true}'
    assert entry.result is original
