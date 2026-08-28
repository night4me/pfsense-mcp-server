"""`PfRestDocumentationProvider` -- the one class that composes
`fetch`/`cache`/`openapi_index`/`guide_topics` into the three lookup
primitives this package exposes (pfREST_LIVE_GUIDANCE_ARC Phase 4/5/6).

Deliberately NOT `fetch_public_openapi()` as a public method (that
would invite a caller to dump the whole 4+ MB document) and NOT
`lookup_reference(symbol)` (no structured PHP-reference index exists
upstream to back it -- see the research report). Exactly the three
primitives the mission's Phase 4 names:

    provider.lookup_endpoint(path, method)
    provider.lookup_model(name)
    provider.lookup_guide_topic(topic)

Every method fails closed: a fetch/parse/network failure never raises
out of this class -- it returns a `Retrieval` whose `.value` is `None`
and whose `.freshness` explains why (`UPSTREAM_UNAVAILABLE`, or a
`STALE_BUT_USABLE` cached value if one exists). No method here is
called at import time; a `PfRestDocumentationProvider` instance does
nothing on construction beyond creating an empty in-memory cache.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Generic, TypeVar

from . import fetch
from .cache import DocumentCache
from .guide_topics import GuideTopic, extract_excerpt, guide_topic_url
from .models import FreshnessState
from .openapi_index import EndpointDoc, ModelDoc, OpenApiIndex, parse_openapi

logger = logging.getLogger("pfsense_mcp.pfrest_docs")

OPENAPI_URL = "https://pfrest.org/api-docs/openapi.json"

T = TypeVar("T")


@dataclass(frozen=True)
class Retrieval(Generic[T]):
    value: T | None
    freshness: FreshnessState
    fetched_at: str | None
    content_hash: str | None
    source_url: str


def _parse_openapi_document(body: str) -> OpenApiIndex | None:
    try:
        document = json.loads(body)
    except ValueError:
        return None
    if not isinstance(document, dict):
        return None
    return parse_openapi(document)


class PfRestDocumentationProvider:
    def __init__(self) -> None:
        self._cache = DocumentCache()
        self._index: OpenApiIndex | None = None
        self._index_content_hash: str | None = None

    def _get_index(self) -> Retrieval[OpenApiIndex]:
        lookup = self._cache.get(OPENAPI_URL)
        if lookup.state == FreshnessState.FRESH and lookup.entry is not None:
            return self._retrieval_from_cached(lookup.entry.result, FreshnessState.FRESH)

        try:
            result = fetch.fetch(OPENAPI_URL, accept="application/json")
        except fetch.FetchError as exc:
            logger.warning("pfrest_docs: openapi fetch failed: %s", exc)
            if lookup.state == FreshnessState.STALE_BUT_USABLE and lookup.entry is not None:
                return self._retrieval_from_cached(lookup.entry.result, FreshnessState.STALE_BUT_USABLE)
            return Retrieval(
                value=None,
                freshness=FreshnessState.UPSTREAM_UNAVAILABLE,
                fetched_at=None,
                content_hash=None,
                source_url=OPENAPI_URL,
            )

        self._cache.put(OPENAPI_URL, result)
        return self._retrieval_from_cached(result, FreshnessState.FRESH)

    def _retrieval_from_cached(self, result: fetch.FetchResult, freshness: FreshnessState) -> Retrieval[OpenApiIndex]:
        if self._index is None or self._index_content_hash != result.content_hash:
            self._index = _parse_openapi_document(result.body)
            self._index_content_hash = result.content_hash
        if self._index is None:
            return Retrieval(
                value=None,
                freshness=FreshnessState.CORRUPT,
                fetched_at=result.fetched_at,
                content_hash=result.content_hash,
                source_url=OPENAPI_URL,
            )
        return Retrieval(
            value=self._index,
            freshness=freshness,
            fetched_at=result.fetched_at,
            content_hash=result.content_hash,
            source_url=OPENAPI_URL,
        )

    def lookup_endpoint(self, path: str, method: str) -> Retrieval[EndpointDoc]:
        indexed = self._get_index()
        if indexed.value is None:
            return Retrieval(
                value=None,
                freshness=indexed.freshness,
                fetched_at=indexed.fetched_at,
                content_hash=indexed.content_hash,
                source_url=OPENAPI_URL,
            )
        endpoint = indexed.value.lookup_endpoint(path, method)
        return Retrieval(
            value=endpoint,
            freshness=indexed.freshness,
            fetched_at=indexed.fetched_at,
            content_hash=indexed.content_hash,
            source_url=OPENAPI_URL,
        )

    def lookup_model(self, name: str) -> Retrieval[ModelDoc]:
        indexed = self._get_index()
        if indexed.value is None:
            return Retrieval(
                value=None,
                freshness=indexed.freshness,
                fetched_at=indexed.fetched_at,
                content_hash=indexed.content_hash,
                source_url=OPENAPI_URL,
            )
        model = indexed.value.lookup_model(name)
        return Retrieval(
            value=model,
            freshness=indexed.freshness,
            fetched_at=indexed.fetched_at,
            content_hash=indexed.content_hash,
            source_url=OPENAPI_URL,
        )

    def lookup_guide_topic(self, topic: GuideTopic) -> Retrieval[str]:
        url = guide_topic_url(topic)
        lookup = self._cache.get(url)
        if lookup.state == FreshnessState.FRESH and lookup.entry is not None:
            return Retrieval(
                value=extract_excerpt(lookup.entry.result.body),
                freshness=FreshnessState.FRESH,
                fetched_at=lookup.entry.result.fetched_at,
                content_hash=lookup.entry.result.content_hash,
                source_url=url,
            )

        try:
            result = fetch.fetch(url, accept="text/html")
        except fetch.FetchError as exc:
            logger.warning("pfrest_docs: guide topic fetch failed for %s: %s", topic.value, exc)
            if lookup.state == FreshnessState.STALE_BUT_USABLE and lookup.entry is not None:
                return Retrieval(
                    value=extract_excerpt(lookup.entry.result.body),
                    freshness=FreshnessState.STALE_BUT_USABLE,
                    fetched_at=lookup.entry.result.fetched_at,
                    content_hash=lookup.entry.result.content_hash,
                    source_url=url,
                )
            return Retrieval(
                value=None,
                freshness=FreshnessState.UPSTREAM_UNAVAILABLE,
                fetched_at=None,
                content_hash=None,
                source_url=url,
            )

        self._cache.put(url, result)
        return Retrieval(
            value=extract_excerpt(result.body),
            freshness=FreshnessState.FRESH,
            fetched_at=result.fetched_at,
            content_hash=result.content_hash,
            source_url=url,
        )
