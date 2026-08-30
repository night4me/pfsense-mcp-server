"""LIVE_APPLIANCE_SCHEMA evidence adapter (pfREST_LIVE_GUIDANCE_ARC
Phase 7).

Fetches the connected appliance's own `/api/v2/schema/openapi` through
the existing, already-authenticated `PfSenseClient` -- the exact same
trust boundary every one of the 100 READ tools already uses. This is
NOT a call to the public internet and does NOT go through
`fetch.py`/`cache.py` (those exist solely for the untrusted
`PFREST_UPSTREAM` domain) -- reusing `PfSenseClient` here is the
correct trust-domain match, not a shortcut.

Parses the result with the SAME `openapi_index.parse_openapi()` this
package already uses for the public upstream document, so
`lookup_endpoint()`/`lookup_model()` return the identical `EndpointDoc`/
`ModelDoc` shapes regardless of which source they came from -- the
*meaning* differs (this is "does the connected appliance actually have
this", not "what does the pfREST project publish generally"), never the
shape.

Never called at import time or MCP server startup -- only when the
`pfsense_get_api_guidance` tool actually needs LIVE_APPLIANCE_SCHEMA
evidence for a specific query.

`ApplianceSchemaCache` holds the parsed index in memory for
`CACHE_TTL_SECONDS`, one instance per server process (constructed once
by the tool's own `build()`, same lifetime as the `PfSenseClient` it
wraps) -- without this, every single guidance query would re-fetch and
re-parse a multi-megabyte document from the appliance, which would be
both slow and needlessly repeated network load against the operator's
own firewall. Never persisted to disk, never shared across
`PfSenseClient` instances.

Size guard: unlike every other pfSense response this project's existing
transport handles (all small, bounded by pfSense's own domain-object
sizes), a full OpenAPI schema can be several megabytes. The existing
`HttpTransport`/`RestApiClient` layer applies no response-size cap
(correct for its own scope -- every endpoint it has ever served until
now was small) -- `_MAX_APPLIANCE_SCHEMA_BYTES` here is defense-in-depth
specific to this one call, dropping an implausibly large response
rather than indexing it, even though the source is authenticated and
already trusted.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass

from ..errors import PfSenseMCPError
from ..pfsense_client import PfSenseClient
from .openapi_index import EndpointDoc, ModelDoc, OpenApiIndex, parse_openapi

logger = logging.getLogger("pfsense_mcp.pfrest_docs")

#: Generous relative to the public document (~4.2 MiB, measured live
#: 2026-08-28) -- this exists to catch a pathological/misbehaving
#: response, not to constrain a normal one.
_MAX_APPLIANCE_SCHEMA_BYTES = 32 * 1024 * 1024

#: pfSense's own REST API settings responses have not been observed to
#: send Cache-Control (unlike pfrest.org's GitHub Pages hosting) -- this
#: is a fixed, conservative default, not derived from any response
#: header. 10 minutes balances "don't hammer the appliance on every
#: guidance query" against "don't serve a wildly stale schema after a
#: package upgrade changes it."
CACHE_TTL_SECONDS = 600.0


@dataclass(frozen=True)
class ApplianceSchemaResult:
    available: bool
    endpoint: EndpointDoc | None = None
    model: ModelDoc | None = None
    error: str | None = None


def _index_from_document(document: object) -> OpenApiIndex | None:
    if not isinstance(document, dict):
        logger.warning("pfrest_docs: appliance schema response was not a JSON object")
        return None
    try:
        serialized_size = len(json.dumps(document))
    except (TypeError, ValueError):
        logger.warning("pfrest_docs: appliance schema response could not be measured")
        return None
    if serialized_size > _MAX_APPLIANCE_SCHEMA_BYTES:
        logger.warning(
            "pfrest_docs: appliance schema response exceeded %d bytes, refusing to index",
            _MAX_APPLIANCE_SCHEMA_BYTES,
        )
        return None
    return parse_openapi(document)


class ApplianceSchemaCache:
    """One instance per server process, constructed by the
    `pfsense_get_api_guidance` tool's `build()` and held for the
    server's lifetime. Not thread-safe by contract, matching
    `cache.DocumentCache`'s own single-request-at-a-time assumption for
    this stdio-transport server."""

    def __init__(self) -> None:
        self._index: OpenApiIndex | None = None
        self._inserted_at_monotonic: float | None = None

    def _get_index(self, client: PfSenseClient) -> OpenApiIndex | None:
        if (
            self._index is not None
            and self._inserted_at_monotonic is not None
            and time.monotonic() - self._inserted_at_monotonic <= CACHE_TTL_SECONDS
        ):
            return self._index

        try:
            document = client.get_system_schema_openapi()
        except PfSenseMCPError as exc:
            logger.warning("pfrest_docs: appliance schema fetch failed: %s", exc)
            # Fail closed to the freshest available data: serve a stale
            # cached index rather than nothing, if one exists.
            return self._index

        index = _index_from_document(document)
        if index is not None:
            self._index = index
            self._inserted_at_monotonic = time.monotonic()
        return index if index is not None else self._index

    def lookup_endpoint(self, client: PfSenseClient, path: str, method: str) -> ApplianceSchemaResult:
        """Fail-closed: any fetch/parse/size failure returns
        `available=False`, never raises past this method's boundary --
        mirrors `tools/read/official_guidance.py`'s identity-resolution
        fail-closed discipline for the same class of appliance-call
        failure."""

        index = self._get_index(client)
        if index is None:
            return ApplianceSchemaResult(available=False, error="appliance schema unavailable")
        return ApplianceSchemaResult(available=True, endpoint=index.lookup_endpoint(path, method))

    def lookup_model(self, client: PfSenseClient, name: str) -> ApplianceSchemaResult:
        index = self._get_index(client)
        if index is None:
            return ApplianceSchemaResult(available=False, error="appliance schema unavailable")
        return ApplianceSchemaResult(available=True, model=index.lookup_model(name))
