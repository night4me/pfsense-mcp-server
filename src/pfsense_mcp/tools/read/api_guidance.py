"""pfsense_get_api_guidance tool definition (pfREST_LIVE_GUIDANCE_ARC,
2026-08-28).

**The second deliberate, reviewed import-boundary crossing** between
the production MCP tool surface and `pfsense_mcp.guidance` -- the first
being `official_guidance.py` (ADR-017/018, 2026-08-22). This module is
also the ONLY production module allowed to import
`pfsense_mcp.pfrest_docs` outside that package itself.
`tests/guidance/test_isolation.py` and `tests/pfrest_docs/test_isolation.py`
each enforce their own half of this by AST scan.

Distinct from `pfsense_get_official_guidance` on purpose (Phase 10
decision, this arc): `OFFICIAL_NETGATE` guidance is Netgate's own
official pfSense documentation; this tool covers the community-
maintained pfREST package's own API reference (`PFREST_UPSTREAM`), this
project's own tool interpretation (`PROJECT_AUTHORED`, reusing Slice A's
`tool_guidance` module), and the connected appliance's own OpenAPI
schema (`LIVE_APPLIANCE_SCHEMA`). Blending these into the existing
Netgate-guidance tool would corrupt that tool's own settled meaning
(its `disclaimer` literal explicitly says "official Netgate sources")
and would force `GuidanceReference`'s Netgate-specific shape
(`Edition`/`ApplicabilityState`/overlay chains) onto sources it was
never designed to represent. This tool never rewrites, relabels, or
merges Netgate guidance into a pfREST claim or vice versa -- if a
future caller wants OFFICIAL_NETGATE guidance too, the existing
`pfsense_get_official_guidance` tool remains the way to get it,
unchanged.

This is a GUIDANCE tool, not a pfSense appliance READ capability --
same accounting as `pfsense_get_official_guidance`: not gated by, and
does not consume, the `Capability`/privilege/profile system, counted
separately from the 95 pfSense READ tools in the public contract.

**Bounded query modes, never arbitrary fetch** (Phase 3/10 threat-model
requirement): every input here is used exclusively as a *lookup key*
into already-fetched, already-cached, already-parsed data -- never as a
URL, never passed to `pfrest_docs.fetch.fetch()` (which is only ever
called internally with its own fixed `OPENAPI_URL`/guide-topic-URL
constants). A caller cannot make this tool fetch an arbitrary URL no
matter what string it supplies for `endpoint_path`/`model_name`/`topic`.

**Zero network access at import time or MCP server startup**: mirrors
`official_guidance.py`'s deferred-import discipline exactly, for the
same reason -- `pfsense_mcp.pfrest_docs`/`pfsense_mcp.guidance.tool_guidance`
imports happen inside `pfsense_get_api_guidance()` itself, not at this
module's top level, so a failure in either can only ever fail this
one tool's own calls.

**Provider/cache instances are constructed once, in `build()`, and
reused for the server's lifetime** -- not per-call -- so that the
in-memory `PFREST_UPSTREAM` document cache and the
`LIVE_APPLIANCE_SCHEMA` cache actually do their job across repeated
guidance queries within one running server process.
"""

from __future__ import annotations

from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict

from ...pfsense_client import PfSenseClient

QueryMode = Literal["tool", "endpoint", "model", "topic"]

_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_MAX_INPUT_LENGTH = 300


class ApiGuidanceResult(BaseModel):
    """The only shape `pfsense_get_api_guidance` ever returns.

    `guidance` reuses `pfrest_docs.models.CrossSourceGuidance` --
    already closed (`extra="forbid"`), already bounded per-evidence-entry
    and per-response (`MAX_EVIDENCE_ENTRIES`), already independently
    provenance-labeled.
    """

    model_config = ConfigDict(extra="forbid")

    query_mode: QueryMode
    guidance: "CrossSourceGuidance"
    disclaimer: Literal[
        "This is documentation guidance from multiple independently labeled sources "
        "(PROJECT_AUTHORED / PFREST_UPSTREAM / LIVE_APPLIANCE_SCHEMA). It is NOT observed "
        "live appliance configuration state and does NOT authorize any action. "
        "PFREST_UPSTREAM is the community-maintained pfREST package's own documentation, "
        "not official Netgate guidance -- use pfsense_get_official_guidance for that. "
        "For current appliance configuration or status, use the relevant pfsense_get_* "
        "READ tool instead."
    ] = (
        "This is documentation guidance from multiple independently labeled sources "
        "(PROJECT_AUTHORED / PFREST_UPSTREAM / LIVE_APPLIANCE_SCHEMA). It is NOT observed "
        "live appliance configuration state and does NOT authorize any action. "
        "PFREST_UPSTREAM is the community-maintained pfREST package's own documentation, "
        "not official Netgate guidance -- use pfsense_get_official_guidance for that. "
        "For current appliance configuration or status, use the relevant pfsense_get_* "
        "READ tool instead."
    )


# Deferred import solely to resolve the forward reference above without
# putting pfrest_docs on this module's own top-level import list (kept
# consistent with every *behavioral* import in this file being deferred
# to build()/call time -- see module docstring). This one is schema-only
# (Pydantic needs the real type at class-definition time for validation/
# JSON-schema generation) and carries no network or guidance-package
# dependency of its own: `pfrest_docs.models` has zero I/O.
from pfsense_mcp.pfrest_docs.models import CrossSourceGuidance  # noqa: E402

ApiGuidanceResult.model_rebuild()


def _bounded(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) > _MAX_INPUT_LENGTH:
        raise ValueError(f"Input exceeds maximum length of {_MAX_INPUT_LENGTH} characters")
    return value


def build(client: PfSenseClient) -> Callable[..., ApiGuidanceResult]:
    from pfsense_mcp.pfrest_docs.appliance_schema import ApplianceSchemaCache
    from pfsense_mcp.pfrest_docs.composition import build_cross_source_guidance
    from pfsense_mcp.pfrest_docs.guide_topics import GuideTopic, guide_topic_url
    from pfsense_mcp.pfrest_docs.models import FreshnessState, GuidanceEvidence
    from pfsense_mcp.pfrest_docs.provenance import Provenance
    from pfsense_mcp.pfrest_docs.provider import PfRestDocumentationProvider
    from pfsense_mcp.pfrest_docs.tool_endpoint_map import pfrest_path_for

    provider = PfRestDocumentationProvider()
    appliance_cache = ApplianceSchemaCache()

    def _pfrest_endpoint_evidence(path: str, method: str) -> tuple[GuidanceEvidence, bool]:
        retrieval = provider.lookup_endpoint(path, method)
        found = retrieval.value is not None
        facts: tuple[str, ...]
        if retrieval.value is None:
            facts = (f"No {method} {path} operation found in the public pfREST OpenAPI document.",)
        else:
            doc = retrieval.value
            facts = tuple(
                fact
                for fact in (
                    f"Description: {doc.description}" if doc.description else None,
                    f"Operation ID: {doc.operation_id}" if doc.operation_id else None,
                    f"Associated model: {doc.associated_model}" if doc.associated_model else None,
                    f"Requires authentication: {doc.requires_authentication}"
                    if doc.requires_authentication is not None
                    else None,
                    f"Supported authentication modes: {', '.join(doc.supported_authentication_modes)}"
                    if doc.supported_authentication_modes
                    else None,
                    f"Allowed privileges: {', '.join(doc.allowed_privileges)}" if doc.allowed_privileges else None,
                    f"Required packages: {', '.join(doc.required_packages)}" if doc.required_packages else None,
                    f"Applies immediately: {doc.applies_immediately}" if doc.applies_immediately is not None else None,
                    f"Utilizes cache: {doc.utilizes_cache}" if doc.utilizes_cache else None,
                )
                if fact is not None
            )
        evidence = GuidanceEvidence(
            provenance=Provenance.PFREST_UPSTREAM,
            source="https://pfrest.org/api-docs/openapi.json",
            subject=f"{method} {path}",
            version=None,
            fetched_at=retrieval.fetched_at,
            content_hash=retrieval.content_hash,
            freshness=retrieval.freshness,
            facts=facts,
        )
        return evidence, found

    def _appliance_endpoint_evidence(path: str, method: str) -> tuple[GuidanceEvidence, bool]:
        result = appliance_cache.lookup_endpoint(client, path, method)
        if not result.available:
            evidence = GuidanceEvidence(
                provenance=Provenance.LIVE_APPLIANCE_SCHEMA,
                source="Connected appliance's own /api/v2/schema/openapi",
                subject=f"{method} {path}",
                version=None,
                fetched_at=None,
                content_hash=None,
                freshness=FreshnessState.UPSTREAM_UNAVAILABLE,
                facts=(result.error or "Appliance schema evidence unavailable this call.",),
            )
            return evidence, False
        found = result.endpoint is not None
        facts = (
            (f"Confirmed present on the connected appliance ({method} {path}).",)
            if found
            else (f"No {method} {path} operation found on the connected appliance's own schema.",)
        )
        evidence = GuidanceEvidence(
            provenance=Provenance.LIVE_APPLIANCE_SCHEMA,
            source="Connected appliance's own /api/v2/schema/openapi",
            subject=f"{method} {path}",
            version=None,
            fetched_at=None,
            content_hash=None,
            freshness=FreshnessState.FRESH,
            facts=facts,
        )
        return evidence, found

    def _pfrest_model_evidence(name: str) -> tuple[GuidanceEvidence, bool]:
        retrieval = provider.lookup_model(name)
        found = retrieval.value is not None
        if retrieval.value is None:
            facts: tuple[str, ...] = (f"No model named {name!r} found in the public pfREST OpenAPI document.",)
        else:
            model = retrieval.value
            field_summaries = tuple(
                f"{field.name}"
                f"{' (required)' if field.required else ''}"
                f": {field.field_type or 'unknown'}"
                f"{' [' + ', '.join(field.enum_values) + ']' if field.enum_values else ''}"
                for field in model.fields
            )
            facts = (
                f"Fields ({model.field_count_total} total{', truncated' if model.truncated else ''}):",
                *field_summaries,
            )
        evidence = GuidanceEvidence(
            provenance=Provenance.PFREST_UPSTREAM,
            source="https://pfrest.org/api-docs/openapi.json",
            subject=name,
            version=None,
            fetched_at=retrieval.fetched_at,
            content_hash=retrieval.content_hash,
            freshness=retrieval.freshness,
            facts=facts,
        )
        return evidence, found

    def _appliance_model_evidence(name: str) -> tuple[GuidanceEvidence, bool]:
        result = appliance_cache.lookup_model(client, name)
        if not result.available:
            evidence = GuidanceEvidence(
                provenance=Provenance.LIVE_APPLIANCE_SCHEMA,
                source="Connected appliance's own /api/v2/schema/openapi",
                subject=name,
                version=None,
                fetched_at=None,
                content_hash=None,
                freshness=FreshnessState.UPSTREAM_UNAVAILABLE,
                facts=(result.error or "Appliance schema evidence unavailable this call.",),
            )
            return evidence, False
        found = result.model is not None
        facts = (
            (f"Confirmed present on the connected appliance ({result.model.field_count_total} fields).",)
            if found and result.model is not None
            else (f"No model named {name!r} found on the connected appliance's own schema.",)
        )
        evidence = GuidanceEvidence(
            provenance=Provenance.LIVE_APPLIANCE_SCHEMA,
            source="Connected appliance's own /api/v2/schema/openapi",
            subject=name,
            version=None,
            fetched_at=None,
            content_hash=None,
            freshness=FreshnessState.FRESH,
            facts=facts,
        )
        return evidence, found

    def _existence_notes(
        subject: str, pfrest_found: bool, appliance_available: bool, appliance_found: bool
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        conflicts: tuple[str, ...] = ()
        notes: tuple[str, ...] = ()
        if not appliance_available:
            notes = (
                f"Live appliance schema evidence was unavailable for {subject!r} this call; "
                "existence cannot be confirmed against the connected appliance right now.",
            )
        elif pfrest_found and not appliance_found:
            conflicts = (
                f"{subject!r} is present in PFREST_UPSTREAM but was NOT found in the connected "
                "appliance's own schema -- LIVE_APPLIANCE_SCHEMA is authoritative for existence on "
                "this specific appliance; this may indicate a newer pfREST release than installed.",
            )
        elif appliance_found and not pfrest_found:
            conflicts = (
                f"{subject!r} is present in the connected appliance's own schema but was NOT found "
                "in the public PFREST_UPSTREAM document -- the appliance schema is authoritative for "
                "this appliance; the public document may describe a different pfREST release.",
            )
        elif pfrest_found and appliance_found:
            notes = (
                f"{subject!r} is confirmed present in both PFREST_UPSTREAM and the connected appliance's own schema.",
            )
        return conflicts, notes

    def pfsense_get_api_guidance(
        query_mode: QueryMode,
        tool_name: str | None = None,
        endpoint_path: str | None = None,
        endpoint_method: str | None = None,
        model_name: str | None = None,
        topic: str | None = None,
    ) -> ApiGuidanceResult:
        """Get bounded, structured, provenance-labeled documentation
        guidance about the pfSense REST API (pfREST) or this project's
        own tools -- from up to three independently labeled sources:
        PROJECT_AUTHORED (this project's own tool interpretation),
        PFREST_UPSTREAM (the community-maintained pfREST package's live
        published API reference at pfrest.org -- NOT official Netgate
        documentation), and LIVE_APPLIANCE_SCHEMA (the connected
        appliance's own OpenAPI schema). Read-only, documentation-only:
        never returns raw appliance configuration and never authorizes
        any action.

        Exactly one of four bounded query modes:

        - query_mode="tool": requires tool_name (an exact pfsense-mcp-server
          tool name, e.g. "pfsense_get_firewall_aliases"). Returns this
          project's own PROJECT_AUTHORED interpretation of that tool,
          plus (if the tool has a known corresponding pfREST endpoint)
          PFREST_UPSTREAM and LIVE_APPLIANCE_SCHEMA evidence for it.
        - query_mode="endpoint": requires endpoint_path (e.g.
          "/api/v2/firewall/alias") and endpoint_method (one of GET,
          POST, PUT, PATCH, DELETE). Returns PFREST_UPSTREAM and
          LIVE_APPLIANCE_SCHEMA evidence for that exact path/method.
        - query_mode="model": requires model_name (an exact pfREST
          OpenAPI schema/model name, e.g. "FirewallAlias"). Returns
          PFREST_UPSTREAM and LIVE_APPLIANCE_SCHEMA evidence for that
          model's fields.
        - query_mode="topic": requires topic (one of
          AUTHENTICATION_AND_AUTHORIZATION, WORKING_WITH_OBJECT_IDS,
          QUERIES_FILTERS_AND_SORTING, COMMON_CONTROL_PARAMETERS,
          WORKING_WITH_HATEOAS, SWAGGER_AND_OPENAPI). Returns a bounded
          PFREST_UPSTREAM excerpt of that guide page.

        Every input is used only as a lookup key into already-fetched,
        already-cached documentation -- never as a URL, and never
        forwarded to any network call this tool does not already make
        internally to its own fixed, allowlisted sources.

        This tool never covers official Netgate/pfSense product
        documentation -- use pfsense_get_official_guidance for that.
        """

        tool_name_v = _bounded(tool_name)
        endpoint_path_v = _bounded(endpoint_path)
        endpoint_method_v = _bounded(endpoint_method)
        model_name_v = _bounded(model_name)
        topic_v = _bounded(topic)

        if query_mode == "tool":
            if not tool_name_v:
                raise ValueError("query_mode='tool' requires tool_name")
            from pfsense_mcp.guidance.tool_guidance import get_tool_guidance

            evidence: list[GuidanceEvidence] = []
            conflicts: list[str] = []
            notes: list[str] = []

            project_guidance = get_tool_guidance(tool_name_v)
            if project_guidance is None:
                raise ValueError(f"Unknown tool_name: {tool_name_v!r}")
            evidence.append(
                GuidanceEvidence(
                    provenance=Provenance.PROJECT_AUTHORED,
                    source="pfsense-mcp-server",
                    subject=tool_name_v,
                    version=None,
                    fetched_at=None,
                    content_hash=None,
                    freshness=FreshnessState.NOT_APPLICABLE,
                    facts=(
                        f"Result kind: {project_guidance.result_kind.value}",
                        project_guidance.interpretation,
                        f"Empty result is meaningful: {project_guidance.empty_result_is_meaningful}",
                        f"Secrets intentionally omitted: {project_guidance.secrets_intentionally_omitted}",
                        *(f"Related tool: {name}" for name in project_guidance.related_tools),
                    ),
                )
            )

            mapped = pfrest_path_for(tool_name_v)
            if mapped is not None:
                path, method = mapped
                pfrest_evidence, pfrest_found = _pfrest_endpoint_evidence(path, method)
                evidence.append(pfrest_evidence)
                appliance_evidence, appliance_found = _appliance_endpoint_evidence(path, method)
                evidence.append(appliance_evidence)
                appliance_available = appliance_evidence.freshness != FreshnessState.UPSTREAM_UNAVAILABLE
                c, n = _existence_notes(f"{method} {path}", pfrest_found, appliance_available, appliance_found)
                conflicts.extend(c)
                notes.extend(n)
            else:
                notes.append(f"{tool_name_v!r} has no known corresponding pfREST endpoint (e.g. a local-only tool).")

            guidance = build_cross_source_guidance(
                query=f"tool={tool_name_v}", evidence=evidence, conflicts=conflicts, applicability_notes=notes
            )
            return ApiGuidanceResult(query_mode=query_mode, guidance=guidance)

        if query_mode == "endpoint":
            if not endpoint_path_v or not endpoint_method_v:
                raise ValueError("query_mode='endpoint' requires endpoint_path and endpoint_method")
            method = endpoint_method_v.upper()
            if method not in _ALLOWED_METHODS:
                raise ValueError(f"endpoint_method must be one of {sorted(_ALLOWED_METHODS)}")
            pfrest_evidence, pfrest_found = _pfrest_endpoint_evidence(endpoint_path_v, method)
            appliance_evidence, appliance_found = _appliance_endpoint_evidence(endpoint_path_v, method)
            appliance_available = appliance_evidence.freshness != FreshnessState.UPSTREAM_UNAVAILABLE
            endpoint_conflicts, endpoint_notes = _existence_notes(
                f"{method} {endpoint_path_v}", pfrest_found, appliance_available, appliance_found
            )
            guidance = build_cross_source_guidance(
                query=f"endpoint={method} {endpoint_path_v}",
                evidence=[pfrest_evidence, appliance_evidence],
                conflicts=endpoint_conflicts,
                applicability_notes=endpoint_notes,
            )
            return ApiGuidanceResult(query_mode=query_mode, guidance=guidance)

        if query_mode == "model":
            if not model_name_v:
                raise ValueError("query_mode='model' requires model_name")
            pfrest_evidence, pfrest_found = _pfrest_model_evidence(model_name_v)
            appliance_evidence, appliance_found = _appliance_model_evidence(model_name_v)
            appliance_available = appliance_evidence.freshness != FreshnessState.UPSTREAM_UNAVAILABLE
            model_conflicts, model_notes = _existence_notes(
                model_name_v, pfrest_found, appliance_available, appliance_found
            )
            guidance = build_cross_source_guidance(
                query=f"model={model_name_v}",
                evidence=[pfrest_evidence, appliance_evidence],
                conflicts=model_conflicts,
                applicability_notes=model_notes,
            )
            return ApiGuidanceResult(query_mode=query_mode, guidance=guidance)

        if query_mode == "topic":
            if not topic_v:
                raise ValueError("query_mode='topic' requires topic")
            try:
                topic_enum = GuideTopic(topic_v)
            except ValueError:
                raise ValueError(
                    f"Unknown topic: {topic_v!r} (must be one of {[t.value for t in GuideTopic]})"
                ) from None
            retrieval = provider.lookup_guide_topic(topic_enum)
            facts = (retrieval.value,) if retrieval.value else ("No excerpt available for this topic right now.",)
            evidence = [
                GuidanceEvidence(
                    provenance=Provenance.PFREST_UPSTREAM,
                    source=guide_topic_url(topic_enum),
                    subject=topic_v,
                    version=None,
                    fetched_at=retrieval.fetched_at,
                    content_hash=retrieval.content_hash,
                    freshness=retrieval.freshness,
                    facts=facts,
                )
            ]
            guidance = build_cross_source_guidance(query=f"topic={topic_v}", evidence=evidence)
            return ApiGuidanceResult(query_mode=query_mode, guidance=guidance)

        raise ValueError(f"Unknown query_mode: {query_mode!r}")

    return pfsense_get_api_guidance
