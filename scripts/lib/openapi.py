"""Shared OpenAPI schema loading and inspection helpers.

Used by scripts/discover_endpoints.py today, and intended to be
reused unchanged by future automation scripts (scaffold_capability.py,
capture_fixture.py) so schema-parsing logic is written exactly once.

This module is read-only and inspection-only. It never classifies an
endpoint as "verified" (that word belongs solely to
pfsense_mcp.endpoints.EndpointInfo, set only after independent,
human-performed verification), never modifies any production source
file, fixture, or generates code. Its only job is turning a raw
OpenAPI 3.0 document into a deterministic, structured description of
the available GET API surface.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.config import PfSenseConfig
from pfsense_mcp.endpoints import EndpointInfo
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tls import resolve_verify
from pfsense_mcp.transport.http import HttpTransport

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

# Not part of the project's registered Endpoints (pfsense_mcp.endpoints) —
# this is a meta/introspection endpoint used only by automation tooling,
# never exposed as an MCP tool and never marked as a project "capability".
_SCHEMA_PATH_SUFFIX = "/schema/openapi"


@dataclass(frozen=True)
class ParameterInfo:
    name: str
    type: str | None
    required: bool
    default: Any
    enum: tuple[str, ...] | None


@dataclass(frozen=True)
class FieldInfo:
    name: str
    type: str | None
    nullable: bool
    enum: tuple[str, ...] | None
    format: str | None
    required: bool


@dataclass(frozen=True)
class EndpointMatch:
    path: str
    method: str
    tags: tuple[str, ...]
    summary: str | None
    description: str | None
    sibling_methods: tuple[str, ...]
    query_parameters: list[ParameterInfo] = field(default_factory=list)
    response_fields: list[FieldInfo] = field(default_factory=list)


def load_schema(
    *,
    schema_file: Path | None = None,
    config: PfSenseConfig | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Single entry point for obtaining an OpenAPI schema document.

    Callers never need to know whether the schema came from a local
    fixture file or a live GET against pfSense — that decision is made
    here, in one place, so a future caching layer only has to change
    this function.
    """
    if schema_file is not None:
        return _load_schema_from_file(schema_file)
    if config is None or api_key is None:
        raise ValueError("config and api_key are required when schema_file is not given")
    return _fetch_schema_live(config, api_key)


def _load_schema_from_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _fetch_schema_live(config: PfSenseConfig, api_key: str) -> dict[str, Any]:
    verify = resolve_verify(config.tls_mode, config.tls_ca_file)
    transport = HttpTransport(config.base_url, api_key, verify)
    try:
        rest_client = RestApiClient(transport, identity=config.identity, api_version=config.api_version)
        schema_endpoint = EndpointInfo(
            path_suffix=_SCHEMA_PATH_SUFFIX, verified=True, min_api_version=ApiVersion.V2
        )
        # Verified live: GET /api/v2/schema/openapi returns the raw OpenAPI
        # document directly (no {code,status,data} envelope) — unlike every
        # domain/resource endpoint in pfsense_client.py, there is no "data"
        # key to unwrap here.
        return rest_client.get(schema_endpoint)
    finally:
        transport.close()


def resolve_ref(schema_doc: dict[str, Any], ref: str) -> dict[str, Any]:
    """Resolve a local '#/components/schemas/Foo' style reference."""
    if not ref.startswith("#/"):
        raise ValueError(f"Only local refs are supported (got {ref!r})")
    node: Any = schema_doc
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def _resolve_node(schema_doc: dict[str, Any], node: dict[str, Any], _seen: frozenset[str] = frozenset()) -> dict[str, Any]:
    """Recursively resolve $ref and merge allOf, following references of
    references to arbitrary depth. _seen guards against reference cycles."""
    if "$ref" in node:
        ref = node["$ref"]
        if ref in _seen:
            return {}
        resolved = resolve_ref(schema_doc, ref)
        return _resolve_node(schema_doc, resolved, _seen | {ref})

    if "allOf" in node:
        merged: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
        for part in node["allOf"]:
            resolved_part = _resolve_node(schema_doc, part, _seen)
            merged["properties"].update(resolved_part.get("properties", {}))
            for name in resolved_part.get("required", []):
                if name not in merged["required"]:
                    merged["required"].append(name)
            # A merged allOf may itself carry a bare type (e.g. "object")
            # from a non-ref, non-properties part; keep the most specific.
            if "type" in resolved_part and resolved_part.get("type") != "object":
                merged["type"] = resolved_part["type"]
        return merged

    return node


def _type_of(node: dict[str, Any]) -> str | None:
    """A schema node's effective type. Handles the plain "type" case
    plus the "oneOf"/"anyOf" case (e.g. pfSense's `id` query parameter,
    which accepts either an integer or a string and so has no
    top-level "type" key at all) by joining the alternatives."""
    if "type" in node:
        return node["type"]
    for key in ("oneOf", "anyOf"):
        if key in node:
            alt_types = sorted({sub.get("type", "unknown") for sub in node[key]})
            return "|".join(alt_types)
    return None


def _describe_property(schema_doc: dict[str, Any], name: str, prop: dict[str, Any], required_names: set[str]) -> FieldInfo:
    resolved = _resolve_node(schema_doc, prop)

    field_type = _type_of(resolved)
    if field_type == "array":
        items = resolved.get("items", {})
        resolved_items = _resolve_node(schema_doc, items)
        inner_type = _type_of(resolved_items) or "object"
        field_type = f"array<{inner_type}>"

    enum = resolved.get("enum")
    return FieldInfo(
        name=name,
        type=field_type,
        nullable=bool(resolved.get("nullable", False)),
        enum=tuple(enum) if enum else None,
        format=resolved.get("format"),
        required=name in required_names,
    )


def describe_response_fields(schema_doc: dict[str, Any], operation: dict[str, Any]) -> list[FieldInfo]:
    """Extract the actual resource fields from a GET operation's 200
    response, unwrapping the pfSense envelope (Success + top-level
    "data") so the reported fields are the resource's own fields, not
    the envelope's."""
    responses = operation.get("responses", {})
    resp = responses.get("200") or responses.get("default") or {}
    content = resp.get("content", {}).get("application/json", {})
    schema = content.get("schema", {})
    if not schema:
        return []

    resolved = _resolve_node(schema_doc, schema)

    data_prop = resolved.get("properties", {}).get("data")
    target = resolved
    if data_prop is not None:
        resolved_data = _resolve_node(schema_doc, data_prop)
        if resolved_data.get("type") == "array":
            items = resolved_data.get("items", {})
            target = _resolve_node(schema_doc, items)
        else:
            target = resolved_data

    required_names = set(target.get("required", []))
    properties = target.get("properties", {})
    fields = [_describe_property(schema_doc, name, prop, required_names) for name, prop in properties.items()]
    return sorted(fields, key=lambda f: f.name)


def describe_query_parameters(operation: dict[str, Any]) -> list[ParameterInfo]:
    params = []
    for p in operation.get("parameters", []):
        if p.get("in") != "query":
            continue
        schema = p.get("schema", {})
        enum = schema.get("enum")
        params.append(
            ParameterInfo(
                name=p["name"],
                type=_type_of(schema),
                required=bool(p.get("required", False)),
                default=schema.get("default"),
                enum=tuple(enum) if enum else None,
            )
        )
    return sorted(params, key=lambda p: p.name)


def iter_get_operations(schema_doc: dict[str, Any]):
    """Yield (path, get_operation, sibling_methods) for every path in
    the schema that has a GET method, in deterministic path order."""
    paths = schema_doc.get("paths", {})
    for path in sorted(paths):
        methods = paths[path]
        if "get" not in methods:
            continue
        sibling = tuple(sorted(m for m in methods if m in _HTTP_METHODS))
        yield path, methods["get"], sibling


def _matches(path: str, operation: dict[str, Any], query: str | None, area: str | None) -> bool:
    tags = operation.get("tags") or []
    haystack = " ".join([path, operation.get("summary") or "", operation.get("description") or "", *tags]).lower()

    if query and query.lower() not in haystack:
        return False
    if area:
        area_lower = area.lower()
        tags_lower = [t.lower() for t in tags]
        if area_lower not in tags_lower and area_lower not in path.lower():
            return False
    return True


def find_endpoints(schema_doc: dict[str, Any], *, query: str | None = None, area: str | None = None) -> list[EndpointMatch]:
    """The single query surface of this module: given a schema
    document and an optional search term/area, return every matching
    GET endpoint, fully described, sorted deterministically by path
    then method."""
    results = []
    for path, get_op, sibling in iter_get_operations(schema_doc):
        if not _matches(path, get_op, query, area):
            continue
        results.append(
            EndpointMatch(
                path=path,
                method="get",
                tags=tuple(get_op.get("tags") or []),
                summary=get_op.get("summary"),
                description=get_op.get("description"),
                sibling_methods=sibling,
                query_parameters=describe_query_parameters(get_op),
                response_fields=describe_response_fields(schema_doc, get_op),
            )
        )
    return sorted(results, key=lambda e: (e.path, e.method))
