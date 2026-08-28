"""Deterministic, bounded OpenAPI document parser/index
(pfREST_LIVE_GUIDANCE_ARC Phase 6).

Never exposes the complete OpenAPI document to a caller -- this module
builds a queryable index and returns only the smallest evidence a
specific `lookup_endpoint()`/`lookup_model()` call needs, each result
independently bounded (`MAX_*` constants below), never a multi-MB dump.

pfREST's own operation descriptions are HTML fragments embedded in a
JSON string (verified live 2026-08-28: `<h3>Description:</h3>...<br>
<h3>Details:</h3>**Endpoint type**: ...<br>...`) -- `_strip_html()`
removes every tag; the structured `**Label**: value<br>` lines are then
parsed with a fixed set of label patterns into typed fields, never
executed or rendered as HTML, never passed through to a consumer as a
raw fragment.

`$ref` resolution is deliberately shallow and one-directional: a
model's own field may reference another model by name (surfaced as
`FieldDoc.ref_model`, a cross-reference the caller can look up
separately via another `lookup_model()` call), never inlined -- this
keeps every single result bounded regardless of how deeply nested the
real schema graph is, and sidesteps circular-reference risk entirely
(there is nothing here that recursively walks into a referenced
model's own definition). Verified live 2026-08-28: the current
document contains zero self-referencing or 2-cycle schemas, but this
module does not rely on that fact -- it is architecturally incapable of
following a $ref recursively at all, so a future circular schema
upstream could not create infinite recursion here even if one appeared.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from typing import Any

MAX_DESCRIPTION_LENGTH = 500
#: Kept well below MAX_DESCRIPTION_LENGTH: a model lookup returns many
#: fields at once (up to MAX_FIELDS_PER_MODEL), so per-field budget must
#: be tighter than a single endpoint's own one description (Phase 14
#: token-efficiency measurement: the largest real model,
#: ACMECertificateDomain at 297 fields/~90KB raw, serialized to ~10.5KB
#: at a 300-char-description/40-field cap -- tightened to these values
#: to bring that same worst case down to roughly half that).
MAX_FIELD_DESCRIPTION_LENGTH = 150
MAX_FIELDS_PER_MODEL = 25
MAX_ENUM_VALUES = 20
MAX_LIST_ITEMS = 20

_TAG_PATTERN = re.compile(r"<[^>]+>")
_WHITESPACE_PATTERN = re.compile(r"\s+")

#: pfREST's fixed structured-description template, verified live
#: 2026-08-28 against multiple operations
#: (`GET/POST/PATCH/DELETE /api/v2/firewall/alias`) -- a label whose
#: text changes upstream simply stops matching and that field comes
#: back `None`/empty, never raises.
_DETAIL_LABELS = {
    "endpoint_type": "Endpoint type",
    "associated_model": "Associated model",
    "parent_model": "Parent model",
    "requires_authentication": "Requires authentication",
    "supported_authentication_modes": "Supported authentication modes",
    "allowed_privileges": "Allowed privileges",
    "required_packages": "Required packages",
    "applies_immediately": "Applies immediately",
    "utilizes_cache": "Utilizes cache",
}


def _strip_html(raw: str) -> str:
    """Remove every HTML tag and unescape entities. Never renders or
    executes anything -- the result is plain text only, truncated to
    keep any single description bounded."""

    without_tags = _TAG_PATTERN.sub(" ", raw)
    unescaped = html.unescape(without_tags)
    collapsed = _WHITESPACE_PATTERN.sub(" ", unescaped).strip()
    return collapsed[:MAX_DESCRIPTION_LENGTH]


def _extract_detail(text: str, label: str) -> str | None:
    pattern = re.compile(rf"\*\*{re.escape(label)}:?\*\*:?\s*(.+?)(?:<br>|$)", re.IGNORECASE)
    match = pattern.search(text)
    if not match:
        return None
    return _strip_html(match.group(1))


def _extract_free_description(text: str) -> str:
    match = re.search(r"<h3>Description:?</h3>(.*?)<h3>", text, re.IGNORECASE | re.DOTALL)
    if match:
        return _strip_html(match.group(1))
    return _strip_html(text)


def _parse_bool_detail(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in ("yes", "true"):
        return True
    if normalized in ("no", "false"):
        return False
    return None


def _parse_optional_name_detail(value: str | None) -> str | None:
    """For details whose real value vocabulary is `None`/a proper-noun
    name (verified live 2026-08-28: `Utilizes cache` is `None`,
    `RESTAPIVersionReleasesCache`, or `AvailablePackageCache` -- never
    `Yes`/`No`) -- distinct from `_parse_bool_detail()`, which is for
    the genuinely boolean-vocabulary details."""

    if value is None:
        return None
    normalized = value.strip()
    if normalized.lower() == "none":
        return None
    return normalized


def _parse_list_detail(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    inner = value.strip()
    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1]
    if inner.strip().lower() in ("none", ""):
        return ()
    items = [item.strip() for item in inner.split(",") if item.strip()]
    return tuple(items[:MAX_LIST_ITEMS])


@dataclass(frozen=True)
class EndpointDoc:
    path: str
    method: str
    operation_id: str | None
    tags: tuple[str, ...]
    description: str
    endpoint_type: str | None
    associated_model: str | None
    parent_model: str | None
    requires_authentication: bool | None
    supported_authentication_modes: tuple[str, ...]
    allowed_privileges: tuple[str, ...]
    required_packages: tuple[str, ...]
    applies_immediately: bool | None
    utilizes_cache: str | None


@dataclass(frozen=True)
class FieldDoc:
    name: str
    field_type: str | None
    nullable: bool | None
    required: bool
    enum_values: tuple[str, ...]
    description: str
    ref_model: str | None


@dataclass(frozen=True)
class ModelDoc:
    name: str
    fields: tuple[FieldDoc, ...]
    field_count_total: int
    truncated: bool


def _ref_name(schema: dict[str, Any]) -> str | None:
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
        return ref.rsplit("/", 1)[-1]
    return None


def _field_from_property(name: str, prop: dict[str, Any], required_names: frozenset[str]) -> FieldDoc:
    ref_model = _ref_name(prop)
    description = _strip_html(str(prop.get("description", "")))[:MAX_FIELD_DESCRIPTION_LENGTH]
    enum_values = tuple(str(item) for item in prop.get("enum", [])[:MAX_ENUM_VALUES])
    field_type = prop.get("type")
    if field_type is None and ref_model is not None:
        field_type = f"ref:{ref_model}"
    return FieldDoc(
        name=name,
        field_type=field_type,
        nullable=prop.get("nullable"),
        required=name in required_names,
        enum_values=enum_values,
        description=description,
        ref_model=ref_model,
    )


@dataclass
class OpenApiIndex:
    """Built once per fetched document by `parse_openapi()`, then
    queried any number of times. Holds only what the two lookup
    functions need -- never the full raw document past construction."""

    _paths: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    _schemas: dict[str, dict[str, Any]] = field(default_factory=dict)

    def lookup_endpoint(self, path: str, method: str) -> EndpointDoc | None:
        operation = self._paths.get((path, method.upper()))
        if operation is None:
            return None
        raw_description = str(operation.get("description", ""))
        return EndpointDoc(
            path=path,
            method=method.upper(),
            operation_id=operation.get("operationId"),
            tags=tuple(str(tag) for tag in operation.get("tags", [])[:MAX_LIST_ITEMS]),
            description=_extract_free_description(raw_description),
            endpoint_type=_extract_detail(raw_description, _DETAIL_LABELS["endpoint_type"]),
            associated_model=_extract_detail(raw_description, _DETAIL_LABELS["associated_model"]),
            parent_model=_extract_detail(raw_description, _DETAIL_LABELS["parent_model"]),
            requires_authentication=_parse_bool_detail(
                _extract_detail(raw_description, _DETAIL_LABELS["requires_authentication"])
            ),
            supported_authentication_modes=_parse_list_detail(
                _extract_detail(raw_description, _DETAIL_LABELS["supported_authentication_modes"])
            ),
            allowed_privileges=_parse_list_detail(
                _extract_detail(raw_description, _DETAIL_LABELS["allowed_privileges"])
            ),
            required_packages=_parse_list_detail(_extract_detail(raw_description, _DETAIL_LABELS["required_packages"])),
            applies_immediately=_parse_bool_detail(
                _extract_detail(raw_description, _DETAIL_LABELS["applies_immediately"])
            ),
            utilizes_cache=_parse_optional_name_detail(
                _extract_detail(raw_description, _DETAIL_LABELS["utilizes_cache"])
            ),
        )

    def lookup_model(self, name: str) -> ModelDoc | None:
        schema = self._schemas.get(name)
        if schema is None:
            return None
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        required_names = frozenset(str(item) for item in schema.get("required", []))
        names = sorted(properties.keys())
        truncated = len(names) > MAX_FIELDS_PER_MODEL
        fields = tuple(
            _field_from_property(field_name, properties[field_name], required_names)
            for field_name in names[:MAX_FIELDS_PER_MODEL]
            if isinstance(properties[field_name], dict)
        )
        return ModelDoc(name=name, fields=fields, field_count_total=len(names), truncated=truncated)

    def known_path_count(self) -> int:
        return len({path for path, _method in self._paths})

    def known_model_count(self) -> int:
        return len(self._schemas)


def parse_openapi(document: dict[str, Any]) -> OpenApiIndex:
    """Build an `OpenApiIndex` from an already-fetched, already-JSON-
    decoded OpenAPI document. Pure -- no I/O, no network. Never raises
    on a malformed/partial document; missing sections simply produce an
    index with fewer entries (fail closed to "not found" on lookup,
    never a crash on a document shaped differently than expected)."""

    index = OpenApiIndex()
    paths = document.get("paths")
    if isinstance(paths, dict):
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    continue
                if isinstance(operation, dict):
                    index._paths[(path, method.upper())] = operation

    components = document.get("components")
    if isinstance(components, dict):
        schemas = components.get("schemas")
        if isinstance(schemas, dict):
            for name, schema in schemas.items():
                if isinstance(schema, dict):
                    index._schemas[name] = schema

    return index
