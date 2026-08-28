"""Canonicalized, dimension-classified diff between two already-fetched
OpenAPI documents (owner direction, pfREST_LIVE_GUIDANCE_ARC
continuation, 2026-08-28).

Purpose, concretely: today, compare `PFREST_UPSTREAM`'s public OpenAPI
document against a connected appliance's own `LIVE_APPLIANCE_SCHEMA` --
the same pfREST *version* running on public infrastructure vs. one
specific real installation. Designed so the same pure function can
later, under separate authorization, compare two `LIVE_APPLIANCE_SCHEMA`
captures from *different appliances* (e.g. "does pfREST 2.10.2 expose an
identical contract on pfSense CE 2.9.0 vs. pfSense Plus 26.07?") --
this module takes two plain OpenAPI dicts and two labels; it has no
opinion about where either document came from.

Semantic, not byte-level: a raw JSON/hash diff would flag harmless
whitespace/key-ordering noise as "different" and would flag a single
instance-specific default value (e.g. a per-install random secret, or a
runtime-computed capacity number) the same way it would flag a missing
endpoint. This module instead walks each document into named,
comparable shapes across a fixed set of dimensions -- paths/methods,
operationIds, parameters, schemas/models, fields, enums,
required_packages, auth metadata, allowed_privileges,
applies_immediately, other pfREST `x-` extensions, top-level
version/build metadata, and field *default values* -- and classifies
each dimension's differences as ADDED_IN_B / REMOVED_IN_B / CHANGED.

`default_values` is kept as its own dimension, separate from `fields`
(structural type/required/nullable shape): a default is frequently
instance-specific runtime state -- a per-install random secret, a
runtime-computed capacity number, a next-available ID -- rather than
part of the request/response contract. Bundling it into `fields` would
make a harmless instance-specific value look, in shape, exactly like a
genuine contract break.

Endpoint-level structured facts (required_packages, auth metadata,
allowed_privileges, applies_immediately) are extracted by reusing
`openapi_index.parse_openapi()`'s already-reviewed HTML-description
parser verbatim -- this module does not reimplement that parsing, only
compares its output between two documents (same precedent as
`scripts/pfrest_privilege_crosscheck.py` reusing `security_privileges.py`).

**Classifies WHAT differs; never asserts WHY.** A found difference is
reported with its dimension and the two raw values -- this module does
not attribute a cause (pfSense edition, release, installed packages,
runtime/package discovery, generated-schema environment, configuration,
pfREST build, or schema-generation behavior are all possible causes; see
`docs/adr/ADR-035-pfrest-live-guidance-layer.md`). Pure -- no I/O, no
network, no appliance/upstream knowledge; the caller supplies both
already-fetched documents.

**Advisory only, like every other module in this package**: a
`SchemaDiffReport` is evidence for a human or for `pfsense_get_api_guidance`'s
existing cross-source evidence model to cite -- it never grants a
privilege, never authorizes an endpoint, and is not itself part of the
public MCP tool surface (see `scripts/pfrest_schema_diff.py`, which is
the offline entry point, following the same non-MCP precedent as
`scripts/pfrest_privilege_crosscheck.py`).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .openapi_index import EndpointDoc, parse_openapi

#: Report output is capped per dimension so a large real-world
#: divergence (hypothetically, every field of every model) cannot
#: produce unbounded output -- but the *comparison itself* is always
#: exhaustive; only which entries are shown is capped. `dimension_totals`
#: always reports the true count regardless of truncation.
MAX_ENTRIES_PER_DIMENSION = 25

#: Extension-key scan depth: top-level document, per-path-item, per-
#: operation, per-schema, per-property. Deliberately shallow -- pfREST's
#: own OpenAPI generator has never been observed nesting `x-` keys any
#: deeper than this, and unbounded recursion into arbitrary schema
#: content is exactly the kind of pathological-input surface this
#: package avoids elsewhere (see `openapi_index.py`'s own shallow `$ref`
#: handling).
_MAX_EXTENSION_SCAN_DEPTH = 5

_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})

_DIMENSION_PATHS_METHODS = "paths_methods"
_DIMENSION_OPERATION_IDS = "operation_ids"
_DIMENSION_PARAMETERS = "parameters"
_DIMENSION_SCHEMAS_MODELS = "schemas_models"
_DIMENSION_FIELDS = "fields"
_DIMENSION_ENUMS = "enums"
_DIMENSION_DEFAULT_VALUES = "default_values"
_DIMENSION_REQUIRED_PACKAGES = "required_packages"
_DIMENSION_AUTH_METADATA = "auth_metadata"
_DIMENSION_ALLOWED_PRIVILEGES = "allowed_privileges"
_DIMENSION_APPLIES_IMMEDIATELY = "applies_immediately"
_DIMENSION_EXTENSIONS = "extensions"
_DIMENSION_VERSION_METADATA = "version_metadata"

ALL_DIMENSIONS = (
    _DIMENSION_PATHS_METHODS,
    _DIMENSION_OPERATION_IDS,
    _DIMENSION_PARAMETERS,
    _DIMENSION_SCHEMAS_MODELS,
    _DIMENSION_FIELDS,
    _DIMENSION_ENUMS,
    _DIMENSION_DEFAULT_VALUES,
    _DIMENSION_REQUIRED_PACKAGES,
    _DIMENSION_AUTH_METADATA,
    _DIMENSION_ALLOWED_PRIVILEGES,
    _DIMENSION_APPLIES_IMMEDIATELY,
    _DIMENSION_EXTENSIONS,
    _DIMENSION_VERSION_METADATA,
)

_POSSIBLE_CAUSES_DISCLAIMER = (
    "Each entry below states WHAT differs between the two sources, never WHY. "
    "Possible causes include (not exhaustively, and not in priority order): pfSense "
    "edition, pfSense release, installed packages, runtime/package discovery, the "
    "schema-generation environment, appliance configuration, pfREST package build, "
    "or schema-generation behavior itself. Do not attribute a difference to any one "
    "of these without independent evidence."
)


class ChangeKind(str, Enum):
    ADDED_IN_B = "added_in_b"
    REMOVED_IN_B = "removed_in_b"
    CHANGED = "changed"


@dataclass(frozen=True)
class DiffEntry:
    dimension: str
    key: str
    change: ChangeKind
    detail: str


@dataclass(frozen=True)
class SchemaDiffReport:
    label_a: str
    label_b: str
    entries: tuple[DiffEntry, ...]
    dimension_totals: tuple[tuple[str, int], ...]
    identical_dimensions: tuple[str, ...]
    truncated_dimensions: tuple[str, ...]
    disclaimer: str


def _endpoint_keys(document: dict[str, Any]) -> frozenset[tuple[str, str]]:
    paths = document.get("paths")
    keys: set[tuple[str, str]] = set()
    if isinstance(paths, dict):
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method in methods:
                if method.upper() in _HTTP_METHODS:
                    keys.add((str(path), method.upper()))
    return frozenset(keys)


def _operation(document: dict[str, Any], path: str, method: str) -> dict[str, Any] | None:
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return None
    methods = paths.get(path)
    if not isinstance(methods, dict):
        return None
    operation = methods.get(method.lower())
    return operation if isinstance(operation, dict) else None


def _model_names(document: dict[str, Any]) -> frozenset[str]:
    components = document.get("components")
    if isinstance(components, dict):
        schemas = components.get("schemas")
        if isinstance(schemas, dict):
            return frozenset(str(name) for name in schemas)
    return frozenset()


def _model_schema(document: dict[str, Any], name: str) -> dict[str, Any] | None:
    components = document.get("components")
    if not isinstance(components, dict):
        return None
    schemas = components.get("schemas")
    if not isinstance(schemas, dict):
        return None
    schema = schemas.get(name)
    return schema if isinstance(schema, dict) else None


def _fields_of(schema: dict[str, Any]) -> dict[str, tuple[str | None, bool, bool]]:
    """name -> (type, required, nullable). Unbounded -- unlike
    `openapi_index.ModelDoc` (capped for MCP token budget), this
    internal comparison must see every field, not just the first
    `MAX_FIELDS_PER_MODEL`."""

    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return {}
    required = frozenset(str(item) for item in schema.get("required", []) if isinstance(schema.get("required"), list))
    result: dict[str, tuple[str | None, bool, bool]] = {}
    for name, prop in properties.items():
        if not isinstance(prop, dict):
            continue
        field_type = prop.get("type")
        nullable = bool(prop.get("nullable", False))
        result[str(name)] = (
            str(field_type) if field_type is not None else None,
            str(name) in required,
            nullable,
        )
    return result


def _enum_values(schema: dict[str, Any], field_name: str) -> tuple[str, ...] | None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return None
    prop = properties.get(field_name)
    if not isinstance(prop, dict):
        return None
    enum = prop.get("enum")
    if not isinstance(enum, list):
        return None
    return tuple(str(item) for item in enum)


_NO_DEFAULT = object()


def _field_default(schema: dict[str, Any], field_name: str) -> Any:
    """Returns `_NO_DEFAULT` (never `None`) when the property has no
    `default` key at all -- `None` is itself a valid, meaningful
    default value for a nullable field and must not be confused with
    "absent"."""

    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return _NO_DEFAULT
    prop = properties.get(field_name)
    if not isinstance(prop, dict) or "default" not in prop:
        return _NO_DEFAULT
    return prop["default"]


def _extension_keys(obj: Any, prefix: str, depth: int, out: dict[str, Any]) -> None:
    if depth > _MAX_EXTENSION_SCAN_DEPTH or not isinstance(obj, dict):
        return
    for key, value in obj.items():
        key_str = str(key)
        if key_str.startswith("x-"):
            out[f"{prefix}/{key_str}"] = value
        elif isinstance(value, dict):
            _extension_keys(value, f"{prefix}/{key_str}", depth + 1, out)


def _extensions(document: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    _extension_keys(document, "", 0, out)
    return out


def _version_metadata(document: dict[str, Any]) -> dict[str, str]:
    info = document.get("info")
    info = info if isinstance(info, dict) else {}
    license_block = info.get("license")
    license_block = license_block if isinstance(license_block, dict) else {}
    return {
        "openapi": str(document.get("openapi", "")),
        "info.version": str(info.get("version", "")),
        "info.title": str(info.get("title", "")),
        "info.license.name": str(license_block.get("name", "")),
    }


def _cap(entries: list[DiffEntry], dimension: str) -> tuple[tuple[DiffEntry, ...], int, bool]:
    total = len(entries)
    truncated = total > MAX_ENTRIES_PER_DIMENSION
    return tuple(entries[:MAX_ENTRIES_PER_DIMENSION]), total, truncated


def diff_schemas(
    document_a: dict[str, Any],
    document_b: dict[str, Any],
    *,
    label_a: str,
    label_b: str,
) -> SchemaDiffReport:
    """Pure. Both documents must already be parsed JSON dicts (the
    caller is responsible for fetching them, from whatever source --
    this function has no opinion). Never raises on a malformed/partial
    document; missing sections simply compare as empty, matching
    `openapi_index.parse_openapi()`'s own fail-closed-to-empty
    convention."""

    all_entries: list[DiffEntry] = []
    dimension_totals: dict[str, int] = {}
    truncated_dimensions: list[str] = []

    keys_a = _endpoint_keys(document_a)
    keys_b = _endpoint_keys(document_b)
    common_keys = keys_a & keys_b

    # paths_methods
    entries: list[DiffEntry] = []
    for path, method in sorted(keys_b - keys_a):
        entries.append(
            DiffEntry(_DIMENSION_PATHS_METHODS, f"{method} {path}", ChangeKind.ADDED_IN_B, f"present only in {label_b}")
        )
    for path, method in sorted(keys_a - keys_b):
        entries.append(
            DiffEntry(
                _DIMENSION_PATHS_METHODS, f"{method} {path}", ChangeKind.REMOVED_IN_B, f"present only in {label_a}"
            )
        )
    capped, total, trunc = _cap(entries, _DIMENSION_PATHS_METHODS)
    all_entries.extend(capped)
    dimension_totals[_DIMENSION_PATHS_METHODS] = total
    if trunc:
        truncated_dimensions.append(_DIMENSION_PATHS_METHODS)

    # operation_ids, parameters (common endpoints only -- existence
    # differences are already captured by paths_methods above)
    op_id_entries: list[DiffEntry] = []
    param_entries: list[DiffEntry] = []
    for path, method in sorted(common_keys):
        op_a = _operation(document_a, path, method) or {}
        op_b = _operation(document_b, path, method) or {}
        key = f"{method} {path}"

        op_id_a = op_a.get("operationId")
        op_id_b = op_b.get("operationId")
        if op_id_a != op_id_b:
            op_id_entries.append(
                DiffEntry(
                    _DIMENSION_OPERATION_IDS, key, ChangeKind.CHANGED, f"{label_a}={op_id_a!r} {label_b}={op_id_b!r}"
                )
            )

        params_a = frozenset(
            (str(p.get("name")), str(p.get("in")), bool(p.get("required", False)))
            for p in op_a.get("parameters", [])
            if isinstance(p, dict)
        )
        params_b = frozenset(
            (str(p.get("name")), str(p.get("in")), bool(p.get("required", False)))
            for p in op_b.get("parameters", [])
            if isinstance(p, dict)
        )
        if params_a != params_b:
            added = sorted(params_b - params_a)
            removed = sorted(params_a - params_b)
            detail_parts = []
            if added:
                detail_parts.append(f"added in {label_b}: {added}")
            if removed:
                detail_parts.append(f"removed in {label_b}: {removed}")
            param_entries.append(DiffEntry(_DIMENSION_PARAMETERS, key, ChangeKind.CHANGED, "; ".join(detail_parts)))

    for dimension, dim_entries in ((_DIMENSION_OPERATION_IDS, op_id_entries), (_DIMENSION_PARAMETERS, param_entries)):
        capped, total, trunc = _cap(dim_entries, dimension)
        all_entries.extend(capped)
        dimension_totals[dimension] = total
        if trunc:
            truncated_dimensions.append(dimension)

    # schemas_models
    names_a = _model_names(document_a)
    names_b = _model_names(document_b)
    common_models = names_a & names_b
    entries = []
    for name in sorted(names_b - names_a):
        entries.append(DiffEntry(_DIMENSION_SCHEMAS_MODELS, name, ChangeKind.ADDED_IN_B, f"present only in {label_b}"))
    for name in sorted(names_a - names_b):
        entries.append(
            DiffEntry(_DIMENSION_SCHEMAS_MODELS, name, ChangeKind.REMOVED_IN_B, f"present only in {label_a}")
        )
    capped, total, trunc = _cap(entries, _DIMENSION_SCHEMAS_MODELS)
    all_entries.extend(capped)
    dimension_totals[_DIMENSION_SCHEMAS_MODELS] = total
    if trunc:
        truncated_dimensions.append(_DIMENSION_SCHEMAS_MODELS)

    # fields, enums (common models only)
    field_entries: list[DiffEntry] = []
    enum_entries: list[DiffEntry] = []
    default_entries: list[DiffEntry] = []
    for model_name in sorted(common_models):
        schema_a = _model_schema(document_a, model_name) or {}
        schema_b = _model_schema(document_b, model_name) or {}
        fields_a = _fields_of(schema_a)
        fields_b = _fields_of(schema_b)
        common_fields = fields_a.keys() & fields_b.keys()

        for field_name in sorted(fields_b.keys() - fields_a.keys()):
            field_entries.append(
                DiffEntry(
                    _DIMENSION_FIELDS, f"{model_name}.{field_name}", ChangeKind.ADDED_IN_B, f"present only in {label_b}"
                )
            )
        for field_name in sorted(fields_a.keys() - fields_b.keys()):
            field_entries.append(
                DiffEntry(
                    _DIMENSION_FIELDS,
                    f"{model_name}.{field_name}",
                    ChangeKind.REMOVED_IN_B,
                    f"present only in {label_a}",
                )
            )
        for field_name in sorted(common_fields):
            if fields_a[field_name] != fields_b[field_name]:
                field_entries.append(
                    DiffEntry(
                        _DIMENSION_FIELDS,
                        f"{model_name}.{field_name}",
                        ChangeKind.CHANGED,
                        f"{label_a}={fields_a[field_name]!r} {label_b}={fields_b[field_name]!r}",
                    )
                )

            enum_a = _enum_values(schema_a, field_name)
            enum_b = _enum_values(schema_b, field_name)
            if (enum_a is not None or enum_b is not None) and (enum_a or ()) != (enum_b or ()):
                enum_entries.append(
                    DiffEntry(
                        _DIMENSION_ENUMS,
                        f"{model_name}.{field_name}",
                        ChangeKind.CHANGED,
                        f"{label_a}={sorted(enum_a or ())} {label_b}={sorted(enum_b or ())}",
                    )
                )

            default_a = _field_default(schema_a, field_name)
            default_b = _field_default(schema_b, field_name)
            if default_a != default_b:
                default_entries.append(
                    DiffEntry(
                        _DIMENSION_DEFAULT_VALUES,
                        f"{model_name}.{field_name}",
                        ChangeKind.CHANGED,
                        f"{label_a}={default_a!r} {label_b}={default_b!r} "
                        "(often instance-specific runtime state, not a contract change)",
                    )
                )

    for dimension, dim_entries in (
        (_DIMENSION_FIELDS, field_entries),
        (_DIMENSION_ENUMS, enum_entries),
        (_DIMENSION_DEFAULT_VALUES, default_entries),
    ):
        capped, total, trunc = _cap(dim_entries, dimension)
        all_entries.extend(capped)
        dimension_totals[dimension] = total
        if trunc:
            truncated_dimensions.append(dimension)

    # required_packages, auth_metadata, allowed_privileges,
    # applies_immediately -- reuse openapi_index's already-reviewed
    # parser, compared for common endpoints only.
    index_a = parse_openapi(document_a)
    index_b = parse_openapi(document_b)
    packages_entries: list[DiffEntry] = []
    auth_entries: list[DiffEntry] = []
    privilege_entries: list[DiffEntry] = []
    applies_entries: list[DiffEntry] = []
    for path, method in sorted(common_keys):
        doc_a: EndpointDoc | None = index_a.lookup_endpoint(path, method)
        doc_b: EndpointDoc | None = index_b.lookup_endpoint(path, method)
        if doc_a is None or doc_b is None:
            continue
        key = f"{method} {path}"

        if frozenset(doc_a.required_packages) != frozenset(doc_b.required_packages):
            packages_entries.append(
                DiffEntry(
                    _DIMENSION_REQUIRED_PACKAGES,
                    key,
                    ChangeKind.CHANGED,
                    f"{label_a}={sorted(doc_a.required_packages)} {label_b}={sorted(doc_b.required_packages)}",
                )
            )

        auth_a = (doc_a.requires_authentication, frozenset(doc_a.supported_authentication_modes))
        auth_b = (doc_b.requires_authentication, frozenset(doc_b.supported_authentication_modes))
        if auth_a != auth_b:
            auth_entries.append(
                DiffEntry(
                    _DIMENSION_AUTH_METADATA,
                    key,
                    ChangeKind.CHANGED,
                    f"{label_a}={auth_a!r} {label_b}={auth_b!r}",
                )
            )

        if frozenset(doc_a.allowed_privileges) != frozenset(doc_b.allowed_privileges):
            privilege_entries.append(
                DiffEntry(
                    _DIMENSION_ALLOWED_PRIVILEGES,
                    key,
                    ChangeKind.CHANGED,
                    f"{label_a}={sorted(doc_a.allowed_privileges)} {label_b}={sorted(doc_b.allowed_privileges)}",
                )
            )

        if doc_a.applies_immediately != doc_b.applies_immediately:
            applies_entries.append(
                DiffEntry(
                    _DIMENSION_APPLIES_IMMEDIATELY,
                    key,
                    ChangeKind.CHANGED,
                    f"{label_a}={doc_a.applies_immediately!r} {label_b}={doc_b.applies_immediately!r}",
                )
            )

    for dimension, dim_entries in (
        (_DIMENSION_REQUIRED_PACKAGES, packages_entries),
        (_DIMENSION_AUTH_METADATA, auth_entries),
        (_DIMENSION_ALLOWED_PRIVILEGES, privilege_entries),
        (_DIMENSION_APPLIES_IMMEDIATELY, applies_entries),
    ):
        capped, total, trunc = _cap(dim_entries, dimension)
        all_entries.extend(capped)
        dimension_totals[dimension] = total
        if trunc:
            truncated_dimensions.append(dimension)

    # extensions
    ext_a = _extensions(document_a)
    ext_b = _extensions(document_b)
    entries = []
    for key in sorted(ext_b.keys() - ext_a.keys()):
        entries.append(DiffEntry(_DIMENSION_EXTENSIONS, key, ChangeKind.ADDED_IN_B, f"present only in {label_b}"))
    for key in sorted(ext_a.keys() - ext_b.keys()):
        entries.append(DiffEntry(_DIMENSION_EXTENSIONS, key, ChangeKind.REMOVED_IN_B, f"present only in {label_a}"))
    for key in sorted(ext_a.keys() & ext_b.keys()):
        if ext_a[key] != ext_b[key]:
            entries.append(
                DiffEntry(
                    _DIMENSION_EXTENSIONS,
                    key,
                    ChangeKind.CHANGED,
                    f"{label_a}={ext_a[key]!r} {label_b}={ext_b[key]!r}",
                )
            )
    capped, total, trunc = _cap(entries, _DIMENSION_EXTENSIONS)
    all_entries.extend(capped)
    dimension_totals[_DIMENSION_EXTENSIONS] = total
    if trunc:
        truncated_dimensions.append(_DIMENSION_EXTENSIONS)

    # version_metadata
    version_a = _version_metadata(document_a)
    version_b = _version_metadata(document_b)
    entries = []
    for key in sorted(set(version_a) | set(version_b)):
        value_a = version_a.get(key, "")
        value_b = version_b.get(key, "")
        if value_a != value_b:
            entries.append(
                DiffEntry(
                    _DIMENSION_VERSION_METADATA,
                    key,
                    ChangeKind.CHANGED,
                    f"{label_a}={value_a!r} {label_b}={value_b!r}",
                )
            )
    capped, total, trunc = _cap(entries, _DIMENSION_VERSION_METADATA)
    all_entries.extend(capped)
    dimension_totals[_DIMENSION_VERSION_METADATA] = total
    if trunc:
        truncated_dimensions.append(_DIMENSION_VERSION_METADATA)

    identical_dimensions = tuple(dim for dim in ALL_DIMENSIONS if dimension_totals.get(dim, 0) == 0)

    return SchemaDiffReport(
        label_a=label_a,
        label_b=label_b,
        entries=tuple(all_entries),
        dimension_totals=tuple(sorted(dimension_totals.items())),
        identical_dimensions=identical_dimensions,
        truncated_dimensions=tuple(truncated_dimensions),
        disclaimer=_POSSIBLE_CAUSES_DISCLAIMER,
    )
