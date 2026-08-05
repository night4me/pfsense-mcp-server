"""Capability manifest schema and validation.

The manifest is the one piece of input a human authors by hand for
scaffold_capability.py. Everything else (field types, nullability,
capture-policy bounds, endpoint verification state) is derived from
already-existing, already-reviewed artifacts: the real Endpoints
registry, the real CAPTURE_POLICIES registry, a saved OpenAPI
discovery snapshot, and an approved fixture already committed under
tests/fixtures/.

First version: exactly one endpoint per manifest (see
scaffold_capability.py's module docstring for the rationale). A
capability with several endpoints/tools is scaffolded via several
separate invocations, each extending the same capability.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA_VERSION = 1

_VALID_PROFILE_NAMES = frozenset({"AuditorProfile", "EngineerProfile"})
_VALID_RESPONSE_SHAPES = frozenset({"list", "object"})
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_REQUIRED_STRING_FIELDS = (
    "capability_name",
    "endpoint_symbol",
    "model_class_name",
    "client_method_name",
    "mcp_tool_name",
    "tool_summary",
    "response_shape",
    "approved_fixture_path",
)


class ManifestError(Exception):
    def __init__(self, category: str, reason: str) -> None:
        self.category = category
        self.reason = reason
        super().__init__(f"[{category}] {reason}")


@dataclass(frozen=True)
class FieldOverride:
    type: str
    nullable: bool


@dataclass(frozen=True)
class CapabilityManifest:
    manifest_schema_version: int
    capability_name: str
    profiles: tuple[str, ...]
    endpoint_symbol: str
    model_class_name: str
    client_method_name: str
    mcp_tool_name: str
    tool_summary: str
    identifying_fields: tuple[str, ...]
    response_shape: str
    approved_fixture_path: str
    field_overrides: dict[str, FieldOverride]


def _require_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.match(value):
        raise ManifestError("invalid-identifier", f"{field_name} must be a plain Python identifier (got {value!r})")
    return value


def _require_no_path_traversal(value: str, field_name: str) -> None:
    if "/" in value or "\\" in value or ".." in value:
        raise ManifestError(
            "path-traversal-in-name", f"{field_name} must not contain path separators or '..' (got {value!r})"
        )


def load_manifest(path: Path) -> CapabilityManifest:
    if not path.is_file():
        raise ManifestError("manifest-not-found", f"manifest file not found: {path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestError("invalid-json", f"manifest is not valid JSON: {exc}") from None

    if not isinstance(raw, dict):
        raise ManifestError("invalid-manifest-shape", "manifest must be a JSON object")

    schema_version = raw.get("manifest_schema_version")
    if schema_version != MANIFEST_SCHEMA_VERSION:
        raise ManifestError(
            "unsupported-manifest-schema-version",
            f"unrecognized manifest_schema_version: {schema_version!r} (expected {MANIFEST_SCHEMA_VERSION})",
        )

    if "endpoints" in raw:
        # v1 supports exactly one endpoint per manifest (see module
        # docstring); the older multi-endpoint array shape is refused
        # explicitly rather than silently ignored.
        endpoints_value = raw["endpoints"]
        count = len(endpoints_value) if isinstance(endpoints_value, list) else "non-list"
        raise ManifestError(
            "multiple-endpoints-not-supported",
            f"this version accepts exactly one endpoint per manifest (found an 'endpoints' array with {count} entries) "
            "— use 'endpoint_symbol' and the other single-endpoint fields directly",
        )

    missing = [f for f in _REQUIRED_STRING_FIELDS if f not in raw]
    if missing:
        raise ManifestError("missing-required-field", f"manifest is missing required field(s): {', '.join(missing)}")

    for f in _REQUIRED_STRING_FIELDS:
        if not isinstance(raw[f], str) or not raw[f]:
            raise ManifestError("invalid-field-type", f"{f} must be a non-empty string")

    capability_name = _require_identifier(raw["capability_name"], "capability_name")
    endpoint_symbol = _require_identifier(raw["endpoint_symbol"], "endpoint_symbol")
    model_class_name = _require_identifier(raw["model_class_name"], "model_class_name")
    client_method_name = _require_identifier(raw["client_method_name"], "client_method_name")

    mcp_tool_name = raw["mcp_tool_name"]
    _require_no_path_traversal(mcp_tool_name, "mcp_tool_name")
    if not _IDENTIFIER_RE.match(mcp_tool_name):
        raise ManifestError(
            "invalid-identifier", f"mcp_tool_name must be a plain Python identifier (got {mcp_tool_name!r})"
        )

    for name, value in (
        ("capability_name", capability_name),
        ("endpoint_symbol", endpoint_symbol),
        ("model_class_name", model_class_name),
        ("client_method_name", client_method_name),
        ("mcp_tool_name", mcp_tool_name),
    ):
        _require_no_path_traversal(value, name)

    response_shape = raw["response_shape"]
    if response_shape not in _VALID_RESPONSE_SHAPES:
        raise ManifestError(
            "invalid-response-shape",
            f"response_shape must be one of {sorted(_VALID_RESPONSE_SHAPES)} (got {response_shape!r})",
        )

    approved_fixture_path = raw["approved_fixture_path"]
    # This is a path (legitimately contains "/"), so only ".." and
    # backslashes are rejected here — the stronger business rule ("must
    # actually live under tests/fixtures/") is enforced separately by
    # scaffold_capability.py against the real filesystem, not here.
    if ".." in approved_fixture_path or "\\" in approved_fixture_path or approved_fixture_path.startswith("/"):
        raise ManifestError(
            "path-traversal-in-name",
            f"approved_fixture_path must not contain '..' or be absolute (got {approved_fixture_path!r})",
        )

    profiles_raw = raw.get("profiles")
    if not isinstance(profiles_raw, list) or not profiles_raw:
        raise ManifestError("missing-required-field", "profiles must be a non-empty list")
    for p in profiles_raw:
        if p not in _VALID_PROFILE_NAMES:
            raise ManifestError(
                "invalid-profile-name", f"unknown profile {p!r}; must be one of {sorted(_VALID_PROFILE_NAMES)}"
            )

    identifying_fields_raw = raw.get("identifying_fields", [])
    if not isinstance(identifying_fields_raw, list) or not all(isinstance(f, str) for f in identifying_fields_raw):
        raise ManifestError("invalid-field-type", "identifying_fields must be a list of strings")

    field_overrides_raw = raw.get("field_overrides", {})
    if not isinstance(field_overrides_raw, dict):
        raise ManifestError("invalid-field-type", "field_overrides must be an object")
    field_overrides: dict[str, FieldOverride] = {}
    for name, spec in field_overrides_raw.items():
        if not isinstance(spec, dict) or "type" not in spec or "nullable" not in spec:
            raise ManifestError("invalid-field-override", f"field_overrides[{name!r}] must have 'type' and 'nullable'")
        field_overrides[name] = FieldOverride(type=spec["type"], nullable=bool(spec["nullable"]))

    return CapabilityManifest(
        manifest_schema_version=schema_version,
        capability_name=capability_name,
        profiles=tuple(profiles_raw),
        endpoint_symbol=endpoint_symbol,
        model_class_name=model_class_name,
        client_method_name=client_method_name,
        mcp_tool_name=mcp_tool_name,
        tool_summary=raw["tool_summary"],
        identifying_fields=tuple(identifying_fields_raw),
        response_shape=response_shape,
        approved_fixture_path=approved_fixture_path,
        field_overrides=field_overrides,
    )
