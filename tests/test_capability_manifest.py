"""Unit tests for scripts/lib/capability_manifest.py — pure schema
validation, no filesystem access beyond the manifest file itself."""

from __future__ import annotations

import json

import pytest
from lib.capability_manifest import ManifestError, load_manifest

_VALID = {
    "manifest_schema_version": 1,
    "capability_name": "DEMO_READ",
    "profiles": ["AuditorProfile"],
    "endpoint_symbol": "DEMO_ENDPOINT",
    "model_class_name": "DemoModel",
    "client_method_name": "get_demo",
    "mcp_tool_name": "pfsense_get_demo",
    "tool_summary": "Demo. Read-only.",
    "identifying_fields": ["secret_field"],
    "response_shape": "list",
    "approved_fixture_path": "tests/fixtures/demo_response.json",
}


def _write(tmp_path, overrides=None, remove=None):
    data = dict(_VALID)
    if overrides:
        data.update(overrides)
    if remove:
        for k in remove:
            data.pop(k, None)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data))
    return path


def test_load_valid_manifest(tmp_path):
    path = _write(tmp_path)
    manifest = load_manifest(path)
    assert manifest.capability_name == "DEMO_READ"
    assert manifest.identifying_fields == ("secret_field",)
    assert manifest.profiles == ("AuditorProfile",)


def test_missing_manifest_file(tmp_path):
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(tmp_path / "does_not_exist.json")
    assert excinfo.value.category == "manifest-not-found"


def test_invalid_json(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text("{not valid json")
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert excinfo.value.category == "invalid-json"


def test_unsupported_schema_version(tmp_path):
    path = _write(tmp_path, overrides={"manifest_schema_version": 999})
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert excinfo.value.category == "unsupported-manifest-schema-version"


@pytest.mark.parametrize(
    "field",
    [
        "capability_name",
        "endpoint_symbol",
        "model_class_name",
        "client_method_name",
        "mcp_tool_name",
        "tool_summary",
        "response_shape",
        "approved_fixture_path",
    ],
)
def test_missing_required_field(tmp_path, field):
    path = _write(tmp_path, remove=[field])
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert excinfo.value.category == "missing-required-field"


def test_missing_profiles(tmp_path):
    path = _write(tmp_path, remove=["profiles"])
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert excinfo.value.category == "missing-required-field"


def test_invalid_profile_name(tmp_path):
    path = _write(tmp_path, overrides={"profiles": ["NotARealProfile"]})
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert excinfo.value.category == "invalid-profile-name"


def test_invalid_response_shape(tmp_path):
    path = _write(tmp_path, overrides={"response_shape": "banana"})
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert excinfo.value.category == "invalid-response-shape"


@pytest.mark.parametrize(
    "field,value",
    [
        ("capability_name", "not an identifier!"),
        ("endpoint_symbol", "123starts_with_digit"),
        ("model_class_name", "has space"),
        ("client_method_name", "has-dash"),
        ("mcp_tool_name", "has.dot"),
    ],
)
def test_invalid_identifier(tmp_path, field, value):
    path = _write(tmp_path, overrides={field: value})
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert excinfo.value.category in ("invalid-identifier", "path-traversal-in-name")


@pytest.mark.parametrize(
    "field,value",
    [
        ("capability_name", "../etc/passwd"),
        ("model_class_name", "foo/bar"),
        ("client_method_name", "foo\\bar"),
    ],
)
def test_path_traversal_in_name_rejected(tmp_path, field, value):
    path = _write(tmp_path, overrides={field: value})
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_multiple_endpoints_array_rejected(tmp_path):
    data = dict(_VALID)
    data["endpoints"] = [{"endpoint_symbol": "A"}, {"endpoint_symbol": "B"}]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert excinfo.value.category == "multiple-endpoints-not-supported"


def test_empty_endpoints_array_also_rejected(tmp_path):
    data = dict(_VALID)
    data["endpoints"] = []
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert excinfo.value.category == "multiple-endpoints-not-supported"


def test_field_overrides_parsed(tmp_path):
    path = _write(tmp_path, overrides={"field_overrides": {"foo": {"type": "str", "nullable": True}}})
    manifest = load_manifest(path)
    assert manifest.field_overrides["foo"].type == "str"
    assert manifest.field_overrides["foo"].nullable is True


def test_invalid_field_override_shape(tmp_path):
    path = _write(tmp_path, overrides={"field_overrides": {"foo": {"type": "str"}}})
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert excinfo.value.category == "invalid-field-override"


def test_identifying_fields_defaults_to_empty(tmp_path):
    path = _write(tmp_path, remove=["identifying_fields"])
    manifest = load_manifest(path)
    assert manifest.identifying_fields == ()


def test_identifying_fields_must_be_list_of_strings(tmp_path):
    path = _write(tmp_path, overrides={"identifying_fields": [1, 2]})
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert excinfo.value.category == "invalid-field-type"
