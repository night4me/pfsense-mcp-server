"""Unit tests for scripts/discover_endpoints.py and scripts/lib/openapi.py.

Everything here runs fully offline against the synthetic fixture
tests/fixtures/openapi_schema_sample.json — no network, no credentials,
no `live` marker.
"""

from __future__ import annotations

import json
from pathlib import Path

import discover_endpoints
from lib.openapi import (
    _resolve_node,
    describe_query_parameters,
    describe_response_fields,
    find_endpoints,
    iter_get_operations,
    load_schema,
    resolve_ref,
)

FIXTURE = Path(__file__).parent / "fixtures" / "openapi_schema_sample.json"


def _schema() -> dict:
    return json.loads(FIXTURE.read_text())


def test_load_schema_from_file():
    schema = load_schema(schema_file=FIXTURE)
    assert schema["openapi"] == "3.0.0"


def test_iter_get_operations_finds_all_get_paths():
    schema = _schema()
    paths = [path for path, _op, _sibling in iter_get_operations(schema)]
    assert paths == [
        "/api/v2/widget/gadgets",
        "/api/v2/widget/gadgets/count",
        "/api/v2/widget/sprockets",
    ]


def test_iter_get_operations_skips_paths_without_get():
    schema = _schema()
    schema["paths"]["/api/v2/widget/no-get"] = {"post": {"responses": {}}}
    paths = [path for path, _op, _sibling in iter_get_operations(schema)]
    assert "/api/v2/widget/no-get" not in paths


def test_matches_filters_by_search_term_case_insensitive():
    schema = _schema()
    results = find_endpoints(schema, query="GADGET")
    paths = [e.path for e in results]
    assert paths == ["/api/v2/widget/gadgets", "/api/v2/widget/gadgets/count"]


def test_matches_filters_by_area_tag():
    schema = _schema()
    results = find_endpoints(schema, area="WIDGET")
    assert len(results) == 3


def test_matches_filters_by_area_with_no_match():
    schema = _schema()
    results = find_endpoints(schema, area="NONEXISTENT_AREA")
    assert results == []


def test_matches_combines_query_and_area_as_and():
    schema = _schema()
    results = find_endpoints(schema, query="sprocket", area="WIDGET")
    assert [e.path for e in results] == ["/api/v2/widget/sprockets"]

    results_no_match = find_endpoints(schema, query="sprocket", area="NONEXISTENT_AREA")
    assert results_no_match == []


def test_resolve_ref_resolves_simple_ref():
    schema = _schema()
    resolved = resolve_ref(schema, "#/components/schemas/GadgetCount")
    assert resolved["properties"]["count"]["type"] == "integer"


def test_nested_ref_resolution_follows_multiple_levels():
    """Sprocket.details.items is an allOf referencing SprocketDetail,
    which itself has an "extra" property that is an allOf referencing
    SprocketDetailExtra. Confirm the resolver follows both levels and
    surfaces SprocketDetailExtra's own fields."""
    schema = _schema()
    sprocket = resolve_ref(schema, "#/components/schemas/Sprocket")
    details_items = sprocket["properties"]["details"]["items"]

    resolved_detail = _resolve_node(schema, details_items)
    assert "label" in resolved_detail["properties"]

    extra_node = resolved_detail["properties"]["extra"]
    resolved_extra = _resolve_node(schema, extra_node)
    assert set(resolved_extra["properties"]) == {"code", "note"}


def test_describe_response_fields_extracts_field_types():
    schema = _schema()
    _path, op, _sibling = next(iter_get_operations(schema))
    fields = {f.name: f for f in describe_response_fields(schema, op)}
    assert fields["id"].type == "integer"
    assert fields["name"].type == "string"
    assert fields["weight"].type == "number"


def test_describe_response_fields_marks_nullable_fields():
    schema = _schema()
    _path, op, _sibling = next(iter_get_operations(schema))
    fields = {f.name: f for f in describe_response_fields(schema, op)}
    assert fields["name"].nullable is True
    assert fields["id"].nullable is False


def test_describe_response_fields_extracts_enum_values():
    schema = _schema()
    _path, op, _sibling = next(iter_get_operations(schema))
    fields = {f.name: f for f in describe_response_fields(schema, op)}
    assert fields["status"].enum == ("ACTIVE", "INACTIVE")


def test_describe_response_fields_extracts_format():
    schema = _schema()
    _path, op, _sibling = next(iter_get_operations(schema))
    fields = {f.name: f for f in describe_response_fields(schema, op)}
    assert fields["weight"].format == "float"


def test_describe_response_fields_unwraps_singleton_object_data():
    schema = _schema()
    ops = {path: op for path, op, _sibling in iter_get_operations(schema)}
    fields = {f.name: f for f in describe_response_fields(schema, ops["/api/v2/widget/gadgets/count"])}
    assert set(fields) == {"count", "max_count"}


def test_describe_query_parameters_extracts_name_type_required_default_enum():
    schema = _schema()
    ops = {path: op for path, op, _sibling in iter_get_operations(schema)}
    params = describe_query_parameters(ops["/api/v2/widget/gadgets"])
    by_name = {p.name: p for p in params}

    assert by_name["limit"].type == "integer"
    assert by_name["limit"].required is False
    assert by_name["limit"].default == 50

    assert by_name["sort_order"].enum == ("SORT_ASC", "SORT_DESC")


def test_describe_query_parameters_handles_oneof_type():
    """Mirrors a real pfSense pattern (firewall/alias's `id` parameter):
    a query parameter with no top-level "type", only "oneOf"."""
    schema = _schema()
    ops = {path: op for path, op, _sibling in iter_get_operations(schema)}
    params = {p.name: p for p in describe_query_parameters(ops["/api/v2/widget/gadgets"])}
    assert params["id"].type == "integer|string"


def test_describe_query_parameters_marks_required_parameter():
    schema = _schema()
    ops = {path: op for path, op, _sibling in iter_get_operations(schema)}
    params = {p.name: p for p in describe_query_parameters(ops["/api/v2/widget/sprockets"])}
    assert params["label"].required is True


def test_find_endpoints_sorted_by_path_then_method():
    schema = _schema()
    results = find_endpoints(schema)
    keys = [(e.path, e.method) for e in results]
    assert keys == sorted(keys)


def test_find_endpoints_response_fields_sorted_alphabetically():
    schema = _schema()
    results = find_endpoints(schema, query="gadgets")
    gadgets_ep = next(e for e in results if e.path == "/api/v2/widget/gadgets")
    names = [f.name for f in gadgets_ep.response_fields]
    assert names == sorted(names)


def test_find_endpoints_query_parameters_sorted_alphabetically():
    schema = _schema()
    results = find_endpoints(schema, query="gadgets")
    gadgets_ep = next(e for e in results if e.path == "/api/v2/widget/gadgets")
    names = [p.name for p in gadgets_ep.query_parameters]
    assert names == sorted(names)


def test_mutating_methods_detected_on_shared_path():
    schema = _schema()
    results = find_endpoints(schema, query="gadgets")
    gadgets_ep = next(e for e in results if e.path == "/api/v2/widget/gadgets")
    assert "post" in gadgets_ep.sibling_methods


def test_no_mutating_methods_reported_for_get_only_path():
    schema = _schema()
    results = find_endpoints(schema, query="count")
    count_ep = next(e for e in results if e.path == "/api/v2/widget/gadgets/count")
    assert count_ep.sibling_methods == ("get",)


def test_cli_schema_file_mode_produces_human_readable_report(capsys):
    exit_code = discover_endpoints.main(["--schema-file", str(FIXTURE), "gadgets"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "GET /api/v2/widget/gadgets" in captured.out
    assert "Mutating methods on this path: yes" in captured.out


def test_cli_show_all_methods_expands_verb_list(capsys):
    discover_endpoints.main(["--schema-file", str(FIXTURE), "--show-all-methods", "gadgets"])
    captured = capsys.readouterr()
    assert "Mutating methods on this path: POST" in captured.out


def test_cli_json_mode_produces_valid_json_with_schema_version(capsys):
    exit_code = discover_endpoints.main(["--schema-file", str(FIXTURE), "--json", "sprockets"])
    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["schema_version"] == 1
    assert "generated_at" in report
    assert report["endpoints"][0]["path"] == "/api/v2/widget/sprockets"


def test_cli_missing_schema_file_reports_clear_error_exit_code(capsys):
    exit_code = discover_endpoints.main(["--schema-file", "/nonexistent/path/schema.json"])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Error reading schema file" in captured.err


def test_cli_no_matches_exits_zero_with_message(capsys):
    exit_code = discover_endpoints.main(["--schema-file", str(FIXTURE), "nonexistent-term-xyz"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "No matching GET endpoints found." in captured.out


def test_cli_never_prints_api_key_even_on_error(monkeypatch, tmp_path, capsys):
    sentinel_key = "SENTINEL-DO-NOT-PRINT-1234567890"
    key_file = tmp_path / "test.key"
    key_file.write_text(sentinel_key + "\n")

    monkeypatch.setenv("PFSENSE_API_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("PFSENSE_IDENTITY", "test-identity")
    monkeypatch.setenv("PFSENSE_API_KEY_FILE", str(key_file))
    monkeypatch.delenv("PFSENSE_TLS_CA_FILE", raising=False)

    exit_code = discover_endpoints.main([])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert sentinel_key not in captured.out
    assert sentinel_key not in captured.err


def test_cli_missing_env_vars_reports_configuration_error(monkeypatch, capsys):
    for var in ("PFSENSE_API_URL", "PFSENSE_IDENTITY", "PFSENSE_API_KEY_FILE"):
        monkeypatch.delenv(var, raising=False)

    exit_code = discover_endpoints.main([])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Error:" in captured.err


def test_report_never_includes_the_word_verified(capsys):
    discover_endpoints.main(["--schema-file", str(FIXTURE)])
    captured = capsys.readouterr()
    assert "verified" not in captured.out.lower()

    discover_endpoints.main(["--schema-file", str(FIXTURE), "--json"])
    captured = capsys.readouterr()
    assert "verified" not in captured.out.lower()
