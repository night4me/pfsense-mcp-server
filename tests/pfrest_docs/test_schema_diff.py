"""Tests for pfsense_mcp.pfrest_docs.schema_diff (owner direction,
pfREST_LIVE_GUIDANCE_ARC continuation, 2026-08-28: "make OpenAPI first-
class" + real-world CE/pfREST-version comparison tooling).

Pure module, no I/O -- every test constructs small synthetic OpenAPI-
shaped dicts directly, never touches the network or a real appliance."""

from __future__ import annotations

from pfsense_mcp.pfrest_docs.schema_diff import (
    ALL_DIMENSIONS,
    MAX_ENTRIES_PER_DIMENSION,
    ChangeKind,
    diff_schemas,
)


def _base_document() -> dict:
    return {
        "openapi": "3.0.0",
        "info": {"title": "pfSense REST API Documentation", "version": "unknown", "license": {"name": "Apache 2.0"}},
        "paths": {
            "/api/v2/firewall/alias": {
                "get": {
                    "operationId": "getFirewallAliasEndpoint",
                    "parameters": [{"name": "id", "in": "query", "required": True}],
                    "description": (
                        "<h3>Details:</h3>"
                        "**Requires authentication**: Yes<br>"
                        "**Supported authentication modes:** [ BasicAuth ]<br>"
                        "**Allowed privileges**: [ page-all, api-v2-firewall-alias-get ]<br>"
                        "**Required packages**: [ None ]<br>"
                        "**Applies immediately**: No<br>"
                    ),
                }
            }
        },
        "components": {
            "schemas": {
                "FirewallAlias": {
                    "properties": {
                        "name": {"type": "string", "nullable": False, "default": "example"},
                        "type": {"type": "string", "enum": ["host", "network"]},
                    },
                    "required": ["name"],
                }
            }
        },
    }


def test_identical_documents_produce_no_differences():
    doc = _base_document()
    report = diff_schemas(doc, doc, label_a="A", label_b="B")
    assert report.entries == ()
    assert set(report.identical_dimensions) == set(ALL_DIMENSIONS)
    assert report.truncated_dimensions == ()
    assert all(total == 0 for _dim, total in report.dimension_totals)


def test_added_and_removed_path_method():
    doc_a = _base_document()
    doc_b = _base_document()
    doc_b["paths"]["/api/v2/firewall/rule"] = {"get": {"operationId": "getFirewallRuleEndpoint"}}
    del doc_b["paths"]["/api/v2/firewall/alias"]

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    entries_by_dim = {e.dimension: e for e in report.entries}
    added = [e for e in report.entries if e.dimension == "paths_methods" and e.change == ChangeKind.ADDED_IN_B]
    removed = [e for e in report.entries if e.dimension == "paths_methods" and e.change == ChangeKind.REMOVED_IN_B]
    assert len(added) == 1
    assert added[0].key == "GET /api/v2/firewall/rule"
    assert len(removed) == 1
    assert removed[0].key == "GET /api/v2/firewall/alias"
    assert entries_by_dim  # sanity: dict was populated


def test_changed_operation_id():
    doc_a = _base_document()
    doc_b = _base_document()
    doc_b["paths"]["/api/v2/firewall/alias"]["get"]["operationId"] = "renamedOperation"

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    matching = [e for e in report.entries if e.dimension == "operation_ids"]
    assert len(matching) == 1
    assert matching[0].change == ChangeKind.CHANGED
    assert "getFirewallAliasEndpoint" in matching[0].detail
    assert "renamedOperation" in matching[0].detail


def test_changed_parameters():
    doc_a = _base_document()
    doc_b = _base_document()
    doc_b["paths"]["/api/v2/firewall/alias"]["get"]["parameters"] = [
        {"name": "id", "in": "query", "required": False},
        {"name": "limit", "in": "query", "required": False},
    ]

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    matching = [e for e in report.entries if e.dimension == "parameters"]
    assert len(matching) == 1
    assert matching[0].change == ChangeKind.CHANGED


def test_added_removed_schema_model():
    doc_a = _base_document()
    doc_b = _base_document()
    doc_b["components"]["schemas"]["FirewallRule"] = {"properties": {}}
    del doc_b["components"]["schemas"]["FirewallAlias"]

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    added = [e for e in report.entries if e.dimension == "schemas_models" and e.change == ChangeKind.ADDED_IN_B]
    removed = [e for e in report.entries if e.dimension == "schemas_models" and e.change == ChangeKind.REMOVED_IN_B]
    assert [e.key for e in added] == ["FirewallRule"]
    assert [e.key for e in removed] == ["FirewallAlias"]


def test_field_added_removed_and_changed():
    doc_a = _base_document()
    doc_b = _base_document()
    props_b = doc_b["components"]["schemas"]["FirewallAlias"]["properties"]
    props_b["descr"] = {"type": "string"}
    del props_b["type"]
    props_b["name"]["type"] = "integer"

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    field_entries = {e.key: e for e in report.entries if e.dimension == "fields"}
    assert field_entries["FirewallAlias.descr"].change == ChangeKind.ADDED_IN_B
    assert field_entries["FirewallAlias.type"].change == ChangeKind.REMOVED_IN_B
    assert field_entries["FirewallAlias.name"].change == ChangeKind.CHANGED


def test_enum_values_changed():
    doc_a = _base_document()
    doc_b = _base_document()
    doc_b["components"]["schemas"]["FirewallAlias"]["properties"]["type"]["enum"] = ["host", "network", "port"]

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    matching = [e for e in report.entries if e.dimension == "enums"]
    assert len(matching) == 1
    assert matching[0].key == "FirewallAlias.type"


def test_default_value_change_is_its_own_dimension_not_fields():
    """Regression: a differing `default` must not masquerade as a
    structural `fields` change (type/required/nullable are unaffected;
    only the default differs) -- this is the exact real-world shape
    found comparing LAB LIVE_APPLIANCE_SCHEMA against PFREST_UPSTREAM
    (both pfREST 2.10.2): identical structure, three differing
    instance-specific default values."""

    doc_a = _base_document()
    doc_b = _base_document()
    doc_b["components"]["schemas"]["FirewallAlias"]["properties"]["name"]["default"] = "different-example"

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    default_entries = [e for e in report.entries if e.dimension == "default_values"]
    field_entries = [e for e in report.entries if e.dimension == "fields"]
    assert len(default_entries) == 1
    assert default_entries[0].key == "FirewallAlias.name"
    assert "instance-specific" in default_entries[0].detail
    assert field_entries == []


def test_default_none_is_distinguished_from_default_absent():
    doc_a = _base_document()
    doc_b = _base_document()
    doc_b["components"]["schemas"]["FirewallAlias"]["properties"]["name"]["default"] = None

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    default_entries = [e for e in report.entries if e.dimension == "default_values"]
    assert len(default_entries) == 1


def test_required_packages_auth_privileges_applies_immediately_changed():
    doc_a = _base_document()
    doc_b = _base_document()
    doc_b["paths"]["/api/v2/firewall/alias"]["get"]["description"] = (
        "<h3>Details:</h3>"
        "**Requires authentication**: No<br>"
        "**Supported authentication modes:** [ BasicAuth, JWTAuth ]<br>"
        "**Allowed privileges**: [ page-all, some-renamed-privilege ]<br>"
        "**Required packages**: [ some-package ]<br>"
        "**Applies immediately**: Yes<br>"
    )

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    dims_hit = {e.dimension for e in report.entries}
    assert "required_packages" in dims_hit
    assert "auth_metadata" in dims_hit
    assert "allowed_privileges" in dims_hit
    assert "applies_immediately" in dims_hit


def test_extensions_added_removed_changed():
    doc_a = _base_document()
    doc_b = _base_document()
    doc_a["x-build-id"] = "111"
    doc_b["x-build-id"] = "222"
    doc_b["x-new-extension"] = "value"

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    ext_entries = {e.key: e for e in report.entries if e.dimension == "extensions"}
    assert ext_entries["/x-build-id"].change == ChangeKind.CHANGED
    assert ext_entries["/x-new-extension"].change == ChangeKind.ADDED_IN_B


def test_version_metadata_changed():
    doc_a = _base_document()
    doc_b = _base_document()
    doc_b["info"]["version"] = "2.10.2"

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    matching = [e for e in report.entries if e.dimension == "version_metadata"]
    assert len(matching) == 1
    assert matching[0].key == "info.version"


def test_output_is_capped_per_dimension_but_total_is_exact():
    doc_a = {"paths": {}}
    doc_b = {"paths": {f"/api/v2/synthetic/{i}": {"get": {}} for i in range(MAX_ENTRIES_PER_DIMENSION + 10)}}

    report = diff_schemas(doc_a, doc_b, label_a="A", label_b="B")
    shown = [e for e in report.entries if e.dimension == "paths_methods"]
    assert len(shown) == MAX_ENTRIES_PER_DIMENSION
    total = dict(report.dimension_totals)["paths_methods"]
    assert total == MAX_ENTRIES_PER_DIMENSION + 10
    assert "paths_methods" in report.truncated_dimensions


def test_malformed_documents_never_raise():
    malformed_variants = [
        {},
        {"paths": None},
        {"paths": {"/x": None}},
        {"paths": {"/x": {"get": None}}},
        {"components": None},
        {"components": {"schemas": None}},
        {"components": {"schemas": {"Foo": None}}},
        {"components": {"schemas": {"Foo": {"properties": None}}}},
    ]
    for variant in malformed_variants:
        report = diff_schemas(variant, _base_document(), label_a="A", label_b="B")
        assert isinstance(report.entries, tuple)


def test_disclaimer_present_and_never_attributes_cause():
    report = diff_schemas(_base_document(), _base_document(), label_a="A", label_b="B")
    assert "never WHY" in report.disclaimer
    assert "Do not attribute" in report.disclaimer


def test_all_dimensions_covered_by_the_module():
    assert set(ALL_DIMENSIONS) == {
        "paths_methods",
        "operation_ids",
        "parameters",
        "schemas_models",
        "fields",
        "enums",
        "default_values",
        "required_packages",
        "auth_metadata",
        "allowed_privileges",
        "applies_immediately",
        "extensions",
        "version_metadata",
    }


def test_module_performs_no_network_or_appliance_io():
    """Structural: schema_diff.py must not import any network-capable
    or client module -- it is pure data transformation over two
    already-fetched dicts, matching the rest of this package's split
    between fetch-capable and pure modules."""

    import ast
    from pathlib import Path

    tree = ast.parse(
        Path("src/pfsense_mcp/pfrest_docs/schema_diff.py").read_text(encoding="utf-8"),
        filename="schema_diff.py",
    )
    forbidden = {"httpx", "requests", "socket", "urllib.request", "pfsense_mcp.pfsense_client"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            assert node.module not in forbidden
