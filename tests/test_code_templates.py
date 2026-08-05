"""Unit tests for scripts/lib/code_templates.py — pure string
generation and anchor-based insertion, synthetic source only."""

from __future__ import annotations

import ast
import subprocess
import sys

import pytest
from lib.code_templates import (
    AnchorError,
    GeneratedField,
    append_at_end_of_file,
    append_to_method_body,
    find_capability_frozenset_literal,
    find_method_body_end,
    insert_after_anchor,
    insert_client_model_import,
    insert_into_capability_frozenset,
    insert_new_capability_enum_member,
    insert_read_import,
    insert_register_all_dispatch,
    openapi_type_to_python,
    render_client_method,
    render_live_test_file,
    render_model_file,
    render_register_method,
    render_register_method_extension,
    render_tool_file,
    replace_anchor,
)


def test_openapi_type_mapping():
    assert openapi_type_to_python("integer") == "int"
    assert openapi_type_to_python("string") == "str"
    assert openapi_type_to_python("boolean") == "bool"
    assert openapi_type_to_python("number") == "float"
    assert openapi_type_to_python("array<string>") == "list[str]"
    assert openapi_type_to_python("integer|string") == "int | str"
    assert openapi_type_to_python(None) == "Any"
    assert openapi_type_to_python("something-unknown") == "Any"


def test_insert_after_anchor_missing_refuses():
    with pytest.raises(AnchorError) as excinfo:
        insert_after_anchor("hello world", "xyz", "!!!", anchor_name="xyz")
    assert excinfo.value.category == "anchor-missing"


def test_insert_after_anchor_ambiguous_refuses():
    with pytest.raises(AnchorError) as excinfo:
        insert_after_anchor("aa bb aa", "aa", "!", anchor_name="aa")
    assert excinfo.value.category == "anchor-ambiguous"


def test_insert_after_anchor_single_match_works():
    result = insert_after_anchor("hello world", "hello", "!!!", anchor_name="hello")
    assert result == "hello!!! world"


def test_replace_anchor_ambiguous_refuses():
    with pytest.raises(AnchorError):
        replace_anchor("aa aa", "aa", "bb", anchor_name="aa")


def test_find_method_body_end_missing_refuses():
    with pytest.raises(AnchorError) as excinfo:
        find_method_body_end("class X:\n    def foo(self):\n        pass\n", "bar")
    assert excinfo.value.category == "anchor-missing"


def test_find_method_body_end_ambiguous_refuses():
    src = "class X:\n    def foo(self):\n        pass\n\n    def foo(self):\n        pass\n"
    with pytest.raises(AnchorError) as excinfo:
        find_method_body_end(src, "foo")
    assert excinfo.value.category == "anchor-ambiguous"


def test_append_to_method_body_extends_correct_method():
    src = "class X:\n    def foo(self):\n        return 1\n\n    def bar(self):\n        return 2\n"
    result = append_to_method_body(src, "foo", "        # extra\n")
    assert "def foo(self):\n        return 1\n        # extra\n\n    def bar" in result
    ast.parse(result)


def test_render_model_file_with_identifying_fields_parses():
    fields = [
        GeneratedField(name="id", python_type="int", nullable=False),
        GeneratedField(name="secret", python_type="str", nullable=True),
    ]
    src = render_model_file("Widget", fields, ("secret",), "list")
    ast.parse(src)
    assert "_WIDGET_IDENTIFYING_FIELDS" in src
    assert "include_identifying_metadata: bool = False" in src


def test_render_model_file_without_identifying_fields_has_no_metadata_param():
    fields = [GeneratedField(name="id", python_type="int", nullable=False)]
    src = render_model_file("Widget", fields, (), "object")
    ast.parse(src)
    assert "include_identifying_metadata" not in src
    assert "_WIDGET_IDENTIFYING_FIELDS" not in src


def test_render_model_file_escapes_reserved_keyword_field_name():
    # Regression test: pfSense's /interfaces endpoint literally names a
    # field "if" (physical interface name) — using it verbatim as a
    # Python class attribute / constructor kwarg name is a SyntaxError.
    # A trailing underscore (the standard Python convention, cf.
    # "type_", "class_") must be used for the Python identifier while
    # the raw dict subscript keeps reading via the original API name.
    fields = [
        GeneratedField(name="if", python_type="str", nullable=False),
        GeneratedField(name="descr", python_type="str", nullable=False),
    ]
    src = render_model_file("Widget", fields, (), "object")
    ast.parse(src)
    assert "if_: str" in src
    assert 'if_=data["if"]' in src
    assert "    if:" not in src


def test_generated_field_identifier_property():
    assert GeneratedField(name="if", python_type="str", nullable=False).identifier == "if_"
    assert GeneratedField(name="class", python_type="str", nullable=False).identifier == "class_"
    assert GeneratedField(name="descr", python_type="str", nullable=False).identifier == "descr"


def test_render_tool_file_list_shape_parses():
    src = render_tool_file(
        tool_module_name="widgets",
        mcp_tool_name="pfsense_get_widgets",
        client_method_name="get_widgets",
        model_class_name="Widget",
        model_module_name="widget",
        has_identifying_fields=True,
        response_shape="list",
        tool_summary="Get widgets.",
        bounded_param_name="limit",
        bounded_param_default=100,
    )
    ast.parse(src)
    assert "limit: int = 100" in src
    assert "list[Widget]" in src


def test_render_tool_file_singleton_no_identifying_has_no_metadata_param():
    src = render_tool_file(
        tool_module_name="widget_count",
        mcp_tool_name="pfsense_get_widget_count",
        client_method_name="get_widget_count",
        model_class_name="WidgetCount",
        model_module_name="widget_count",
        has_identifying_fields=False,
        response_shape="object",
        tool_summary="Get widget count.",
        bounded_param_name=None,
        bounded_param_default=None,
    )
    ast.parse(src)
    assert "include_identifying_metadata" not in src
    assert "def pfsense_get_widget_count() -> WidgetCount:" in src


def test_render_client_method_list_shape_bounded_parses():
    src = render_client_method(
        client_method_name="get_widgets",
        model_class_name="Widget",
        endpoint_symbol="WIDGETS",
        endpoint_path="/widgets",
        has_identifying_fields=True,
        response_shape="list",
        bounded_param_name="limit",
        bounded_param_default=100,
        bounded_param_min_const="WIDGETS_MIN_LIMIT",
        bounded_param_max_const="WIDGETS_MAX_LIMIT",
    )
    wrapped = "class X:\n" + src
    ast.parse(wrapped)
    assert "PfSenseRequestValidationError" in src
    assert "WIDGETS_MIN_LIMIT" in src


def test_render_client_method_object_shape_no_identifying_parses():
    src = render_client_method(
        client_method_name="get_widget_count",
        model_class_name="WidgetCount",
        endpoint_symbol="WIDGET_COUNT",
        endpoint_path="/widget-count",
        has_identifying_fields=False,
        response_shape="object",
        bounded_param_name=None,
        bounded_param_default=0,
        bounded_param_min_const=None,
        bounded_param_max_const=None,
    )
    wrapped = "class X:\n" + src
    ast.parse(wrapped)
    assert "def get_widget_count(self) -> WidgetCount:" in src
    assert "PfSenseRequestValidationError" not in src


def test_insert_read_import_alphabetical_and_no_duplicate():
    src = "from .read import (\n    aaa,\n    zzz,\n)\n"
    result = insert_read_import(src, "mmm")
    assert "    aaa,\n    mmm,\n    zzz,\n" in result

    with pytest.raises(AnchorError) as excinfo:
        insert_read_import(result, "mmm")
    assert excinfo.value.category == "already-imported"


def test_insert_register_all_dispatch():
    src = "class X:\n    def register_all(self) -> None:\n        pass\n\n    def other(self):\n        pass\n"
    result = insert_register_all_dispatch(src, "WIDGETS_READ")
    assert "if Capability.WIDGETS_READ in self._capabilities:" in result
    assert "self._register_widgets_read()" in result
    ast.parse(result)


def test_render_register_method_single_tool():
    src = render_register_method("WIDGETS_READ", [("pfsense_get_widgets", "widgets")])
    wrapped = "class X:\n" + src
    ast.parse(wrapped)
    assert "_register_widgets_read" in src


def test_render_register_method_extension():
    src = render_register_method_extension("pfsense_get_widgets", "widgets")
    wrapped = "class X:\n    def _register_widgets_read(self) -> None:\n        pass\n" + src
    ast.parse(wrapped)


def test_insert_new_capability_enum_member():
    src = (
        "class Capability(Enum):\n"
        "    SYSTEM_READ = auto()\n"
        "    # Not usable until a separate, explicitly authorized implementation phase:\n"
        "    FIREWALL_WRITE = auto()\n"
    )
    result = insert_new_capability_enum_member(src, "WIDGETS_READ")
    assert "WIDGETS_READ = auto()\n    # Not usable" in result
    ast.parse("from enum import Enum, auto\n" + result)


def test_insert_into_capability_frozenset():
    src = "X = frozenset(\n    {Capability.A, Capability.B}\n)\n"
    result = insert_into_capability_frozenset(src, "{Capability.A, Capability.B}", "WIDGETS_READ")
    assert "{Capability.A, Capability.B, Capability.WIDGETS_READ}" in result


def test_append_at_end_of_file():
    result = append_at_end_of_file("line1\nline2\n", "line3\n")
    assert result == "line1\nline2\nline3\n"


_CLIENT_IMPORTS_SAMPLE = (
    '"""PfSenseClient — domain layer."""\n'
    "\n"
    "from __future__ import annotations\n"
    "\n"
    "from pydantic import ValidationError\n"
    "\n"
    "from .endpoints import Endpoints\n"
    "from .errors import PfSenseRequestValidationError, PfSenseResponseShapeError\n"
    "from .models.firewall import FirewallApplyStatus, FirewallRule, FirewallState, FirewallStatesSize\n"
    "from .models.gateways import GatewayConfig, GatewayStatus\n"
    "from .models.interfaces import InterfaceStatus\n"
    "from .models.system import SystemStatus\n"
    "from .rest_api_client import RestApiClient\n"
    "\n"
    "\n"
    "class PfSenseClient:\n"
    "    def __init__(self, rest: RestApiClient) -> None:\n"
    "        self._rest = rest\n"
    "\n"
    "    def use_everything(\n"
    "        self,\n"
    "    ) -> (\n"
    "        Endpoints\n"
    "        | PfSenseRequestValidationError\n"
    "        | PfSenseResponseShapeError\n"
    "        | ValidationError\n"
    "        | FirewallApplyStatus\n"
    "        | FirewallRule\n"
    "        | FirewallState\n"
    "        | FirewallStatesSize\n"
    "        | GatewayConfig\n"
    "        | GatewayStatus\n"
    "        | InterfaceStatus\n"
    "        | SystemStatus\n"
    "    ):\n"
    "        raise NotImplementedError\n"
)


def test_insert_client_model_import_adds_new_module_in_sorted_position():
    result = insert_client_model_import(_CLIENT_IMPORTS_SAMPLE, "firewall_alias", "FirewallAlias")
    lines = result.splitlines()
    firewall_idx = lines.index(
        "from .models.firewall import FirewallApplyStatus, FirewallRule, FirewallState, FirewallStatesSize"
    )
    alias_idx = lines.index("from .models.firewall_alias import FirewallAlias")
    gateways_idx = lines.index("from .models.gateways import GatewayConfig, GatewayStatus")
    assert firewall_idx < alias_idx < gateways_idx
    ast.parse(result)


def test_insert_client_model_import_extends_existing_module_without_duplicate_line():
    result = insert_client_model_import(_CLIENT_IMPORTS_SAMPLE, "gateways", "GatewayGroup")
    assert result.count("from .models.gateways import") == 1
    assert "from .models.gateways import GatewayConfig, GatewayGroup, GatewayStatus" in result


def test_insert_client_model_import_refuses_exact_duplicate():
    with pytest.raises(AnchorError) as excinfo:
        insert_client_model_import(_CLIENT_IMPORTS_SAMPLE, "firewall", "FirewallRule")
    assert excinfo.value.category == "already-imported"


def test_insert_client_model_import_refuses_missing_block():
    source = '"""No model imports here."""\n\nfrom __future__ import annotations\n'
    with pytest.raises(AnchorError) as excinfo:
        insert_client_model_import(source, "firewall_alias", "FirewallAlias")
    assert excinfo.value.category == "anchor-missing"


def test_insert_client_model_import_refuses_ambiguous_non_contiguous_block():
    source = (
        "from .models.firewall import FirewallRule\n\nSOME_CONSTANT = 1\n\nfrom .models.gateways import GatewayConfig\n"
    )
    with pytest.raises(AnchorError) as excinfo:
        insert_client_model_import(source, "firewall_alias", "FirewallAlias")
    assert excinfo.value.category == "anchor-ambiguous"


def test_insert_client_model_import_result_parses_with_ast():
    result = insert_client_model_import(_CLIENT_IMPORTS_SAMPLE, "firewall_alias", "FirewallAlias")
    ast.parse(result)


def test_insert_client_model_import_result_passes_ruff():
    # Mirror real usage: the newly imported class is only unused in
    # isolation. In practice scaffold_capability.py always appends a
    # client method that consumes it (render_client_method) in the
    # same pass, so append an equivalent stub consumer here too —
    # otherwise ruff's unused-import check (F401) would fail for a
    # reason unrelated to import placement/duplication correctness.
    result = insert_client_model_import(_CLIENT_IMPORTS_SAMPLE, "firewall_alias", "FirewallAlias")
    result += "\n    def get_firewall_aliases(self) -> FirewallAlias:\n        raise NotImplementedError\n"

    check = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--stdin-filename=pfsense_client.py", "-"],
        input=result,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stdout + check.stderr

    fmt = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--check", "--stdin-filename=pfsense_client.py", "-"],
        input=result,
        capture_output=True,
        text=True,
    )
    assert fmt.returncode == 0, fmt.stdout + fmt.stderr


def test_render_live_test_file_list_shape_without_identifying_fields_parses():
    # Regression test: a list-shaped capability with zero identifying
    # fields (e.g. STATUS_SERVICES_READ) used to generate an empty
    # `for item in result:` loop body, which is a SyntaxError. The
    # loop must be omitted entirely when there is nothing to assert.
    src = render_live_test_file(
        capability_name="SERVICE_READ",
        client_method_name="get_service_status",
        model_class_name="ServiceStatus",
        model_module_name="service_status",
        identifying_fields=(),
        response_shape="list",
        bounded_param_name="limit",
    )
    ast.parse(src)
    assert "for item in result:" not in src
    # List-shape never references the model class by name; importing
    # it anyway would be an unused import (ruff F401).
    assert "import ServiceStatus" not in src


def test_render_live_test_file_list_shape_with_identifying_fields_still_parses():
    src = render_live_test_file(
        capability_name="WIDGETS_READ",
        client_method_name="get_widgets",
        model_class_name="Widget",
        model_module_name="widget",
        identifying_fields=("secret",),
        response_shape="list",
        bounded_param_name="limit",
    )
    ast.parse(src)
    assert "for item in result:" in src
    assert "assert item.secret is None" in src


def test_render_live_test_file_object_shape_imports_model_class():
    # Regression test: the object-shape branch asserts
    # `isinstance(result, ModelClass)` but the generated file never
    # imported ModelClass — syntactically valid (ast.parse passes) but
    # a NameError at actual test runtime. First caught when
    # SYSTEM_INFO_READ became the first object-shape capability to go
    # through the real generator (all earlier object-shape capabilities
    # predate scaffold_capability.py).
    #
    # Uses "service_status" (a real, already-committed module under
    # src/pfsense_mcp/models/) rather than a synthetic name: ruff's
    # first-party import classification depends on the target module
    # actually existing on disk, so a made-up module name here would
    # get misclassified and produce a spurious ruff isort finding
    # unrelated to what this test is actually checking.
    src = render_live_test_file(
        capability_name="SERVICE_READ",
        client_method_name="get_service_status",
        model_class_name="ServiceStatus",
        model_module_name="service_status",
        identifying_fields=(),
        response_shape="object",
        bounded_param_name=None,
    )
    ast.parse(src)
    assert "from pfsense_mcp.models.service_status import ServiceStatus" in src
    assert "isinstance(result, ServiceStatus)" in src

    check = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--stdin-filename=test_live_service_status.py", "-"],
        input=src,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stdout + check.stderr


_MULTILINE_CAPABILITIES_SAMPLE = (
    "SUPPORTED_CAPABILITIES_THIS_BUILD: frozenset[Capability] = frozenset(\n"
    "    {\n"
    "        Capability.SYSTEM_READ,\n"
    "        Capability.INTERFACE_READ,\n"
    "        Capability.GATEWAY_READ,\n"
    "        Capability.FIREWALL_READ,\n"
    "        Capability.ALIAS_READ,\n"
    "    }\n"
    ")\n"
)


def test_find_capability_frozenset_literal_handles_multiline_ruff_format():
    # Regression test: once enough capabilities are active that ruff
    # format wraps the frozenset across multiple lines (one member per
    # line, trailing comma), the anchor regex must still find it.
    literal = find_capability_frozenset_literal(_MULTILINE_CAPABILITIES_SAMPLE)
    assert literal.startswith("{") and literal.endswith("}")
    assert "Capability.ALIAS_READ" in literal


def test_insert_into_capability_frozenset_multiline_no_double_comma():
    literal = find_capability_frozenset_literal(_MULTILINE_CAPABILITIES_SAMPLE)
    result = insert_into_capability_frozenset(_MULTILINE_CAPABILITIES_SAMPLE, literal, "SERVICE_READ")
    assert ",," not in result
    assert ", ," not in result
    assert "Capability.SERVICE_READ" in result
    ast.parse("class Capability:\n    pass\n\n\n" + result)

    check = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--stdin-filename=capabilities.py", "-"],
        input="from enum import Enum\n\n\nclass Capability(Enum):\n    pass\n\n\n" + result,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stdout + check.stderr


def test_insert_into_capability_frozenset_singleline_still_works():
    src = "X = frozenset({Capability.A, Capability.B})\n"
    literal = find_capability_frozenset_literal(src)
    result = insert_into_capability_frozenset(src, literal, "C")
    assert "{Capability.A, Capability.B, Capability.C}" in result
