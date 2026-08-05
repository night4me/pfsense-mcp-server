"""Unit tests for scripts/lib/code_templates.py — pure string
generation and anchor-based insertion, synthetic source only."""

from __future__ import annotations

import ast

import pytest
from lib.code_templates import (
    AnchorError,
    GeneratedField,
    append_at_end_of_file,
    append_to_method_body,
    find_method_body_end,
    insert_after_anchor,
    insert_into_capability_frozenset,
    insert_new_capability_enum_member,
    insert_read_import,
    insert_register_all_dispatch,
    openapi_type_to_python,
    render_client_method,
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
