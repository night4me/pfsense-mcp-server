"""Plain-string code generators and anchor-based insertion helpers for
scaffold_capability.py.

No template engine, no new dependency — every generator here is a
plain Python f-string, deliberately mirroring the exact shape of the
hand-written capabilities already committed under src/pfsense_mcp/
(gateways.py, firewall.py models; the get_firewall_states/
get_gateway_status client methods; the tools/read/*.py tool modules).

Anchor-based insertion (insert_after_anchor, find_method_body_end)
refuses whenever an anchor is found zero or more-than-one times —
never guesses, never silently picks the "closest" match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


class AnchorError(Exception):
    def __init__(self, category: str, reason: str) -> None:
        self.category = category
        self.reason = reason
        super().__init__(f"[{category}] {reason}")


def insert_after_anchor(original: str, anchor: str, insertion: str, *, anchor_name: str) -> str:
    count = original.count(anchor)
    if count == 0:
        raise AnchorError("anchor-missing", f"anchor {anchor_name!r} not found")
    if count > 1:
        raise AnchorError("anchor-ambiguous", f"anchor {anchor_name!r} found {count} times, expected exactly once")
    idx = original.index(anchor)
    insert_at = idx + len(anchor)
    return original[:insert_at] + insertion + original[insert_at:]


def replace_anchor(original: str, anchor: str, replacement: str, *, anchor_name: str) -> str:
    count = original.count(anchor)
    if count == 0:
        raise AnchorError("anchor-missing", f"anchor {anchor_name!r} not found")
    if count > 1:
        raise AnchorError("anchor-ambiguous", f"anchor {anchor_name!r} found {count} times, expected exactly once")
    return original.replace(anchor, replacement, 1)


def find_method_body_end(source: str, method_name: str, *, indent: str = "    ") -> int:
    """Returns the index right after the last line of method_name's
    body (assumed to be a single-level-indented class method), i.e.
    where new lines may be appended to extend it in place. Refuses
    (raises AnchorError) unless the method is found exactly once."""
    pattern = re.compile(rf"\n{indent}def {re.escape(method_name)}\(.*?\n(?=\n{indent}def |\Z)", re.DOTALL)
    matches = list(pattern.finditer(source))
    if not matches:
        raise AnchorError("anchor-missing", f"method {method_name!r} not found")
    if len(matches) > 1:
        raise AnchorError("anchor-ambiguous", f"method {method_name!r} found {len(matches)} times")
    return matches[0].end()


def append_to_method_body(source: str, method_name: str, addition: str, *, indent: str = "    ") -> str:
    end = find_method_body_end(source, method_name, indent=indent)
    return source[:end] + addition + source[end:]


def append_at_end_of_file(source: str, addition: str) -> str:
    return source.rstrip("\n") + "\n" + addition


_TYPE_MAP = {
    "integer": "int",
    "string": "str",
    "boolean": "bool",
    "number": "float",
}


def openapi_type_to_python(type_str: str | None) -> str:
    if type_str is None:
        return "Any"
    if type_str in _TYPE_MAP:
        return _TYPE_MAP[type_str]
    if type_str.startswith("array<") and type_str.endswith(">"):
        inner = type_str[len("array<") : -1]
        return f"list[{openapi_type_to_python(inner)}]"
    if "|" in type_str:
        parts = [openapi_type_to_python(p) for p in type_str.split("|")]
        return " | ".join(parts)
    return "Any"


@dataclass(frozen=True)
class GeneratedField:
    name: str
    python_type: str
    nullable: bool

    @property
    def annotation(self) -> str:
        return f"{self.python_type} | None" if self.nullable else self.python_type


# ------------------------------------------------------------------
# Model file
# ------------------------------------------------------------------


def render_model_file(
    model_class_name: str,
    fields: list[GeneratedField],
    identifying_fields: tuple[str, ...],
    response_shape: str,
) -> str:
    non_identifying = [f for f in fields if f.name not in identifying_fields]
    identifying = [f for f in fields if f.name in identifying_fields]

    lines: list[str] = []
    lines.append(f'"""Model for the {model_class_name} capability endpoint.')
    lines.append("")
    lines.append("GENERATED PROPOSAL — review before use. Field types/nullability were")
    lines.append("derived from a saved OpenAPI discovery snapshot and cross-checked")
    lines.append("against an approved fixture; identifying_fields is exactly what the")
    lines.append("capability manifest declared, never inferred.")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("from typing import Any")
    lines.append("")
    if identifying:
        lines.append("from pydantic import BaseModel, Field")
    else:
        lines.append("from pydantic import BaseModel")
    lines.append("")

    if identifying:
        tuple_name = f"_{_to_snake_upper(model_class_name)}_IDENTIFYING_FIELDS"
        names = ", ".join(f'"{f.name}"' for f in identifying)
        lines.append(f"{tuple_name} = ({names},)")
        lines.append("")
    else:
        tuple_name = None

    lines.append("")
    lines.append(f"class {model_class_name}(BaseModel):")
    for f in non_identifying:
        lines.append(f"    {f.name}: {f.annotation}")
    for f in identifying:
        lines.append(f"    {f.name}: {f.python_type} | None = Field(")
        lines.append("        default=None,")
        lines.append(
            '        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",'
        )
        lines.append("    )")

    lines.append("")
    lines.append("    @classmethod")
    if identifying:
        lines.append(
            f"    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) "
            f'-> "{model_class_name}":'
        )
        lines.append(f"        identifying = {{field: data[field] for field in {tuple_name}}}")
        lines.append("        return cls(")
        for f in non_identifying:
            lines.append(f'            {f.name}=data["{f.name}"],')
        lines.append(
            "            **{field: (value if include_identifying_metadata else None) "
            "for field, value in identifying.items()},"
        )
        lines.append("        )")
    else:
        lines.append(f'    def from_api(cls, data: dict[str, Any]) -> "{model_class_name}":')
        lines.append("        return cls(")
        for f in non_identifying:
            lines.append(f'            {f.name}=data["{f.name}"],')
        lines.append("        )")

    return "\n".join(lines) + "\n"


def _to_snake_upper(class_name: str) -> str:
    s = re.sub(r"(?<!^)(?=[A-Z])", "_", class_name).upper()
    return s


# ------------------------------------------------------------------
# Tool file
# ------------------------------------------------------------------


def render_tool_file(
    *,
    tool_module_name: str,
    mcp_tool_name: str,
    client_method_name: str,
    model_class_name: str,
    model_module_name: str,
    has_identifying_fields: bool,
    response_shape: str,
    tool_summary: str,
    bounded_param_name: str | None,
    bounded_param_default: int | None,
) -> str:
    return_type = f"list[{model_class_name}]" if response_shape == "list" else model_class_name
    lines: list[str] = []
    lines.append(f'"""{mcp_tool_name} tool definition. GENERATED PROPOSAL — review before use."""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("from typing import Callable")
    lines.append("")
    lines.append(f"from ...models.{model_module_name} import {model_class_name}")
    lines.append("from ...pfsense_client import PfSenseClient")
    lines.append("")
    lines.append("")
    lines.append(f"def build(client: PfSenseClient) -> Callable[..., {return_type}]:")

    params = []
    if has_identifying_fields:
        params.append("include_identifying_metadata: bool = False")
    if bounded_param_name:
        params.append(f"{bounded_param_name}: int = {bounded_param_default}")
    param_sig = ", ".join(params)

    lines.append(f"    def {mcp_tool_name}({param_sig}) -> {return_type}:")
    lines.append(f'        """{tool_summary}')
    if has_identifying_fields:
        lines.append("")
        lines.append("        include_identifying_metadata: if True, includes identifying")
        lines.append("        fields in the response. Defaults to False.")
    lines.append('        """')

    call_args = []
    if has_identifying_fields:
        call_args.append("include_identifying_metadata=include_identifying_metadata")
    if bounded_param_name:
        call_args.append(f"{bounded_param_name}={bounded_param_name}")
    call_arg_str = ", ".join(call_args)

    lines.append(f"        return client.{client_method_name}({call_arg_str})")
    lines.append("")
    lines.append(f"    return {mcp_tool_name}")

    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------
# PfSenseClient method snippet
# ------------------------------------------------------------------


def render_client_method(
    *,
    client_method_name: str,
    model_class_name: str,
    endpoint_symbol: str,
    endpoint_path: str,
    has_identifying_fields: bool,
    response_shape: str,
    bounded_param_name: str | None,
    bounded_param_default: int,
    bounded_param_min_const: str | None,
    bounded_param_max_const: str | None,
) -> str:
    return_type = f"list[{model_class_name}]" if response_shape == "list" else model_class_name

    sig_parts = ["self"]
    if has_identifying_fields:
        sig_parts.append("*")
        sig_parts.append("include_identifying_metadata: bool = False")
        if bounded_param_name:
            sig_parts.append(f"{bounded_param_name}: int = {bounded_param_default}")
    elif bounded_param_name:
        sig_parts.append("*")
        sig_parts.append(f"{bounded_param_name}: int = {bounded_param_default}")
    sig = ", ".join(sig_parts)

    lines: list[str] = []
    lines.append(f"    def {client_method_name}({sig}) -> {return_type}:")

    if bounded_param_name:
        lines.append(
            f"        if not ({bounded_param_min_const} <= {bounded_param_name} <= {bounded_param_max_const}):"
        )
        lines.append("            raise PfSenseRequestValidationError(")
        lines.append(
            f'                f"{bounded_param_name} must be between {{{bounded_param_min_const}}} and '
            f'{{{bounded_param_max_const}}} (got {{{bounded_param_name}}})."'
        )
        lines.append("            )")
        lines.append("")
        lines.append(
            f"        raw = self._rest.get(Endpoints.{endpoint_symbol}, "
            f'params={{"{bounded_param_name}": {bounded_param_name}}})'
        )
    else:
        lines.append(f"        raw = self._rest.get(Endpoints.{endpoint_symbol})")

    lines.append("")
    lines.append('        if "data" not in raw:')
    lines.append(
        f"            raise PfSenseResponseShapeError(\"pfSense {endpoint_path} response did not contain 'data'.\")"
    )
    lines.append('        data = raw["data"]')

    if response_shape == "list":
        lines.append("        if not isinstance(data, list):")
        lines.append(
            f"            raise PfSenseResponseShapeError(\"pfSense {endpoint_path} response 'data' was not a list.\")"
        )
        lines.append("")
        lines.append(f"        results: list[{model_class_name}] = []")
        lines.append("        for item in data:")
        lines.append("            if not isinstance(item, dict):")
        lines.append("                raise PfSenseResponseShapeError(")
        lines.append(
            f"                    \"pfSense {endpoint_path} response contained a non-object entry in 'data'.\""
        )
        lines.append("                )")
        lines.append("            try:")
        if has_identifying_fields:
            lines.append("                results.append(")
            lines.append(f"                    {model_class_name}.from_api(")
            lines.append("                        item, include_identifying_metadata=include_identifying_metadata")
            lines.append("                    )")
            lines.append("                )")
        else:
            lines.append(f"                results.append({model_class_name}.from_api(item))")
        lines.append("            except (KeyError, TypeError, ValidationError):")
        lines.append("                raise PfSenseResponseShapeError(")
        lines.append(
            f'                    "pfSense {endpoint_path} response contained an entry that failed schema validation."'
        )
        lines.append("                ) from None")
        lines.append("        return results")
    else:
        lines.append("        if not isinstance(data, dict):")
        lines.append("            raise PfSenseResponseShapeError(")
        lines.append(f"                \"pfSense {endpoint_path} response 'data' was not an object.\"")
        lines.append("            )")
        lines.append("        try:")
        if has_identifying_fields:
            lines.append(f"            return {model_class_name}.from_api(")
            lines.append("                data, include_identifying_metadata=include_identifying_metadata")
            lines.append("            )")
        else:
            lines.append(f"            return {model_class_name}.from_api(data)")
        lines.append("        except (KeyError, TypeError, ValidationError):")
        lines.append("            raise PfSenseResponseShapeError(")
        lines.append(f'                "pfSense {endpoint_path} response failed schema validation."')
        lines.append("            ) from None")

    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------
# pfsense_client.py model-import insertion
# ------------------------------------------------------------------

_MODELS_IMPORT_LINE_RE = re.compile(r"^from \.models\.(\w+) import (.+)$", re.MULTILINE)
_MODELS_IMPORT_BLOCK_RE = re.compile(r"(?:^from \.models\.\w+ import .+\n)+", re.MULTILINE)


def insert_client_model_import(source: str, model_module_name: str, model_class_name: str) -> str:
    """Ensures `from .models.<model_module_name> import <model_class_name>`
    is present in pfsense_client.py, in sorted order alongside the
    other `from .models.X import ...` lines (matching the existing,
    isort-compatible ordering already used there).

    Refuses (AnchorError) if that contiguous import block is missing
    or not found exactly once — never guesses where to insert. Never
    duplicates an already-imported name: if model_class_name is
    already imported from model_module_name, refuses with category
    'already-imported' instead of writing a second copy.
    """
    blocks = list(_MODELS_IMPORT_BLOCK_RE.finditer(source))
    if not blocks:
        raise AnchorError("anchor-missing", "no 'from .models.X import ...' block found")
    if len(blocks) > 1:
        raise AnchorError("anchor-ambiguous", "'from .models.X import ...' lines are not one contiguous block")
    block = blocks[0]

    parsed: dict[str, list[str]] = {}
    for line in block.group(0).splitlines():
        match = _MODELS_IMPORT_LINE_RE.match(line)
        if not match:
            raise AnchorError("malformed-import-block", f"unrecognized line in models import block: {line!r}")
        module, names_raw = match.group(1), match.group(2)
        parsed[module] = [n.strip() for n in names_raw.split(",")]

    if model_module_name in parsed:
        if model_class_name in parsed[model_module_name]:
            raise AnchorError(
                "already-imported",
                f"{model_class_name!r} is already imported from .models.{model_module_name}",
            )
        parsed[model_module_name] = sorted(parsed[model_module_name] + [model_class_name])
    else:
        parsed[model_module_name] = [model_class_name]

    new_block = "".join(f"from .models.{module} import {', '.join(parsed[module])}\n" for module in sorted(parsed))
    return source[: block.start()] + new_block + source[block.end() :]


# ------------------------------------------------------------------
# Live test file (opt-in)
# ------------------------------------------------------------------


def render_live_test_file(
    *,
    capability_name: str,
    client_method_name: str,
    model_class_name: str,
    model_module_name: str,
    identifying_fields: tuple[str, ...],
    response_shape: str,
    bounded_param_name: str | None,
) -> str:
    lines: list[str] = []
    lines.append(f'"""Live integration test for {client_method_name}. GENERATED PROPOSAL — review before use.')
    lines.append("")
    lines.append("Opt-in only: requires PFSENSE_RUN_LIVE_TESTS=true in addition to")
    lines.append("credentials. Never prints or persists a complete response — only")
    lines.append("structural and redaction assertions.")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("import os")
    lines.append("")
    lines.append("import pytest")
    lines.append("")
    lines.append("from pfsense_mcp.config import load_api_key, load_config")
    lines.append("from pfsense_mcp.factory import build_pfsense_client")
    # Only object-shape responses reference the model class by name
    # (an `isinstance(result, ModelClass)` assertion below); list-shape
    # responses only ever check `isinstance(result, list)` plus
    # attribute access on items, so importing the model class there
    # would be an unused import (ruff F401).
    if response_shape != "list":
        lines.append(f"from pfsense_mcp.models.{model_module_name} import {model_class_name}")
    lines.append("")
    lines.append('_RUN_LIVE = os.environ.get("PFSENSE_RUN_LIVE_TESTS", "").strip().lower() == "true"')
    lines.append("")
    lines.append("pytestmark = [")
    lines.append("    pytest.mark.live,")
    lines.append("    pytest.mark.skipif(")
    lines.append("        not _RUN_LIVE,")
    lines.append('        reason="Live pfSense test skipped: set PFSENSE_RUN_LIVE_TESTS=true to opt in.",')
    lines.append("    ),")
    lines.append("]")
    lines.append("")
    lines.append("")
    lines.append(f"def test_{client_method_name}_live_structure_only():")
    lines.append("    config = load_config()")
    lines.append("    api_key = load_api_key(config)")
    lines.append("    transport, client = build_pfsense_client(config, api_key)")
    lines.append("    try:")
    call_args = f"{bounded_param_name}=5" if bounded_param_name else ""
    lines.append(f"        result = client.{client_method_name}({call_args})")
    lines.append("")
    if response_shape == "list":
        lines.append("        assert isinstance(result, list)")
        if bounded_param_name:
            lines.append("        assert len(result) <= 5  # deliberately small: never pull the full live table")
        if identifying_fields:
            lines.append("        for item in result:")
            for name in identifying_fields:
                lines.append(f"            assert item.{name} is None")
    else:
        lines.append(f"        assert isinstance(result, {model_class_name})")
        for name in identifying_fields:
            lines.append(f"        assert result.{name} is None")
    lines.append("    finally:")
    lines.append("        transport.close()")

    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------
# Test skeletons for tests/test_pfsense_client.py (appended, not
# merged into the shared fixture-building helpers there)
# ------------------------------------------------------------------


def render_client_test_functions(
    *,
    client_method_name: str,
    model_class_name: str,
    fields: list[GeneratedField],
    identifying_fields: tuple[str, ...],
    response_shape: str,
    endpoint_path: str,
) -> str:
    non_identifying = [f for f in fields if f.name not in identifying_fields]
    sample_field = non_identifying[0].name if non_identifying else None

    lines: list[str] = []
    lines.append("")
    lines.append("")
    lines.append(f"# GENERATED PROPOSAL for {client_method_name} — review before use.")
    lines.append(f"def _{client_method_name}_body() -> dict:")
    lines.append("    # TODO(human): replace with the approved fixture's actual content")
    if response_shape == "list":
        lines.append('    return {"data": [{}]}')
    else:
        lines.append('    return {"data": {}}')
    lines.append("")
    lines.append("")
    lines.append(f"def test_{client_method_name}_omits_identifying_fields_by_default():")
    lines.append("    # TODO(human): wire up a MockTransport-backed client with the")
    lines.append("    # approved fixture body and assert identifying fields are None.")
    lines.append("    pass")
    lines.append("")
    lines.append("")
    if sample_field:
        lines.append(f"def test_{client_method_name}_maps_non_sensitive_fields():")
        lines.append(f"    # TODO(human): assert {sample_field} (and other non-identifying fields) map correctly.")
        lines.append("    pass")
        lines.append("")
        lines.append("")
    lines.append(f"def test_{client_method_name}_only_calls_expected_endpoint():")
    lines.append(f'    # TODO(human): assert transport.calls == [("GET", "/api/v2{endpoint_path}")]')
    lines.append("    pass")
    lines.append("")
    lines.append("")
    lines.append(f"def test_{client_method_name}_missing_data_key_raises_shape_error():")
    lines.append("    pass")
    lines.append("")
    lines.append("")
    lines.append(f"def test_{client_method_name}_data_wrong_type_raises_shape_error():")
    lines.append("    pass")
    if response_shape == "list":
        lines.append("")
        lines.append("")
        lines.append(f"def test_{client_method_name}_item_wrong_type_raises_shape_error():")
        lines.append("    pass")
    lines.append("")
    lines.append("")
    lines.append(f"def test_{client_method_name}_required_field_missing_raises_shape_error():")
    lines.append("    pass")
    lines.append("")
    lines.append("")
    lines.append(f"def test_{client_method_name}_invalid_field_type_raises_shape_error():")
    lines.append("    pass")
    lines.append("")
    lines.append("")
    lines.append(f"def test_{client_method_name}_shape_error_does_not_leak_raw_field_values():")
    lines.append("    pass")

    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------
# Registry helpers: import list, dispatch line, register method
# ------------------------------------------------------------------

_READ_IMPORT_BLOCK_RE = re.compile(r"from \.read import \(\n(?P<body>.*?)\n\)", re.DOTALL)


def insert_read_import(source: str, module_name: str) -> str:
    matches = list(_READ_IMPORT_BLOCK_RE.finditer(source))
    if not matches:
        raise AnchorError("anchor-missing", "'from .read import (...)' block not found")
    if len(matches) > 1:
        raise AnchorError("anchor-ambiguous", "'from .read import (...)' block found more than once")
    match = matches[0]
    existing = [line.strip().rstrip(",") for line in match.group("body").splitlines() if line.strip()]
    if module_name in existing:
        raise AnchorError("already-imported", f"{module_name!r} is already imported in registry.py")
    names = sorted(existing + [module_name])
    new_body = "\n".join(f"    {n}," for n in names)
    replacement = f"from .read import (\n{new_body}\n)"
    return source[: match.start()] + replacement + source[match.end() :]


def insert_register_all_dispatch(source: str, capability_name: str) -> str:
    addition = (
        f"        if Capability.{capability_name} in self._capabilities:\n"
        f"            self._register_{capability_name.lower()}()\n"
    )
    return append_to_method_body(source, "register_all", addition)


def render_register_method(capability_name: str, tool_registrations: list[tuple[str, str]]) -> str:
    """tool_registrations: list of (mcp_tool_name, tool_module_name)."""
    lines = [f"\n    def _register_{capability_name.lower()}(self) -> None:"]
    for i, (tool_name, module_name) in enumerate(tool_registrations):
        var = "fn" if len(tool_registrations) == 1 else f"{tool_name.replace('pfsense_get_', '')}_fn"
        wrapped_var = "wrapped" if len(tool_registrations) == 1 else f"wrapped_{tool_name.replace('pfsense_get_', '')}"
        lines.append(f"        {var} = {module_name}.build(self._client)")
        lines.append(f'        {wrapped_var} = audit_logged("{tool_name}", self._identity)({var})')
        lines.append(f"        self._mcp.tool()({wrapped_var})")
        if i != len(tool_registrations) - 1:
            lines.append("")
    return "\n".join(lines) + "\n"


def render_register_method_extension(tool_name: str, module_name: str) -> str:
    return (
        f"\n        {module_name}_fn = {module_name}.build(self._client)\n"
        f'        {module_name}_wrapped = audit_logged("{tool_name}", self._identity)({module_name}_fn)\n'
        f"        self._mcp.tool()({module_name}_wrapped)\n"
    )


# ------------------------------------------------------------------
# capabilities.py / profiles.py frozenset insertion
# ------------------------------------------------------------------

_READ_MARKER_COMMENT = "    # Not usable until a separate, explicitly authorized implementation phase:"


def insert_new_capability_enum_member(source: str, capability_name: str) -> str:
    replacement = f"    {capability_name} = auto()\n{_READ_MARKER_COMMENT}"
    return replace_anchor(source, _READ_MARKER_COMMENT, replacement, anchor_name="write-capability marker comment")


# Matches both ruff format's single-line style (small sets) and its
# multi-line, one-member-per-line, trailing-comma style (once a set no
# longer fits the line-length limit) — \s already spans newlines, so
# no re.DOTALL is needed.
_CAPABILITY_FROZENSET_RE = re.compile(r"\{\s*Capability\.\w+(?:\s*,\s*Capability\.\w+)*\s*,?\s*\}")


def find_capability_frozenset_literal(source: str) -> str:
    """Extracts the CURRENT `{Capability.X, Capability.Y, ...}` literal
    from a file's actual content — never a hardcoded expectation of
    what that literal looks like, since it changes every time a
    capability is added. Refuses if not found exactly once."""
    matches = list(_CAPABILITY_FROZENSET_RE.finditer(source))
    if not matches:
        raise AnchorError("anchor-missing", "no '{Capability....}' frozenset literal found")
    if len(matches) > 1:
        raise AnchorError(
            "anchor-ambiguous", f"found {len(matches)} '{{Capability....}}' frozenset literals, expected exactly one"
        )
    return matches[0].group(0)


def insert_into_capability_frozenset(source: str, anchor_set_text: str, capability_name: str) -> str:
    if not anchor_set_text.startswith("{") or not anchor_set_text.endswith("}"):
        raise AnchorError("invalid-anchor", "capability frozenset anchor must be a '{...}' literal")

    names = re.findall(r"Capability\.(\w+)", anchor_set_text)
    if capability_name in names:
        raise AnchorError("already-in-frozenset", f"Capability.{capability_name} is already present")
    names.append(capability_name)

    if "\n" in anchor_set_text:
        # Multi-line, trailing-comma style: re-render deterministically
        # from the parsed member list rather than patching around the
        # existing trailing comma, which would risk a double comma.
        # Preserve the exact member/closing-brace indentation in use.
        member_indent_match = re.search(r"\n(\s+)Capability\.", anchor_set_text)
        closing_indent_match = re.search(r"\n(\s*)\}\Z", anchor_set_text)
        if not member_indent_match or not closing_indent_match:
            raise AnchorError("invalid-anchor", "could not determine indentation of multi-line frozenset literal")
        member_indent = member_indent_match.group(1)
        closing_indent = closing_indent_match.group(1)
        body = "".join(f"{member_indent}Capability.{n},\n" for n in names)
        new_set_text = "{\n" + body + closing_indent + "}"
    else:
        new_set_text = "{" + ", ".join(f"Capability.{n}" for n in names) + "}"

    return replace_anchor(source, anchor_set_text, new_set_text, anchor_name="capability frozenset literal")
