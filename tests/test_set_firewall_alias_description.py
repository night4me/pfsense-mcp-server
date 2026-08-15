"""set_firewall_alias_description_v1 tool definition tests -- the model-
visible schema, and that the handler wires to
`tier1_write_bridge.request_alias_description_change()` rather than
reconstructing any security semantics of its own.
"""

from __future__ import annotations

import inspect
from unittest.mock import Mock

from pfsense_mcp import tier1_write_bridge
from pfsense_mcp.models.write_outcome import AliasDescriptionWriteResult
from pfsense_mcp.tools.write import set_firewall_alias_description

_FORBIDDEN_SCHEMA_TERMS = (
    "plan_digest",
    "step_id",
    "authorization_id",
    "authority_id",
    "signature",
    "contract",
    "endpoint",
    "fingerprint",
    "rollback",
    "digest",
    "posture",
    "anchor",
    "confirmation_evidence",
    "planauthorization",
)


def test_model_visible_signature_is_exactly_alias_name_and_description():
    fn = set_firewall_alias_description.build()
    signature = inspect.signature(fn)
    assert list(signature.parameters) == ["alias_name", "description"]
    hints = inspect.get_annotations(fn, eval_str=True)
    assert hints["alias_name"] is str
    assert hints["description"] is str
    assert hints["return"] is AliasDescriptionWriteResult


def test_docstring_never_mentions_security_internal_terms():
    fn = set_firewall_alias_description.build()
    docstring = (fn.__doc__ or "").lower()
    offending = [term for term in _FORBIDDEN_SCHEMA_TERMS if term in docstring]
    assert offending == [], f"tool docstring leaks security-internal term(s): {offending}"


def test_handler_calls_the_bridge_and_returns_its_result_unmodified(monkeypatch):
    expected = AliasDescriptionWriteResult(state="awaiting_confirmation")
    mock_call = Mock(return_value=expected)
    monkeypatch.setattr(tier1_write_bridge, "request_alias_description_change", mock_call)

    fn = set_firewall_alias_description.build()
    result = fn(alias_name="LAB_ALIAS_TEST", description="after")

    mock_call.assert_called_once_with(alias_name="LAB_ALIAS_TEST", description="after")
    assert result is expected


def test_handler_module_defines_no_authorization_or_confirmation_logic_of_its_own():
    import ast
    from pathlib import Path

    path = Path("src/pfsense_mcp/tools/write/set_firewall_alias_description.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    called_names = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    } | {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    forbidden = {"verify", "sign", "authorize_and_create", "confirm_and_handoff", "try_consume", "execute"}
    offending = called_names & forbidden
    assert offending == set(), f"tool module calls a forbidden security-logic method: {offending}"
