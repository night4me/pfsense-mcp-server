#!/usr/bin/env python3
"""scaffold_capability.py — generate a reviewable code-change proposal
for a new read-only capability, without touching any tracked file.

First version scope: exactly one endpoint per manifest. A capability
with several endpoints/tools is scaffolded across several separate
invocations, each extending the same capability — avoiding complex
multi-endpoint merge logic in this first version. Rejects manifests
that declare zero or more than one endpoint (structurally impossible
today since the manifest schema itself has no endpoints array, but
kept as an explicit, named refusal for a future schema revision).

Consumes only already-local, already-reviewed artifacts:
  - the real Endpoints registry (endpoint must be verified=True),
  - the real CAPTURE_POLICIES registry (endpoint must have a policy),
  - a saved OpenAPI discovery snapshot (discover_endpoints.py --json),
  - an APPROVED fixture already committed under tests/fixtures/ (not
    a mere dry-run-audited .fixture_proposals/ candidate).

No network access, no credentials — this tool never talks to
pfSense. Every output is written beneath .capability_proposals/<name>/
only; nothing under src/pfsense_mcp/ or tests/ is ever modified,
staged, or committed. Every generated .py file is confirmed to parse
via ast.parse() and scanned via security_scan.scan_text() before the
package is written.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixture_safety  # noqa: E402
import security_scan  # noqa: E402
from lib.capability_manifest import CapabilityManifest, ManifestError, load_manifest  # noqa: E402
from lib.capture_policies import CAPTURE_POLICIES  # noqa: E402
from lib.code_templates import (  # noqa: E402
    AnchorError,
    GeneratedField,
    append_at_end_of_file,
    append_to_method_body,
    find_capability_frozenset_literal,
    insert_client_model_import,
    insert_into_capability_frozenset,
    insert_new_capability_enum_member,
    insert_read_import,
    insert_register_all_dispatch,
    openapi_type_to_python,
    render_client_method,
    render_client_test_functions,
    render_live_test_file,
    render_model_file,
    render_register_method,
    render_register_method_extension,
    render_tool_file,
)

from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD, Capability
from pfsense_mcp.endpoints import Endpoints

REPO_ROOT = Path(__file__).resolve().parent.parent
PROPOSALS_ROOT = REPO_ROOT / ".capability_proposals"
DISCOVERY_SCHEMA_VERSION_SUPPORTED = 1
CAPABILITIES_PATH = REPO_ROOT / "src" / "pfsense_mcp" / "capabilities.py"
PROFILES_PATH = REPO_ROOT / "src" / "pfsense_mcp" / "profiles.py"
REGISTRY_PATH = REPO_ROOT / "src" / "pfsense_mcp" / "tools" / "registry.py"
CLIENT_PATH = REPO_ROOT / "src" / "pfsense_mcp" / "pfsense_client.py"
TEST_CLIENT_PATH = REPO_ROOT / "tests" / "test_pfsense_client.py"
MODELS_DIR = REPO_ROOT / "src" / "pfsense_mcp" / "models"
TOOLS_READ_DIR = REPO_ROOT / "src" / "pfsense_mcp" / "tools" / "read"

_MUTATING_VERBS = ("create", "update", "delete", "set", "add", "remove", "write", "post", "put", "patch")


class ScaffoldRefusal(Exception):
    def __init__(self, category: str, reason: str) -> None:
        self.category = category
        self.reason = reason
        super().__init__(f"[{category}] {reason}")


def _to_snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _repo_relative_write_path(root: Path, *parts: str) -> Path:
    """Resolves root/parts and asserts the result remains beneath the
    resolved root — refuses on absolute-path/traversal/symlink-escape
    attempts, never silently clamps."""
    candidate = root.joinpath(*parts).resolve()
    resolved_root = root.resolve()
    try:
        candidate.relative_to(resolved_root)
    except ValueError:
        raise ScaffoldRefusal("path-escape", f"{candidate} is not beneath {resolved_root}") from None
    return candidate


def load_discovery_snapshot(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ScaffoldRefusal("discovery-snapshot-not-found", f"discovery snapshot not found: {path}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScaffoldRefusal("invalid-discovery-snapshot", f"discovery snapshot is not valid JSON: {exc}") from None
    if doc.get("schema_version") != DISCOVERY_SCHEMA_VERSION_SUPPORTED:
        raise ScaffoldRefusal(
            "unsupported-discovery-schema-version",
            f"discovery snapshot schema_version {doc.get('schema_version')!r} is not supported "
            f"(expected {DISCOVERY_SCHEMA_VERSION_SUPPORTED})",
        )
    return doc


def find_discovery_endpoint(discovery: dict[str, Any], endpoint) -> dict[str, Any]:
    expected_path = f"/api/{endpoint.min_api_version.value}{endpoint.path_suffix}"
    matches = [e for e in discovery.get("endpoints", []) if e.get("path") == expected_path]
    if not matches:
        raise ScaffoldRefusal(
            "discovery-endpoint-path-mismatch",
            f"no discovery entry found for path {expected_path!r}",
        )
    return matches[0]


def resolve_endpoint(endpoint_symbol: str):
    endpoint = getattr(Endpoints, endpoint_symbol, None)
    from pfsense_mcp.endpoints import EndpointInfo

    if not isinstance(endpoint, EndpointInfo):
        raise ScaffoldRefusal("unknown-endpoint", f"{endpoint_symbol!r} is not a registered Endpoints attribute")
    if not endpoint.verified:
        raise ScaffoldRefusal("endpoint-not-verified", f"Endpoints.{endpoint_symbol} is not verified=True")
    return endpoint


def resolve_capture_policy(endpoint_symbol: str, response_shape: str):
    policy = CAPTURE_POLICIES.get(endpoint_symbol)
    if policy is None:
        raise ScaffoldRefusal("no-capture-policy", f"Endpoints.{endpoint_symbol} has no entry in CAPTURE_POLICIES")
    if policy.result_shape != response_shape:
        raise ScaffoldRefusal(
            "response-shape-mismatch-policy",
            f"manifest declares response_shape={response_shape!r} but the capture policy "
            f"declares {policy.result_shape!r}",
        )
    return policy


def load_approved_fixture(fixture_path_str: str) -> tuple[Path, str, dict[str, Any]]:
    if not fixture_path_str.startswith("tests/fixtures/"):
        raise ScaffoldRefusal("fixture-outside-tests-fixtures", "approved_fixture_path must be under tests/fixtures/")
    fixture_path = REPO_ROOT / fixture_path_str
    if not fixture_path.is_file():
        raise ScaffoldRefusal("fixture-not-found", f"approved fixture not found: {fixture_path_str}")

    import subprocess

    ignore_check = subprocess.run(["git", "check-ignore", "-q", str(fixture_path)], cwd=REPO_ROOT, capture_output=True)
    if ignore_check.returncode == 0:
        raise ScaffoldRefusal("fixture-ignored-by-git", f"{fixture_path_str} is ignored by .gitignore")

    text = fixture_path.read_text(encoding="utf-8")
    fs_failures, _fs_advisories = fixture_safety.check_fixture_text(fixture_path.name, text)
    if fs_failures:
        raise ScaffoldRefusal("fixture-fails-fixture-safety", "; ".join(fs_failures))

    scan_findings = security_scan.scan_text(fixture_path, text)
    if scan_findings:
        raise ScaffoldRefusal("fixture-fails-security-scan", "; ".join(scan_findings))

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ScaffoldRefusal("fixture-invalid-json", f"approved fixture is not valid JSON: {exc}") from None

    return fixture_path, text, data


_TYPE_COMPAT = {
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
}


def _value_matches_schema_type(value: Any, type_str: str | None) -> bool:
    if value is None or type_str is None:
        return True
    if type_str in _TYPE_COMPAT:
        return _TYPE_COMPAT[type_str](value)
    if type_str.startswith("array<"):
        return isinstance(value, list)
    return True


def cross_check_fields(
    discovery_endpoint: dict[str, Any], fixture_data: dict[str, Any], response_shape: str
) -> list[GeneratedField]:
    schema_fields = {f["name"]: f for f in discovery_endpoint.get("response_fields", [])}

    data = fixture_data.get("data")
    if response_shape == "list":
        if not isinstance(data, list) or not data:
            raise ScaffoldRefusal(
                "fixture-shape-mismatch", "manifest declares 'list' but fixture 'data' is empty or not a list"
            )
        sample = data[0]
    else:
        if not isinstance(data, dict):
            raise ScaffoldRefusal(
                "fixture-shape-mismatch", "manifest declares 'object' but fixture 'data' is not an object"
            )
        sample = data
    if not isinstance(sample, dict):
        raise ScaffoldRefusal("fixture-shape-mismatch", "fixture sample item is not an object")

    fields: list[GeneratedField] = []
    for name, value in sample.items():
        schema_field = schema_fields.get(name)
        if schema_field is None:
            raise ScaffoldRefusal("field-missing-from-schema", f"field name: {name}")
        if not _value_matches_schema_type(value, schema_field.get("type")):
            raise ScaffoldRefusal("field-type-mismatch", f"field name: {name}")
        py_type = openapi_type_to_python(schema_field.get("type"))
        nullable = bool(schema_field.get("nullable")) or value is None
        fields.append(GeneratedField(name=name, python_type=py_type, nullable=nullable))

    return sorted(fields, key=lambda f: f.name)


def apply_field_overrides(fields: list[GeneratedField], manifest: CapabilityManifest) -> list[GeneratedField]:
    result = []
    for f in fields:
        override = manifest.field_overrides.get(f.name)
        if override is not None:
            result.append(GeneratedField(name=f.name, python_type=override.type, nullable=override.nullable))
        else:
            result.append(f)
    return result


def check_redaction_consistency(manifest: CapabilityManifest, discovery_endpoint: dict[str, Any], policy) -> list[str]:
    schema_names = {f["name"] for f in discovery_endpoint.get("response_fields", [])}
    warnings: list[str] = []

    for name in manifest.identifying_fields:
        if name not in schema_names:
            raise ScaffoldRefusal("identifying-field-not-in-schema", f"field name: {name}")
        if name not in policy.identifying_fields:
            raise ScaffoldRefusal("identifying-field-not-in-capture-policy", f"field name: {name}")

    extra = set(policy.identifying_fields) - set(manifest.identifying_fields)
    if extra:
        warnings.append(
            f"CapturePolicy redacts additional field(s) not marked identifying in the model: {sorted(extra)}. "
            "Fixture sanitization may legitimately be stricter than MCP output redaction — confirm this is intended."
        )
    return warnings


def detect_capability_state(capability_name: str) -> str:
    member = getattr(Capability, capability_name, None)
    if member is None:
        return "new"
    if member not in SUPPORTED_CAPABILITIES_THIS_BUILD:
        return "activate"
    return "extend"


def check_collisions(manifest: CapabilityManifest, tool_module_name: str, model_module_name: str) -> None:
    combined_src = ""
    for p in list(MODELS_DIR.glob("*.py")) + list(TOOLS_READ_DIR.glob("*.py")) + [CLIENT_PATH, REGISTRY_PATH]:
        combined_src += p.read_text(encoding="utf-8")

    if f"class {manifest.model_class_name}" in combined_src:
        raise ScaffoldRefusal("model-class-name-collision", manifest.model_class_name)
    if f"def {manifest.client_method_name}(" in combined_src:
        raise ScaffoldRefusal("client-method-name-collision", manifest.client_method_name)
    if f"def {manifest.mcp_tool_name}(" in combined_src:
        raise ScaffoldRefusal("mcp-tool-name-collision", manifest.mcp_tool_name)
    if (MODELS_DIR / f"{model_module_name}.py").exists():
        raise ScaffoldRefusal("model-module-collision", model_module_name)
    if (TOOLS_READ_DIR / f"{tool_module_name}.py").exists():
        raise ScaffoldRefusal("tool-module-collision", tool_module_name)


def check_tool_name_shape(mcp_tool_name: str) -> None:
    if not mcp_tool_name.startswith("pfsense_get_"):
        raise ScaffoldRefusal("tool-name-not-get-shaped", mcp_tool_name)
    lowered = mcp_tool_name.lower()
    for verb in _MUTATING_VERBS:
        if verb in lowered.replace("pfsense_get_", ""):
            raise ScaffoldRefusal("tool-name-contains-mutating-verb", f"{mcp_tool_name} contains {verb!r}")


def resolve_bounded_param(policy) -> tuple[str | None, int | None, int | None, int | None]:
    """Returns (name, default, minimum, maximum) or (None, None, None, None).
    v1 supports at most one bounded parameter per endpoint — the only
    real precedent (get_firewall_states's `limit`) has exactly one."""
    if not policy.allowed_params:
        return None, None, None, None
    if len(policy.allowed_params) > 1:
        raise ScaffoldRefusal(
            "bounded-param-count-unsupported",
            f"this version supports at most one bounded parameter; policy declares {len(policy.allowed_params)}",
        )
    ((name, bound),) = policy.allowed_params.items()
    default = min(100, bound.maximum) if bound.minimum <= 100 <= bound.maximum else bound.minimum
    return name, default, bound.minimum, bound.maximum


def assert_ast_parses(filename: str, source: str) -> None:
    try:
        ast.parse(source)
    except SyntaxError as exc:
        raise ScaffoldRefusal("generated-python-does-not-parse", f"{filename}: {exc}") from None


def assert_security_clean(filename: str, source: str) -> None:
    findings = security_scan.scan_text(Path(filename), source)
    if findings:
        raise ScaffoldRefusal("generated-content-fails-security-scan", f"{filename}: {'; '.join(findings)}")


def unified_diff_text(original: str, proposed: str, path_label: str) -> str:
    import difflib

    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        proposed.splitlines(keepends=True),
        fromfile=f"a/{path_label}",
        tofile=f"b/{path_label}",
    )
    return "".join(diff)


def build_proposal(manifest: CapabilityManifest, discovery_path: Path, output_name: str) -> Path:
    endpoint = resolve_endpoint(manifest.endpoint_symbol)
    policy = resolve_capture_policy(manifest.endpoint_symbol, manifest.response_shape)
    fixture_path, fixture_text, fixture_data = load_approved_fixture(manifest.approved_fixture_path)
    discovery = load_discovery_snapshot(discovery_path)
    discovery_endpoint = find_discovery_endpoint(discovery, endpoint)

    fields = cross_check_fields(discovery_endpoint, fixture_data, manifest.response_shape)
    fields = apply_field_overrides(fields, manifest)
    warnings = check_redaction_consistency(manifest, discovery_endpoint, policy)

    tool_module_name = manifest.mcp_tool_name.removeprefix("pfsense_get_")
    model_module_name = _to_snake(manifest.model_class_name)
    check_collisions(manifest, tool_module_name, model_module_name)
    check_tool_name_shape(manifest.mcp_tool_name)

    if "EngineerProfile" in manifest.profiles:
        raise ScaffoldRefusal("profile-not-supported", "EngineerProfile has no capability set to extend in this build")

    bounded_name, bounded_default, bounded_min, bounded_max = resolve_bounded_param(policy)
    min_const = max_const = None
    base_const_name = manifest.client_method_name.removeprefix("get_").upper()
    if bounded_name:
        min_const = f"{base_const_name}_MIN_{bounded_name.upper()}"
        max_const = f"{base_const_name}_MAX_{bounded_name.upper()}"

    state = detect_capability_state(manifest.capability_name)

    if "/" in output_name or ".." in output_name or output_name.startswith("."):
        raise ScaffoldRefusal("invalid-output-name", output_name)
    proposal_dir = _repo_relative_write_path(PROPOSALS_ROOT, output_name)
    if proposal_dir.exists():
        raise ScaffoldRefusal("proposal-destination-exists", str(proposal_dir))

    has_identifying = bool(manifest.identifying_fields)

    # --- generate new-file content -----------------------------------
    model_src = render_model_file(
        manifest.model_class_name, fields, manifest.identifying_fields, manifest.response_shape
    )
    assert_ast_parses(f"models/{model_module_name}.py", model_src)
    assert_security_clean(f"models/{model_module_name}.py", model_src)

    tool_src = render_tool_file(
        tool_module_name=tool_module_name,
        mcp_tool_name=manifest.mcp_tool_name,
        client_method_name=manifest.client_method_name,
        model_class_name=manifest.model_class_name,
        model_module_name=model_module_name,
        has_identifying_fields=has_identifying,
        response_shape=manifest.response_shape,
        tool_summary=manifest.tool_summary,
        bounded_param_name=bounded_name,
        bounded_param_default=bounded_default,
    )
    assert_ast_parses(f"tools/read/{tool_module_name}.py", tool_src)
    assert_security_clean(f"tools/read/{tool_module_name}.py", tool_src)

    live_test_src = render_live_test_file(
        capability_name=manifest.capability_name,
        client_method_name=manifest.client_method_name,
        model_class_name=manifest.model_class_name,
        model_module_name=model_module_name,
        identifying_fields=manifest.identifying_fields,
        response_shape=manifest.response_shape,
        bounded_param_name=bounded_name,
    )
    assert_ast_parses(f"tests/test_live_{tool_module_name}.py", live_test_src)
    assert_security_clean(f"tests/test_live_{tool_module_name}.py", live_test_src)

    # --- generate diffs against existing tracked files ----------------
    client_method_src = render_client_method(
        client_method_name=manifest.client_method_name,
        model_class_name=manifest.model_class_name,
        endpoint_symbol=manifest.endpoint_symbol,
        endpoint_path=endpoint.path_suffix,
        has_identifying_fields=has_identifying,
        response_shape=manifest.response_shape,
        bounded_param_name=bounded_name,
        bounded_param_default=bounded_default or 0,
        bounded_param_min_const=min_const,
        bounded_param_max_const=max_const,
    )
    client_original = CLIENT_PATH.read_text(encoding="utf-8")
    client_proposed = insert_client_model_import(client_original, model_module_name, manifest.model_class_name)
    if bounded_name:
        const_block = f"{min_const} = {bounded_min}\n{max_const} = {bounded_max}\n"
        client_proposed = insert_after_anchor_constants(client_proposed, const_block)
    client_proposed = append_at_end_of_file(client_proposed, "\n" + client_method_src)
    assert_ast_parses("pfsense_client.py (proposed)", client_proposed)
    assert_security_clean("pfsense_client.py (proposed)", client_proposed)

    registry_original = REGISTRY_PATH.read_text(encoding="utf-8")
    registry_proposed = insert_read_import(registry_original, tool_module_name)
    if state in ("new", "activate"):
        registry_proposed = insert_register_all_dispatch(registry_proposed, manifest.capability_name)
        method_src = render_register_method(manifest.capability_name, [(manifest.mcp_tool_name, tool_module_name)])
        registry_proposed = append_at_end_of_file(registry_proposed, method_src)
    else:
        addition = render_register_method_extension(manifest.mcp_tool_name, tool_module_name)
        registry_proposed = append_to_method_body(
            registry_proposed, f"_register_{manifest.capability_name.lower()}", addition
        )
    assert_ast_parses("registry.py (proposed)", registry_proposed)
    assert_security_clean("registry.py (proposed)", registry_proposed)

    capabilities_original = capabilities_proposed = CAPABILITIES_PATH.read_text(encoding="utf-8")
    profiles_original = profiles_proposed = PROFILES_PATH.read_text(encoding="utf-8")
    if state == "new":
        capabilities_proposed = insert_new_capability_enum_member(capabilities_proposed, manifest.capability_name)
        capabilities_anchor = find_capability_frozenset_literal(capabilities_proposed)
        capabilities_proposed = insert_into_capability_frozenset(
            capabilities_proposed, capabilities_anchor, manifest.capability_name
        )
        profiles_anchor = find_capability_frozenset_literal(profiles_proposed)
        profiles_proposed = insert_into_capability_frozenset(
            profiles_proposed, profiles_anchor, manifest.capability_name
        )
    elif state == "activate":
        capabilities_anchor = find_capability_frozenset_literal(capabilities_proposed)
        capabilities_proposed = insert_into_capability_frozenset(
            capabilities_proposed, capabilities_anchor, manifest.capability_name
        )
        profiles_anchor = find_capability_frozenset_literal(profiles_proposed)
        profiles_proposed = insert_into_capability_frozenset(
            profiles_proposed, profiles_anchor, manifest.capability_name
        )
    if state in ("new", "activate"):
        assert_ast_parses("capabilities.py (proposed)", capabilities_proposed)
        assert_security_clean("capabilities.py (proposed)", capabilities_proposed)
        assert_ast_parses("profiles.py (proposed)", profiles_proposed)
        assert_security_clean("profiles.py (proposed)", profiles_proposed)

    test_client_original = TEST_CLIENT_PATH.read_text(encoding="utf-8")
    test_client_addition = render_client_test_functions(
        client_method_name=manifest.client_method_name,
        model_class_name=manifest.model_class_name,
        fields=fields,
        identifying_fields=manifest.identifying_fields,
        response_shape=manifest.response_shape,
        endpoint_path=endpoint.path_suffix,
    )
    test_client_proposed = append_at_end_of_file(test_client_original, test_client_addition)
    assert_ast_parses("test_pfsense_client.py (proposed)", test_client_proposed)
    assert_security_clean("test_pfsense_client.py (proposed)", test_client_proposed)

    test_registry_src = render_registry_test_function(manifest, tool_module_name)
    assert_ast_parses("test_tool_registry.py addition", "import x\n" + test_registry_src)
    assert_security_clean("test_tool_registry.py addition", test_registry_src)

    test_profiles_src = ""
    if state == "new":
        test_profiles_src = (
            f"\n\ndef test_auditor_profile_has_{manifest.capability_name.lower()}():\n"
            f"    assert Capability.{manifest.capability_name} in AuditorProfile.capabilities\n"
        )
        assert_ast_parses("test_profiles.py addition", "import x\n" + test_profiles_src)
        assert_security_clean("test_profiles.py addition", test_profiles_src)

    # --- write the package --------------------------------------------
    _write_package(
        proposal_dir=proposal_dir,
        manifest=manifest,
        state=state,
        warnings=warnings,
        model_module_name=model_module_name,
        tool_module_name=tool_module_name,
        model_src=model_src,
        tool_src=tool_src,
        live_test_src=live_test_src,
        client_original=client_original,
        client_proposed=client_proposed,
        registry_original=registry_original,
        registry_proposed=registry_proposed,
        capabilities_original=capabilities_original,
        capabilities_proposed=capabilities_proposed,
        profiles_original=profiles_original,
        profiles_proposed=profiles_proposed,
        test_client_original=test_client_original,
        test_client_proposed=test_client_proposed,
        test_registry_src=test_registry_src,
        test_profiles_src=test_profiles_src,
        discovery_endpoint=discovery_endpoint,
        fixture_path=fixture_path,
        fixture_text=fixture_text,
        fields=fields,
    )
    return proposal_dir


def insert_after_anchor_constants(source: str, const_block: str) -> str:
    from lib.code_templates import replace_anchor

    return replace_anchor(
        source, "class PfSenseClient:", f"{const_block}\n\nclass PfSenseClient:", anchor_name="class PfSenseClient:"
    )


def render_registry_test_function(manifest: CapabilityManifest, tool_module_name: str) -> str:
    return (
        f"\n\ndef test_{tool_module_name}_is_registered_when_capability_active():\n"
        f"    # GENERATED PROPOSAL — review before use.\n"
        f"    # TODO(human): build a MockTransport-backed registry with\n"
        f"    # Capability.{manifest.capability_name} active and assert\n"
        f'    # "{manifest.mcp_tool_name}" appears in the registered tool names.\n'
        f"    pass\n"
    )


def _write_package(
    *,
    proposal_dir: Path,
    manifest: CapabilityManifest,
    state: str,
    warnings: list[str],
    model_module_name: str,
    tool_module_name: str,
    model_src: str,
    tool_src: str,
    live_test_src: str,
    client_original: str,
    client_proposed: str,
    registry_original: str,
    registry_proposed: str,
    capabilities_original: str,
    capabilities_proposed: str,
    profiles_original: str,
    profiles_proposed: str,
    test_client_original: str,
    test_client_proposed: str,
    test_registry_src: str,
    test_profiles_src: str,
    discovery_endpoint: dict[str, Any],
    fixture_path: Path,
    fixture_text: str,
    fields: list[GeneratedField],
) -> None:
    new_files_dir = proposal_dir / "new_files"
    diffs_dir = proposal_dir / "diffs"
    full_files_dir = proposal_dir / "proposed_full_files"
    provenance_dir = proposal_dir / "provenance"
    # proposal_dir was already validated (via _repo_relative_write_path)
    # by the caller; these are fixed, hardcoded subdirectory names with
    # no further untrusted input, so no re-validation is needed here.
    for d in (
        new_files_dir / "models",
        new_files_dir / "tools_read",
        new_files_dir / "tests",
        diffs_dir,
        full_files_dir,
        provenance_dir,
    ):
        d.mkdir(parents=True, exist_ok=True)

    (new_files_dir / "models" / f"{model_module_name}.py").write_text(model_src, encoding="utf-8")
    (new_files_dir / "tools_read" / f"{tool_module_name}.py").write_text(tool_src, encoding="utf-8")
    (new_files_dir / "tests" / f"test_live_{tool_module_name}.py").write_text(live_test_src, encoding="utf-8")

    diff_specs = [
        (
            "pfsense_client.patch",
            "src/pfsense_mcp/pfsense_client.py",
            client_original,
            client_proposed,
            "pfsense_client.py",
        ),
        ("registry.patch", "src/pfsense_mcp/tools/registry.py", registry_original, registry_proposed, "registry.py"),
        (
            "test_pfsense_client.patch",
            "tests/test_pfsense_client.py",
            test_client_original,
            test_client_proposed,
            "test_pfsense_client.py",
        ),
    ]
    if state in ("new", "activate"):
        diff_specs.append(
            (
                "capabilities.patch",
                "src/pfsense_mcp/capabilities.py",
                capabilities_original,
                capabilities_proposed,
                "capabilities.py",
            )
        )
        diff_specs.append(
            ("profiles.patch", "src/pfsense_mcp/profiles.py", profiles_original, profiles_proposed, "profiles.py")
        )

    for patch_name, label, original, proposed, full_name in diff_specs:
        (diffs_dir / patch_name).write_text(unified_diff_text(original, proposed, label), encoding="utf-8")
        (full_files_dir / full_name).write_text(proposed, encoding="utf-8")

    # test_tool_registry.py and (optionally) test_profiles.py get their
    # additions shipped as small standalone snippet files rather than a
    # full diff against the real file, since intelligently extending
    # test_tool_registry.py's shared _client() fixture helper is
    # out of scope for this first version (see README.md note).
    (diffs_dir / "test_tool_registry.snippet.py").write_text(test_registry_src, encoding="utf-8")
    if test_profiles_src:
        (diffs_dir / "test_profiles.snippet.py").write_text(test_profiles_src, encoding="utf-8")

    (proposal_dir / "MANIFEST.json").write_text(
        json.dumps(
            {
                "manifest_schema_version": manifest.manifest_schema_version,
                "capability_name": manifest.capability_name,
                "profiles": list(manifest.profiles),
                "endpoint_symbol": manifest.endpoint_symbol,
                "model_class_name": manifest.model_class_name,
                "client_method_name": manifest.client_method_name,
                "mcp_tool_name": manifest.mcp_tool_name,
                "tool_summary": manifest.tool_summary,
                "identifying_fields": list(manifest.identifying_fields),
                "response_shape": manifest.response_shape,
                "approved_fixture_path": manifest.approved_fixture_path,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    digest = hashlib.sha256(fixture_text.encode("utf-8")).hexdigest()
    (provenance_dir / "discovery_snapshot.json").write_text(
        json.dumps(discovery_endpoint, indent=2) + "\n", encoding="utf-8"
    )
    (provenance_dir / "fixture_digest.txt").write_text(
        f"fixture: {manifest.approved_fixture_path}\nsha256: {digest}\n", encoding="utf-8"
    )
    (provenance_dir / "generated_field_schema.json").write_text(
        json.dumps([{"name": f.name, "type": f.python_type, "nullable": f.nullable} for f in fields], indent=2) + "\n",
        encoding="utf-8",
    )

    checklist = _render_checklist(manifest, state, warnings, fields)
    (proposal_dir / "CHECKLIST.md").write_text(checklist, encoding="utf-8")
    (proposal_dir / "README.md").write_text(_render_readme(manifest, state), encoding="utf-8")


def _render_checklist(
    manifest: CapabilityManifest, state: str, warnings: list[str], fields: list[GeneratedField]
) -> str:
    lines = [f"# Review checklist: {manifest.capability_name}", ""]
    lines.append(f"Capability state detected: **{state}**")
    lines.append("")
    lines.append("## Generated field list (review required — derived from discovery + fixture, not final)")
    for f in fields:
        marker = " (IDENTIFYING)" if f.name in manifest.identifying_fields else ""
        lines.append(f"- `{f.name}`: `{f.annotation}`{marker}")
    lines.append("")
    if warnings:
        lines.append("## Warnings requiring an explicit human decision")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")
    lines.append("## Required manual steps")
    lines.append("- [ ] Review generated_field_schema.json and every field's type/nullability")
    lines.append("- [ ] Review diffs/*.patch and proposed_full_files/* before applying manually")
    lines.append("- [ ] Copy new_files/* into their target locations under src/pfsense_mcp/ and tests/")
    lines.append("- [ ] Fill in the TODO(human) markers in the generated test skeletons")
    lines.append("- [ ] Run `make quick` and `make validate` after applying")
    lines.append("- [ ] Never set anything verified=True automatically — endpoint was already verified")
    lines.append("- [ ] This tool never stages or commits anything — do that yourself once satisfied")
    return "\n".join(lines) + "\n"


def _render_readme(manifest: CapabilityManifest, state: str) -> str:
    return (
        f"# Scaffold proposal: {manifest.capability_name}\n\n"
        f"Generated by scripts/scaffold_capability.py. Capability state: {state}.\n\n"
        "This is a PROPOSAL. Nothing here has been applied, staged, or committed.\n"
        "See CHECKLIST.md for required review steps.\n"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scaffold_capability.py",
        description="Generate a reviewable capability proposal from a manifest. Never modifies tracked files.",
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--discovery-snapshot", type=Path, required=True)
    parser.add_argument("--output-name", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
        output_name = args.output_name or manifest.capability_name.lower()
        proposal_dir = build_proposal(manifest, args.discovery_snapshot, output_name)
    except (ManifestError, ScaffoldRefusal, AnchorError) as exc:
        print(f"scaffold_capability: REFUSED [{exc.category}] {exc.reason}", file=sys.stderr)
        return 1

    print(f"scaffold_capability: OK -> {proposal_dir}")
    print("  This is a PROPOSAL, not applied code. See CHECKLIST.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
