"""Unit tests for scripts/scaffold_capability.py.

Uses a synthetic temporary repository (tmp_path) for every tracked
file scaffold_capability.py reads or would-diff against — never the
real src/pfsense_mcp/ or tests/ trees. The real, read-only Endpoints
and CAPTURE_POLICIES registries are used as-is (safe: they are only
ever read, never written, by this tool)."""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
from enum import Enum, auto
from pathlib import Path

import pytest
import scaffold_capability as sc

REAL_REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_FIXTURE = REAL_REPO_ROOT / "tests" / "fixtures" / "firewall_states_size_response.json"


class _FakeCapability(Enum):
    """Mirrors _CAPABILITIES_PY below exactly. detect_capability_state()
    reads the live Capability enum / SUPPORTED_CAPABILITIES_THIS_BUILD
    (correctly, for real usage against the real repo) rather than
    parsing the fake repo's capabilities.py text — so these tests must
    monkeypatch those two names too, not just file paths, or a fake-repo
    capability-state case can silently start reading real repo state."""

    SYSTEM_READ = auto()
    FIREWALL_READ = auto()
    ALIAS_READ = auto()
    FIREWALL_WRITE = auto()


_FAKE_SUPPORTED_CAPABILITIES_THIS_BUILD = frozenset({_FakeCapability.SYSTEM_READ, _FakeCapability.FIREWALL_READ})

_CAPABILITIES_PY = '''"""Capability model."""

from __future__ import annotations

from enum import Enum, auto


class Capability(Enum):
    SYSTEM_READ = auto()
    FIREWALL_READ = auto()
    ALIAS_READ = auto()
    # Not usable until a separate, explicitly authorized implementation phase:
    FIREWALL_WRITE = auto()


SUPPORTED_CAPABILITIES_THIS_BUILD: frozenset[Capability] = frozenset(
    {Capability.SYSTEM_READ, Capability.FIREWALL_READ}
)
'''

_PROFILES_PY = '''"""Profiles."""

from __future__ import annotations

from dataclasses import dataclass

from .capabilities import Capability


@dataclass(frozen=True)
class Profile:
    name: str
    capabilities: frozenset[Capability]


AuditorProfile = Profile(
    name="auditor",
    capabilities=frozenset(
        {Capability.SYSTEM_READ, Capability.FIREWALL_READ}
    ),
)

EngineerProfile = Profile(name="engineer", capabilities=frozenset())
'''

_REGISTRY_PY = '''"""ToolRegistry."""

from __future__ import annotations

from ..capabilities import Capability
from ..pfsense_client import PfSenseClient
from .audit import audit_logged
from .read import (
    firewall_states_size,
    system_status,
)


class ToolRegistry:
    def __init__(self, mcp, client, identity, capabilities):
        self._mcp = mcp
        self._client = client
        self._identity = identity
        self._capabilities = capabilities

    def register_all(self) -> None:
        if Capability.SYSTEM_READ in self._capabilities:
            self._register_system_read()
        if Capability.FIREWALL_READ in self._capabilities:
            self._register_firewall_read()

    def _register_system_read(self) -> None:
        fn = system_status.build(self._client)
        wrapped = audit_logged("pfsense_get_system_status", self._identity)(fn)
        self._mcp.tool()(wrapped)

    def _register_firewall_read(self) -> None:
        fn = firewall_states_size.build(self._client)
        wrapped = audit_logged("pfsense_get_firewall_states_size", self._identity)(fn)
        self._mcp.tool()(wrapped)
'''

_CLIENT_PY = '''"""PfSenseClient."""

from __future__ import annotations

from pydantic import ValidationError

from .endpoints import Endpoints
from .errors import PfSenseRequestValidationError, PfSenseResponseShapeError
from .models.firewall_states_size import FirewallStatesSize
from .rest_api_client import RestApiClient


class PfSenseClient:
    def __init__(self, rest_client: RestApiClient) -> None:
        self._rest = rest_client

    def get_firewall_states_size(self) -> FirewallStatesSize:
        raw = self._rest.get(Endpoints.FIREWALL_STATES_SIZE)
        return FirewallStatesSize.from_api(raw["data"])
'''

_TEST_CLIENT_PY = '''"""Tests."""

def test_placeholder():
    assert True
'''


def _make_fake_repo(tmp_path: Path) -> Path:
    (tmp_path / "src" / "pfsense_mcp" / "models").mkdir(parents=True)
    (tmp_path / "src" / "pfsense_mcp" / "tools" / "read").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)

    (tmp_path / "src" / "pfsense_mcp" / "capabilities.py").write_text(_CAPABILITIES_PY)
    (tmp_path / "src" / "pfsense_mcp" / "profiles.py").write_text(_PROFILES_PY)
    (tmp_path / "src" / "pfsense_mcp" / "tools" / "registry.py").write_text(_REGISTRY_PY)
    (tmp_path / "src" / "pfsense_mcp" / "pfsense_client.py").write_text(_CLIENT_PY)
    (tmp_path / "tests" / "test_pfsense_client.py").write_text(_TEST_CLIENT_PY)
    shutil.copy(REAL_FIXTURE, tmp_path / "tests" / "fixtures" / "firewall_states_size_response.json")

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    return tmp_path


def _patch_paths(monkeypatch, fake_repo: Path):
    monkeypatch.setattr(sc, "REPO_ROOT", fake_repo)
    monkeypatch.setattr(sc, "PROPOSALS_ROOT", fake_repo / ".capability_proposals")
    monkeypatch.setattr(sc, "CAPABILITIES_PATH", fake_repo / "src" / "pfsense_mcp" / "capabilities.py")
    monkeypatch.setattr(sc, "PROFILES_PATH", fake_repo / "src" / "pfsense_mcp" / "profiles.py")
    monkeypatch.setattr(sc, "REGISTRY_PATH", fake_repo / "src" / "pfsense_mcp" / "tools" / "registry.py")
    monkeypatch.setattr(sc, "CLIENT_PATH", fake_repo / "src" / "pfsense_mcp" / "pfsense_client.py")
    monkeypatch.setattr(sc, "TEST_CLIENT_PATH", fake_repo / "tests" / "test_pfsense_client.py")
    monkeypatch.setattr(sc, "MODELS_DIR", fake_repo / "src" / "pfsense_mcp" / "models")
    monkeypatch.setattr(sc, "TOOLS_READ_DIR", fake_repo / "src" / "pfsense_mcp" / "tools" / "read")
    # detect_capability_state() reads these two names directly (not the
    # fake capabilities.py file text), so they must be faked too — see
    # _FakeCapability's docstring above.
    monkeypatch.setattr(sc, "Capability", _FakeCapability)
    monkeypatch.setattr(sc, "SUPPORTED_CAPABILITIES_THIS_BUILD", _FAKE_SUPPORTED_CAPABILITIES_THIS_BUILD)


def _discovery_snapshot(tmp_path) -> Path:
    doc = {
        "schema_version": 1,
        "generated_at": "2026-01-01T00:00:00+00:00",
        "endpoints": [
            {
                "path": "/api/v2/firewall/states/size",
                "method": "get",
                "tags": ["FIREWALL"],
                "summary": "s",
                "description": "d",
                "sibling_methods": ["get"],
                "mutating_methods_exist": False,
                "query_parameters": [],
                "response_fields": [
                    {
                        "name": "maximumstates",
                        "type": "integer",
                        "nullable": True,
                        "enum": None,
                        "format": None,
                        "required": False,
                    },
                    {
                        "name": "defaultmaximumstates",
                        "type": "integer",
                        "nullable": False,
                        "enum": None,
                        "format": None,
                        "required": False,
                    },
                    {
                        "name": "currentstates",
                        "type": "integer",
                        "nullable": False,
                        "enum": None,
                        "format": None,
                        "required": False,
                    },
                ],
            }
        ],
    }
    path = tmp_path / "discovery.json"
    path.write_text(json.dumps(doc))
    return path


def _manifest(tmp_path, **overrides) -> Path:
    data = {
        "manifest_schema_version": 1,
        "capability_name": "FIREWALL_READ",
        "profiles": ["AuditorProfile"],
        "endpoint_symbol": "FIREWALL_STATES_SIZE",
        "model_class_name": "FirewallStatesSizeDemo",
        "client_method_name": "get_firewall_states_size_demo",
        "mcp_tool_name": "pfsense_get_firewall_states_size_demo",
        "tool_summary": "Demo. Read-only.",
        "identifying_fields": [],
        "response_shape": "object",
        "approved_fixture_path": "tests/fixtures/firewall_states_size_response.json",
    }
    data.update(overrides)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data))
    return path


def _snapshot_repo_files(fake_repo: Path) -> set[Path]:
    return {
        p
        for p in fake_repo.rglob("*")
        if p.is_file() and ".git" not in p.parts and ".capability_proposals" not in p.parts
    }


# --- capability-state cases, using the synthetic repo ------------------


def test_extend_already_active_capability(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    before = _snapshot_repo_files(fake_repo)

    manifest = _manifest(tmp_path, capability_name="FIREWALL_READ")
    discovery = _discovery_snapshot(tmp_path)

    proposal_dir = sc.build_proposal(sc.load_manifest(manifest), discovery, "demo_extend")

    assert (proposal_dir / "diffs" / "registry.patch").is_file()
    assert not (proposal_dir / "diffs" / "capabilities.patch").exists()
    assert not (proposal_dir / "diffs" / "profiles.patch").exists()
    registry_patch = (proposal_dir / "diffs" / "registry.patch").read_text()
    # The enclosing method's name may fall outside the diff's small
    # context window; check the actual added lines instead.
    assert "firewall_states_size_demo_fn" in registry_patch
    assert '"pfsense_get_firewall_states_size_demo"' in registry_patch

    after = _snapshot_repo_files(fake_repo)
    assert before == after  # nothing tracked was modified


def test_activate_existing_placeholder_capability(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    before = _snapshot_repo_files(fake_repo)

    manifest = _manifest(
        tmp_path,
        capability_name="ALIAS_READ",
        model_class_name="AliasDemo",
        client_method_name="get_alias_demo",
        mcp_tool_name="pfsense_get_alias_demo",
    )
    discovery = _discovery_snapshot(tmp_path)

    proposal_dir = sc.build_proposal(sc.load_manifest(manifest), discovery, "demo_activate")

    caps_patch = (proposal_dir / "diffs" / "capabilities.patch").read_text()
    assert "ALIAS_READ = auto()" not in caps_patch  # already existed, not re-added
    assert "Capability.ALIAS_READ" in caps_patch  # frozenset extended

    # Regression check: the new model class (AliasDemo, in a brand-new
    # models/alias_demo.py module) must be imported into the proposed
    # pfsense_client.py automatically — no manual import correction
    # should ever be required after scaffolding.
    client_patch = (proposal_dir / "diffs" / "pfsense_client.patch").read_text()
    assert "from .models.alias_demo import AliasDemo" in client_patch
    client_full = (proposal_dir / "proposed_full_files" / "pfsense_client.py").read_text()
    assert "from .models.alias_demo import AliasDemo" in client_full
    ast.parse(client_full)

    assert _snapshot_repo_files(fake_repo) == before


def test_new_capability_case(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    before = _snapshot_repo_files(fake_repo)

    manifest = _manifest(
        tmp_path,
        capability_name="BRAND_NEW_READ",
        model_class_name="BrandNewDemo",
        client_method_name="get_brand_new_demo",
        mcp_tool_name="pfsense_get_brand_new_demo",
    )
    discovery = _discovery_snapshot(tmp_path)

    proposal_dir = sc.build_proposal(sc.load_manifest(manifest), discovery, "demo_new")

    caps_patch = (proposal_dir / "diffs" / "capabilities.patch").read_text()
    assert "BRAND_NEW_READ = auto()" in caps_patch
    profiles_patch = (proposal_dir / "diffs" / "profiles.patch").read_text()
    assert "Capability.BRAND_NEW_READ" in profiles_patch
    assert (proposal_dir / "diffs" / "test_profiles.snippet.py").is_file()

    for f in ("new_files/models/brand_new_demo.py", "new_files/tools_read/brand_new_demo.py"):
        ast.parse((proposal_dir / f).read_text())

    # Regression check: same as the "activate" case above — no manual
    # model-import correction should ever be required after scaffolding.
    client_patch = (proposal_dir / "diffs" / "pfsense_client.patch").read_text()
    assert "from .models.brand_new_demo import BrandNewDemo" in client_patch
    client_full = (proposal_dir / "proposed_full_files" / "pfsense_client.py").read_text()
    assert "from .models.brand_new_demo import BrandNewDemo" in client_full
    ast.parse(client_full)

    assert _snapshot_repo_files(fake_repo) == before


# --- refusal conditions -------------------------------------------------


def test_refuses_unverified_endpoint(tmp_path, monkeypatch):
    from pfsense_mcp.api_version import ApiVersion
    from pfsense_mcp.endpoints import EndpointInfo, Endpoints

    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    monkeypatch.setattr(
        Endpoints,
        "FAKE_UNVERIFIED",
        EndpointInfo(path_suffix="/fake", verified=False, min_api_version=ApiVersion.V2),
        raising=False,
    )

    manifest = _manifest(tmp_path, endpoint_symbol="FAKE_UNVERIFIED")
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "endpoint-not-verified"


def test_refuses_missing_capture_policy(tmp_path, monkeypatch):
    from pfsense_mcp.api_version import ApiVersion
    from pfsense_mcp.endpoints import EndpointInfo, Endpoints

    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    monkeypatch.setattr(
        Endpoints,
        "FAKE_VERIFIED_NO_POLICY",
        EndpointInfo(path_suffix="/fake2", verified=True, min_api_version=ApiVersion.V2),
        raising=False,
    )

    manifest = _manifest(tmp_path, endpoint_symbol="FAKE_VERIFIED_NO_POLICY")
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "no-capture-policy"


def test_refuses_response_shape_mismatch_with_policy(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    manifest = _manifest(tmp_path, response_shape="list")  # FIREWALL_STATES_SIZE policy is "object"
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "response-shape-mismatch-policy"


def test_refuses_fixture_outside_tests_fixtures(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    manifest = _manifest(tmp_path, approved_fixture_path="somewhere_else/fixture.json")
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "fixture-outside-tests-fixtures"


def test_refuses_missing_fixture(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    manifest = _manifest(tmp_path, approved_fixture_path="tests/fixtures/does_not_exist.json")
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "fixture-not-found"


def test_refuses_gitignored_fixture(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    (fake_repo / ".gitignore").write_text("tests/fixtures/ignored_fixture.json\n")
    shutil.copy(REAL_FIXTURE, fake_repo / "tests" / "fixtures" / "ignored_fixture.json")

    manifest = _manifest(tmp_path, approved_fixture_path="tests/fixtures/ignored_fixture.json")
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "fixture-ignored-by-git"


def test_refuses_fixture_failing_fixture_safety(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    bad = {
        "code": 200,
        "data": {"maximumstates": 1, "defaultmaximumstates": 1, "currentstates": 1, "leak": "192.168.1" + ".3"},
    }
    (fake_repo / "tests" / "fixtures" / "bad_fixture.json").write_text(json.dumps(bad))

    manifest = _manifest(tmp_path, approved_fixture_path="tests/fixtures/bad_fixture.json")
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "fixture-fails-fixture-safety"


def test_refuses_field_missing_from_schema(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    extra_field_fixture = {
        "code": 200,
        "data": {"maximumstates": 1, "defaultmaximumstates": 1, "currentstates": 1, "totally_undocumented_field": "x"},
    }
    (fake_repo / "tests" / "fixtures" / "extra_field.json").write_text(json.dumps(extra_field_fixture))

    manifest = _manifest(tmp_path, approved_fixture_path="tests/fixtures/extra_field.json")
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "field-missing-from-schema"


def test_refuses_field_type_mismatch(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    mismatched = {
        "code": 200,
        "data": {"maximumstates": "not-an-integer", "defaultmaximumstates": 1, "currentstates": 1},
    }
    (fake_repo / "tests" / "fixtures" / "mismatch.json").write_text(json.dumps(mismatched))

    manifest = _manifest(tmp_path, approved_fixture_path="tests/fixtures/mismatch.json")
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "field-type-mismatch"


def test_refuses_identifying_field_not_in_schema(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    manifest = _manifest(tmp_path, identifying_fields=["nonexistent_field"])
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "identifying-field-not-in-schema"


def test_refuses_identifying_field_not_in_capture_policy(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    # currentstates is in the discovery schema but FIREWALL_STATES_SIZE's
    # real capture policy has no identifying_fields at all.
    manifest = _manifest(tmp_path, identifying_fields=["currentstates"])
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "identifying-field-not-in-capture-policy"


def test_refuses_unsupported_discovery_schema_version(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    bad_discovery = tmp_path / "bad_discovery.json"
    bad_discovery.write_text(json.dumps({"schema_version": 999, "endpoints": []}))

    manifest = _manifest(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), bad_discovery, "x")
    assert excinfo.value.category == "unsupported-discovery-schema-version"


def test_refuses_discovery_path_mismatch(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    wrong_path_discovery = tmp_path / "wrong_discovery.json"
    wrong_path_discovery.write_text(
        json.dumps({"schema_version": 1, "endpoints": [{"path": "/api/v2/something/else"}]})
    )

    manifest = _manifest(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), wrong_path_discovery, "x")
    assert excinfo.value.category == "discovery-endpoint-path-mismatch"


def test_refuses_model_class_name_collision(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    (fake_repo / "src" / "pfsense_mcp" / "models" / "existing.py").write_text(
        "class FirewallStatesSizeDemo:\n    pass\n"
    )

    manifest = _manifest(tmp_path)
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "model-class-name-collision"


def test_refuses_tool_name_not_get_shaped(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    manifest = _manifest(tmp_path, mcp_tool_name="pfsense_delete_firewall_schedule")
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "tool-name-not-get-shaped"


def test_refuses_tool_name_with_mutating_verb(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    manifest = _manifest(tmp_path, mcp_tool_name="pfsense_get_and_update_firewall_schedule")
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "tool-name-contains-mutating-verb"


def test_allows_tool_name_containing_mutating_verb_as_substring_of_a_noun(tmp_path, monkeypatch):
    # Regression test: "settings" contains "set" and "address" contains
    # "add" as substrings, but neither is the mutating verb itself.
    # check_tool_name_shape must match whole underscore-delimited
    # tokens, not any substring, or these ordinary read-only tool
    # names would be wrongly refused.
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    manifest = _manifest(tmp_path, mcp_tool_name="pfsense_get_system_restapi_settings")
    discovery = _discovery_snapshot(tmp_path)
    sc.build_proposal(sc.load_manifest(manifest), discovery, "x")


def test_refuses_existing_proposal_directory(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    (fake_repo / ".capability_proposals" / "x").mkdir(parents=True)

    manifest = _manifest(tmp_path)
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "proposal-destination-exists"


def test_refuses_output_name_with_path_traversal(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    manifest = _manifest(tmp_path)
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "../escape")
    assert excinfo.value.category == "invalid-output-name"


def test_repo_relative_write_path_refuses_escape(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc._repo_relative_write_path(root, "..", "escape.txt")
    assert excinfo.value.category == "path-escape"


def test_engineer_profile_refused_in_v1(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)
    manifest = _manifest(tmp_path, profiles=["EngineerProfile"])
    discovery = _discovery_snapshot(tmp_path)
    with pytest.raises(sc.ScaffoldRefusal) as excinfo:
        sc.build_proposal(sc.load_manifest(manifest), discovery, "x")
    assert excinfo.value.category == "profile-not-supported"


# --- static safety properties -------------------------------------------


def test_no_pfsense_env_vars_or_network_referenced_in_source():
    src = Path(sc.__file__).read_text()
    for forbidden in ("PFSENSE_API_URL", "PFSENSE_API_KEY", "load_api_key", "HttpTransport", "RestApiClient("):
        assert forbidden not in src, f"scaffold_capability.py unexpectedly references {forbidden!r}"


def test_no_git_mutation_command_in_source():
    src = Path(sc.__file__).read_text()
    for verb in ("add", "commit", "push", "reset", "checkout", "stash"):
        assert f'"git", "{verb}"' not in src
        assert f"'git', '{verb}'" not in src


def test_no_write_tool_path_or_mutating_verb_can_be_generated():
    src = Path(sc.__file__).read_text()
    assert "tools/write" not in src
    assert "tools.write" not in src


# --- diff/full-file round trip ------------------------------------------


def _apply_unified_diff(original: str, diff_text: str) -> str:
    """Minimal unified-diff applier, used only by this test to prove
    round-trip correctness — never by scaffold_capability.py itself,
    which never applies a diff to anything (see the "no patch/git
    apply" static checks above)."""
    original_lines = original.splitlines(keepends=True)
    result: list[str] = []
    orig_idx = 0
    lines = diff_text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("@@"):
            start = int(line.split()[1].split(",")[0].lstrip("-")) - 1
            result.extend(original_lines[orig_idx:start])
            orig_idx = start
            i += 1
            while i < len(lines) and not lines[i].startswith("@@"):
                hunk_line = lines[i]
                if hunk_line.startswith("+"):
                    result.append(hunk_line[1:])
                elif hunk_line.startswith("-"):
                    orig_idx += 1
                elif hunk_line.startswith(" "):
                    result.append(hunk_line[1:])
                    orig_idx += 1
                i += 1
        else:
            i += 1
    result.extend(original_lines[orig_idx:])
    return "".join(result)


def test_diff_reproduces_proposed_full_file_exactly(tmp_path, monkeypatch):
    fake_repo = _make_fake_repo(tmp_path / "repo")
    _patch_paths(monkeypatch, fake_repo)

    manifest = _manifest(
        tmp_path,
        capability_name="ROUNDTRIP_READ",
        model_class_name="RoundTripDemo",
        client_method_name="get_roundtrip_demo",
        mcp_tool_name="pfsense_get_roundtrip_demo",
    )
    discovery = _discovery_snapshot(tmp_path)
    proposal_dir = sc.build_proposal(sc.load_manifest(manifest), discovery, "roundtrip")

    original = _CLIENT_PY
    diff_text = (proposal_dir / "diffs" / "pfsense_client.patch").read_text()
    proposed_full = (proposal_dir / "proposed_full_files" / "pfsense_client.py").read_text()

    reconstructed = _apply_unified_diff(original, diff_text)
    assert reconstructed == proposed_full


def test_cross_check_fields_nullable_reflects_every_sampled_item():
    # Regression test: pfSense's own /interfaces endpoint declares
    # adv_dhcp_pt_values/dhcprejectfrom as non-nullable in its OpenAPI
    # schema, yet a static-mode interface has them null while a
    # DHCP-mode interface has them populated. Checking only the first
    # fixture item (as this function used to) produced a model field
    # typed as required-non-nullable that then failed real validation
    # for every other row.
    discovery_endpoint = {
        "response_fields": [
            {"name": "id", "type": "string", "nullable": False},
            {"name": "note", "type": "string", "nullable": False},
        ]
    }
    fixture_data = {
        "data": [
            {"id": "wan", "note": "populated"},
            {"id": "lan", "note": None},
        ]
    }
    fields = sc.cross_check_fields(discovery_endpoint, fixture_data, "list")
    by_name = {f.name: f for f in fields}
    assert by_name["id"].nullable is False
    assert by_name["note"].nullable is True


def test_cross_check_fields_all_non_null_stays_non_nullable():
    discovery_endpoint = {"response_fields": [{"name": "id", "type": "string", "nullable": False}]}
    fixture_data = {"data": [{"id": "wan"}, {"id": "lan"}]}
    fields = sc.cross_check_fields(discovery_endpoint, fixture_data, "list")
    assert fields[0].nullable is False
