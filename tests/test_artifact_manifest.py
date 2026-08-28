from __future__ import annotations

import tomllib

from artifact_manifest import ROOT, build_manifest

_CURRENT_VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def test_artifact_manifest_contains_release_evidence_without_paths(tmp_path):
    # Derived from pyproject.toml's actual current version, not a hardcoded
    # literal -- build_manifest() itself globs for the version it reads from
    # pyproject.toml, so a fixed literal here silently breaks on every
    # version bump (found during the v0.9.0 release-readiness audit).
    wheel = tmp_path / f"pfsense_mcp_server-{_CURRENT_VERSION}-py3-none-any.whl"
    sdist = tmp_path / f"pfsense_mcp_server-{_CURRENT_VERSION}.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")

    manifest = build_manifest(tmp_path)

    assert manifest["package"] == "pfsense-mcp-server"
    assert manifest["version"] == _CURRENT_VERSION
    assert manifest["requires_python"] == ">=3.11"
    assert len(manifest["source_commit"]) == 40
    assert [item["filename"] for item in manifest["artifacts"]] == sorted([sdist.name, wheel.name])
    assert all("/" not in item["filename"] for item in manifest["artifacts"])
    assert all(len(item["sha256"]) == 64 for item in manifest["artifacts"])
