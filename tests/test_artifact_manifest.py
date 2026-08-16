from __future__ import annotations

from artifact_manifest import build_manifest


def test_artifact_manifest_contains_release_evidence_without_paths(tmp_path):
    wheel = tmp_path / "pfsense_mcp_server-0.4.2-py3-none-any.whl"
    sdist = tmp_path / "pfsense_mcp_server-0.4.2.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")

    manifest = build_manifest(tmp_path)

    assert manifest["package"] == "pfsense-mcp-server"
    assert manifest["version"] == "0.4.2"
    assert manifest["requires_python"] == ">=3.11"
    assert len(manifest["source_commit"]) == 40
    assert [item["filename"] for item in manifest["artifacts"]] == sorted([sdist.name, wheel.name])
    assert all("/" not in item["filename"] for item in manifest["artifacts"])
    assert all(len(item["sha256"]) == 64 for item in manifest["artifacts"])
