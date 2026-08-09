from __future__ import annotations

import json

import pytest
from verify_sbom import SbomVerificationError, verify_sbom


def _valid_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "application", "name": "pfsense-mcp-server"}},
        "components": [{"type": "library", "name": "pydantic", "version": "2.9.0"}],
    }
    document.update(overrides)
    return document


def _write(tmp_path, document: dict[str, object]):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_accepts_a_valid_sbom(tmp_path):
    path = _write(tmp_path, _valid_document())
    document = verify_sbom(path, expected_name="pfsense-mcp-server")
    assert document["components"][0]["name"] == "pydantic"


def test_accepts_underscore_hyphen_name_normalization(tmp_path):
    document = _valid_document()
    document["metadata"] = {"component": {"type": "application", "name": "pfsense_mcp_server"}}
    path = _write(tmp_path, document)
    verify_sbom(path, expected_name="pfsense-mcp-server")


def test_rejects_wrong_bom_format(tmp_path):
    path = _write(tmp_path, _valid_document(bomFormat="SPDX"))
    with pytest.raises(SbomVerificationError, match="bomFormat"):
        verify_sbom(path, expected_name="pfsense-mcp-server")


def test_rejects_missing_spec_version(tmp_path):
    document = _valid_document()
    document["specVersion"] = ""
    path = _write(tmp_path, document)
    with pytest.raises(SbomVerificationError, match="specVersion"):
        verify_sbom(path, expected_name="pfsense-mcp-server")


def test_rejects_missing_metadata_component(tmp_path):
    document = _valid_document()
    del document["metadata"]
    path = _write(tmp_path, document)
    with pytest.raises(SbomVerificationError, match="metadata"):
        verify_sbom(path, expected_name="pfsense-mcp-server")


def test_rejects_wrong_component_name(tmp_path):
    path = _write(tmp_path, _valid_document())
    with pytest.raises(SbomVerificationError, match="does not match"):
        verify_sbom(path, expected_name="some-other-project")


def test_rejects_empty_components_list(tmp_path):
    document = _valid_document()
    document["components"] = []
    path = _write(tmp_path, document)
    with pytest.raises(SbomVerificationError, match="components"):
        verify_sbom(path, expected_name="pfsense-mcp-server")


def test_rejects_missing_components_list(tmp_path):
    document = _valid_document()
    del document["components"]
    path = _write(tmp_path, document)
    with pytest.raises(SbomVerificationError, match="components"):
        verify_sbom(path, expected_name="pfsense-mcp-server")


def test_rejects_non_json_content(tmp_path):
    path = tmp_path / "sbom.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(SbomVerificationError, match="valid JSON"):
        verify_sbom(path, expected_name="pfsense-mcp-server")


def test_rejects_non_object_top_level(tmp_path):
    path = tmp_path / "sbom.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(SbomVerificationError, match="JSON object"):
        verify_sbom(path, expected_name="pfsense-mcp-server")


@pytest.mark.parametrize(
    "marker",
    [
        b"/home/someuser/project",
        b"/Users/someuser/project",
    ],
)
def test_rejects_local_home_path(tmp_path, marker):
    path = tmp_path / "sbom.json"
    payload = json.dumps(_valid_document()).encode("utf-8")
    path.write_bytes(payload[:-1] + b', "note": "' + marker + b'"}')
    with pytest.raises(SbomVerificationError, match="local home path"):
        verify_sbom(path, expected_name="pfsense-mcp-server")


@pytest.mark.parametrize("marker", [b"file:///opt/local/repo", b"editable"])
def test_rejects_local_install_reference(tmp_path, marker):
    path = tmp_path / "sbom.json"
    payload = json.dumps(_valid_document()).encode("utf-8")
    path.write_bytes(payload[:-1] + b', "note": "' + marker + b'"}')
    with pytest.raises(SbomVerificationError, match="local/editable"):
        verify_sbom(path, expected_name="pfsense-mcp-server")


def test_rejects_unreadable_path(tmp_path):
    missing = tmp_path / "does-not-exist.json"
    with pytest.raises(SbomVerificationError, match="cannot read"):
        verify_sbom(missing, expected_name="pfsense-mcp-server")
