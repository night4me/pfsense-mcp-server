"""Tests for scripts/pfrest_schema_diff.py (owner direction,
pfREST_LIVE_GUIDANCE_ARC continuation, 2026-08-28). Network paths tested
via respx; appliance path tested via monkeypatching the client-building
functions -- never the real network or a real appliance."""

from __future__ import annotations

import json

import httpx
import respx
from pfrest_schema_diff import UPSTREAM_OPENAPI_URL, main


def _write_json(tmp_path, name: str, document: dict) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


def test_file_vs_file_identical_exits_zero(tmp_path, capsys):
    doc = {"paths": {}, "components": {"schemas": {}}}
    path_a = _write_json(tmp_path, "a.json", doc)
    path_b = _write_json(tmp_path, "b.json", doc)

    exit_code = main(["--a", "file", "--a-file", path_a, "--b", "file", "--b-file", path_b])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "No differences found" in out
    assert "never WHY" in out


def test_file_vs_file_reports_a_real_difference(tmp_path, capsys):
    doc_a = {"paths": {"/api/v2/x": {"get": {}}}, "components": {"schemas": {}}}
    doc_b = {"paths": {}, "components": {"schemas": {}}}
    path_a = _write_json(tmp_path, "a.json", doc_a)
    path_b = _write_json(tmp_path, "b.json", doc_b)

    exit_code = main(["--a", "file", "--a-file", path_a, "--b", "file", "--b-file", path_b])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "paths_methods" in out
    assert "GET /api/v2/x" in out


def test_missing_a_file_argument_fails_closed(capsys):
    exit_code = main(["--a", "file", "--b", "file", "--b-file", "/nonexistent/does-not-matter.json"])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "--a-file/--b-file is required" in err


def test_nonexistent_file_fails_closed(capsys):
    exit_code = main(
        ["--a", "file", "--a-file", "/nonexistent/path.json", "--b", "file", "--b-file", "/nonexistent/path2.json"]
    )
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "could not read" in err


def test_malformed_json_file_fails_closed(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{not valid json", encoding="utf-8")
    exit_code = main(["--a", "file", "--a-file", str(path), "--b", "file", "--b-file", str(path)])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "was not valid JSON" in err


def test_json_file_not_an_object_fails_closed(tmp_path, capsys):
    path = tmp_path / "array.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    exit_code = main(["--a", "file", "--a-file", str(path), "--b", "file", "--b-file", str(path)])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "did not contain a JSON object" in err


def test_appliance_source_without_env_fails_closed(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("PFSENSE_API_URL", raising=False)
    path_a = _write_json(tmp_path, "a.json", {"paths": {}})
    exit_code = main(["--a", "file", "--a-file", path_a, "--b", "appliance"])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "appliance mode requires PFSENSE_API_URL" in err


@respx.mock
def test_upstream_source_fetch_failure_fails_closed(tmp_path, capsys):
    respx.get(UPSTREAM_OPENAPI_URL).mock(return_value=httpx.Response(500))
    path_b = _write_json(tmp_path, "b.json", {"paths": {}})
    exit_code = main(["--a", "upstream", "--b", "file", "--b-file", path_b])
    assert exit_code == 1
    out_err = capsys.readouterr()
    assert "FAILED" in out_err.out


@respx.mock
def test_upstream_source_fetch_success(tmp_path, capsys):
    doc = {"paths": {"/api/v2/x": {"get": {}}}, "components": {"schemas": {}}}
    respx.get(UPSTREAM_OPENAPI_URL).mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"}, json=doc)
    )
    path_b = _write_json(tmp_path, "b.json", doc)
    exit_code = main(["--a", "upstream", "--b", "file", "--b-file", path_b])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "No differences found" in out


def test_dump_writes_raw_document_for_later_offline_use(tmp_path, capsys):
    doc_a = {"paths": {"/api/v2/x": {"get": {}}}, "components": {"schemas": {}}}
    doc_b = {"paths": {}, "components": {"schemas": {}}}
    path_a = _write_json(tmp_path, "a.json", doc_a)
    path_b = _write_json(tmp_path, "b.json", doc_b)
    dump_path = tmp_path / "dumped.json"

    exit_code = main(["--a", "file", "--a-file", path_a, "--b", "file", "--b-file", path_b, "--dump-a", str(dump_path)])
    assert exit_code == 0
    dumped = json.loads(dump_path.read_text(encoding="utf-8"))
    assert dumped == doc_a


def test_unknown_source_rejected_by_argparse():
    import pytest

    with pytest.raises(SystemExit):
        main(["--a", "not-a-real-source"])
