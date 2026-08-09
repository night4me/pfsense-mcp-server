"""Unit tests for scripts/build_endpoint_catalogue.py.

Everything here runs fully offline against the synthetic fixture
tests/fixtures/openapi_schema_sample.json (shared with
test_discover_endpoints.py) -- no network, no credentials, no `live`
marker, and no committed catalogue file is ever mutated (a fresh
tmp_path target is used for every write).
"""

from __future__ import annotations

import json
from pathlib import Path

import build_endpoint_catalogue

from pfsense_mcp.api_surface.catalogue import EndpointCatalogue, IntendedUse
from pfsense_mcp.api_surface.store import load_catalogue, save_catalogue

FIXTURE = Path(__file__).parent / "fixtures" / "openapi_schema_sample.json"


def test_dry_run_against_fresh_target_reports_three_new_entries_and_writes_nothing(tmp_path, capsys):
    target = tmp_path / "endpoint_catalogue.json"
    exit_code = build_endpoint_catalogue.main(["--schema-file", str(FIXTURE), "--catalogue-file", str(target)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert not target.exists()
    assert "3 GET operation(s) discovered" in captured.out
    assert "3 new entries would be added" in captured.out
    assert "+ GET /api/v2/widget/gadgets" in captured.out
    assert "+ GET /api/v2/widget/gadgets/count" in captured.out
    assert "+ GET /api/v2/widget/sprockets" in captured.out
    assert "Dry run -- no file written" in captured.out


def test_update_writes_catalogue_with_three_entries_default_intended_use(tmp_path):
    target = tmp_path / "endpoint_catalogue.json"
    exit_code = build_endpoint_catalogue.main(
        ["--schema-file", str(FIXTURE), "--catalogue-file", str(target), "--update"]
    )
    assert exit_code == 0
    assert target.exists()

    catalogue = load_catalogue(target)
    assert len(catalogue.entries) == 3
    assert all(e.intended_use is IntendedUse.NONE for e in catalogue.entries)
    assert catalogue.generated_at is not None


def test_update_marks_mutating_methods_exist_correctly(tmp_path):
    target = tmp_path / "endpoint_catalogue.json"
    build_endpoint_catalogue.main(["--schema-file", str(FIXTURE), "--catalogue-file", str(target), "--update"])
    catalogue = load_catalogue(target)
    by_path = {e.path: e for e in catalogue.entries}

    assert by_path["/api/v2/widget/gadgets"].mutating_methods_exist is True
    assert by_path["/api/v2/widget/gadgets/count"].mutating_methods_exist is False


def test_rerun_never_overwrites_human_set_intended_use(tmp_path):
    target = tmp_path / "endpoint_catalogue.json"
    build_endpoint_catalogue.main(["--schema-file", str(FIXTURE), "--catalogue-file", str(target), "--update"])

    catalogue = load_catalogue(target)
    updated_entries = tuple(
        e.model_copy(update={"intended_use": IntendedUse.CANDIDATE}) if e.path == "/api/v2/widget/gadgets" else e
        for e in catalogue.entries
    )
    save_catalogue(EndpointCatalogue(schema_version=1, entries=updated_entries), target)

    build_endpoint_catalogue.main(["--schema-file", str(FIXTURE), "--catalogue-file", str(target), "--update"])
    reloaded = load_catalogue(target)
    by_path = {e.path: e for e in reloaded.entries}
    assert by_path["/api/v2/widget/gadgets"].intended_use is IntendedUse.CANDIDATE
    assert by_path["/api/v2/widget/sprockets"].intended_use is IntendedUse.NONE


def test_rerun_with_unchanged_schema_reports_zero_added_and_zero_updated(tmp_path, capsys):
    target = tmp_path / "endpoint_catalogue.json"
    build_endpoint_catalogue.main(["--schema-file", str(FIXTURE), "--catalogue-file", str(target), "--update"])
    capsys.readouterr()

    build_endpoint_catalogue.main(["--schema-file", str(FIXTURE), "--catalogue-file", str(target), "--update"])
    captured = capsys.readouterr()
    assert "0 new entries would be added" in captured.out
    assert "0 existing entries would be refreshed" in captured.out


def test_entry_removed_from_schema_is_reported_stale_and_kept(tmp_path, capsys):
    target = tmp_path / "endpoint_catalogue.json"
    build_endpoint_catalogue.main(["--schema-file", str(FIXTURE), "--catalogue-file", str(target), "--update"])

    schema = json.loads(FIXTURE.read_text())
    del schema["paths"]["/api/v2/widget/sprockets"]
    trimmed_schema_file = target.parent / "trimmed_schema.json"
    trimmed_schema_file.write_text(json.dumps(schema))

    exit_code = build_endpoint_catalogue.main(
        ["--schema-file", str(trimmed_schema_file), "--catalogue-file", str(target), "--update"]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "1 existing entry no longer discovered" in captured.out
    assert "/api/v2/widget/sprockets" in captured.out

    catalogue = load_catalogue(target)
    assert any(e.path == "/api/v2/widget/sprockets" for e in catalogue.entries), "stale entry must not be deleted"


def test_dry_run_does_not_modify_an_already_existing_file(tmp_path):
    target = tmp_path / "endpoint_catalogue.json"
    build_endpoint_catalogue.main(["--schema-file", str(FIXTURE), "--catalogue-file", str(target), "--update"])
    before = target.read_text()

    build_endpoint_catalogue.main(["--schema-file", str(FIXTURE), "--catalogue-file", str(target)])
    after = target.read_text()
    assert before == after


def test_written_file_is_deterministically_formatted(tmp_path):
    target = tmp_path / "endpoint_catalogue.json"
    build_endpoint_catalogue.main(["--schema-file", str(FIXTURE), "--catalogue-file", str(target), "--update"])
    text = target.read_text()
    assert text.endswith("\n")
    reparsed = json.loads(text)
    assert list(reparsed.keys()) == sorted(reparsed.keys())


def test_cli_missing_schema_file_reports_clear_error_exit_code(tmp_path, capsys):
    target = tmp_path / "endpoint_catalogue.json"
    exit_code = build_endpoint_catalogue.main(
        ["--schema-file", "/nonexistent/path/schema.json", "--catalogue-file", str(target)]
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert not target.exists()
    assert "Error reading schema file" in captured.err


def test_cli_missing_env_vars_reports_configuration_error_when_no_schema_file(tmp_path, monkeypatch, capsys):
    for var in ("PFSENSE_API_URL", "PFSENSE_IDENTITY", "PFSENSE_API_KEY_FILE"):
        monkeypatch.delenv(var, raising=False)
    target = tmp_path / "endpoint_catalogue.json"

    exit_code = build_endpoint_catalogue.main(["--catalogue-file", str(target)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Error:" in captured.err
    assert not target.exists()


def test_report_never_includes_the_word_verified(tmp_path, capsys):
    target = tmp_path / "endpoint_catalogue.json"
    build_endpoint_catalogue.main(["--schema-file", str(FIXTURE), "--catalogue-file", str(target)])
    captured = capsys.readouterr()
    assert "verified" not in captured.out.lower()


def test_default_catalogue_file_points_at_repo_root_catalogue_directory():
    from pfsense_mcp.api_surface.store import DEFAULT_CATALOGUE_PATH

    assert DEFAULT_CATALOGUE_PATH.parts[-2:] == ("catalogue", "endpoint_catalogue.json")
