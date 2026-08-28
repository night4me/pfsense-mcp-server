import importlib.metadata

import pytest

from pfsense_mcp import application, server


def test_main_constructs_application_and_runs_it(monkeypatch):
    calls: list[str] = []

    class _StubApplication:
        def __init__(self) -> None:
            calls.append("constructed")

        def run(self) -> None:
            calls.append("run")

    monkeypatch.setattr(application, "Application", _StubApplication)
    monkeypatch.setattr(server.sys, "argv", ["pfsense-mcp-server"])

    server.main()

    assert calls == ["constructed", "run"]


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_flag_prints_guidance_and_never_constructs_application(monkeypatch, capsys, flag):
    monkeypatch.setattr(server.sys, "argv", ["pfsense-mcp-server", flag])
    monkeypatch.setattr(
        application,
        "Application",
        lambda: (_ for _ in ()).throw(AssertionError("Application must not be constructed for --help")),
    )

    server.main()

    out = capsys.readouterr().out
    assert "pfsense-mcp-security setup" in out
    assert "MCP" in out


def test_help_output_points_to_the_guided_setup_wizard_as_the_next_step(monkeypatch, capsys):
    monkeypatch.setattr(server.sys, "argv", ["pfsense-mcp-server", "--help"])

    server.main()

    out = capsys.readouterr().out
    # The front door: a user with no config should find the one thing to
    # run next, not architecture/internal terminology.
    assert "pfsense-mcp-security setup" in out
    for jargon in ("ADR", "PlanAuthorization", "RecoveryContract", "canonical digest"):
        assert jargon not in out


def test_version_flag_reports_the_installed_package_version(monkeypatch, capsys):
    monkeypatch.setattr(server.sys, "argv", ["pfsense-mcp-server", "--version"])

    server.main()

    out = capsys.readouterr().out
    assert out.strip() == f"pfsense-mcp-server {importlib.metadata.version('pfsense-mcp-server')}"


def test_version_flag_handles_a_non_installed_package_gracefully(monkeypatch, capsys):
    def _raise(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(_name)

    monkeypatch.setattr(server.sys, "argv", ["pfsense-mcp-server", "--version"])
    monkeypatch.setattr(importlib.metadata, "version", _raise)

    server.main()

    out = capsys.readouterr().out
    assert out.startswith("pfsense-mcp-server unknown")


def test_help_and_version_never_construct_fastmcp_and_so_never_emit_its_warning(monkeypatch, capsys):
    # FastMCP's own constructor is what triggers the upstream
    # pydantic-settings warning this module filters -- confirm --help
    # exits before that construction ever happens, rather than relying
    # on the filter to hide it.
    import warnings

    monkeypatch.setattr(server.sys, "argv", ["pfsense-mcp-server", "--help"])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        server.main()
    assert caught == []
