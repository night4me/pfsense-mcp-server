from __future__ import annotations

from public_contract import (
    PUBLISHED_README_GUIDANCE_COUNT,
    PUBLISHED_README_READ_COUNT,
    READ_TOOLS,
    ROOT,
    SNAPSHOT,
    _tool_definitions,
    build_contract,
    main,
    readme_tool_count_mismatches,
)


def test_public_contract_matches_approved_snapshot():
    assert main([]) == 0


def test_public_contract_is_complete_and_security_preserving():
    contract = build_contract()
    tools = contract["tools"]

    # 101 pfSense READ tools + 2 guidance tools (pfsense_get_official_guidance,
    # owner-authorized 2026-08-22) -- accounted for separately below, never
    # blended into "103 READ tools" (GUIDANCE_MCP_EXPOSURE_QUALIFICATION_2026-08-22.md).
    assert len(tools) == 122
    assert len({tool["name"] for tool in tools}) == 122

    read_tools = [tool for tool in tools if tool["tool_class"] == "read"]
    assert len(read_tools) == 120
    assert all(tool["name"].startswith("pfsense_get_") or tool["name"] == "pfsense_mcp_info" for tool in read_tools)
    assert all(tool["capability"].endswith("_READ") for tool in read_tools)

    upstream_tools = [tool for tool in read_tools if tool["name"] != "pfsense_mcp_info"]
    assert all(tool["endpoint"]["method"] == "GET" for tool in upstream_tools)
    assert all(tool["endpoint"]["verified"] is True for tool in upstream_tools)
    assert all(tool["annotations"] == {"openWorldHint": True, "readOnlyHint": True} for tool in upstream_tools)

    local_only_tool = next(tool for tool in read_tools if tool["name"] == "pfsense_mcp_info")
    assert local_only_tool["client_method"] is None
    assert local_only_tool["endpoint"] is None
    assert local_only_tool["annotations"] == {"openWorldHint": False, "readOnlyHint": True}

    guidance_tools = [tool for tool in tools if tool["tool_class"] == "guidance"]
    assert len(guidance_tools) == 2
    assert {tool["name"] for tool in guidance_tools} == {"pfsense_get_official_guidance", "pfsense_get_api_guidance"}
    for guidance_tool in guidance_tools:
        assert guidance_tool["capability"] is None
        assert guidance_tool["client_method"] is None
        assert guidance_tool["endpoint"] is None
        assert guidance_tool["annotations"] == {"openWorldHint": True, "readOnlyHint": True, "destructiveHint": False}

    assert SNAPSHOT.is_file()


def test_contract_descriptions_use_stable_source_docstrings():
    definitions = _tool_definitions()
    acme_source = (READ_TOOLS / "acme_settings.py").read_text(encoding="utf-8")

    description = definitions["pfsense_get_acme_settings"][1]
    assert "        the service is enabled" in description
    assert description in acme_source


# ===========================================================================
# README.md tool-count claims vs the authoritative contract
# ===========================================================================
#
# This is the regression coverage for the clean-room finding that the
# already-published v0.9.0 PyPI long_description carried a stale "96
# tools (95 READ + 1 guidance)" claim after a second guidance tool was
# added -- readme_tool_count_mismatches() is what `public_contract.py`'s
# own `main()` now runs on every invocation (including `make quick` /
# `make validate`) so a future release can never publish a README whose
# stated counts disagree with reality.
#
# README's counts are checked against PUBLISHED_README_READ_COUNT /
# PUBLISHED_README_GUIDANCE_COUNT -- the last actually-*published* PyPI
# baseline -- not against build_contract()'s own live count. As of
# POST_V1_1_FINAL_READ_COVERAGE_AUDIT.md (owner decision, 2026-08-30)
# these two can legitimately differ: a new READ tool was added to the
# SNAPSHOT-approved contract without a version bump/republish, and
# README's Quick Start instructs `pipx install pfsense-mcp-server`,
# which still installs the older, already-published tool count.


def test_current_readme_agrees_with_the_last_published_baseline():
    readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert (
        readme_tool_count_mismatches(
            readme_text,
            read_count=PUBLISHED_README_READ_COUNT,
            guidance_count=PUBLISHED_README_GUIDANCE_COUNT,
        )
        == []
    )


def test_stale_headline_count_is_detected():
    readme_text = (
        "**96 tools: 95 pfSense READ tools + 1 documentation guidance tools.**\n\n"
        "## Release status\n\n"
        "95 pfSense READ tools + 2 documentation guidance tools, 0 WRITE tools.\n\n"
        "shows 97 tools available\n\n"
        "| Category | Tools | Examples |\n|---|---:|---|\n| System | 95 | ... |\n"
    )
    failures = readme_tool_count_mismatches(readme_text, read_count=95, guidance_count=2)
    assert any("headline" in failure for failure in failures)


def test_stale_release_status_count_is_detected():
    readme_text = (
        "**97 tools: 95 pfSense READ tools + 2 documentation guidance tools.**\n\n"
        "## Release status\n\n"
        "95 pfSense READ tools + 1 documentation guidance tools, 0 WRITE tools.\n\n"
        "shows 97 tools available\n\n"
        "| Category | Tools | Examples |\n|---|---:|---|\n| System | 95 | ... |\n"
    )
    failures = readme_tool_count_mismatches(readme_text, read_count=95, guidance_count=2)
    assert any("Release status" in failure for failure in failures)


def test_stale_shows_available_count_is_detected():
    readme_text = (
        "**97 tools: 95 pfSense READ tools + 2 documentation guidance tools.**\n\n"
        "## Release status\n\n"
        "95 pfSense READ tools + 2 documentation guidance tools, 0 WRITE tools.\n\n"
        "shows 96 tools available\n\n"
        "| Category | Tools | Examples |\n|---|---:|---|\n| System | 95 | ... |\n"
    )
    failures = readme_tool_count_mismatches(readme_text, read_count=95, guidance_count=2)
    assert any("shows" in failure for failure in failures)


def test_category_table_sum_mismatch_is_detected():
    readme_text = (
        "**97 tools: 95 pfSense READ tools + 2 documentation guidance tools.**\n\n"
        "## Release status\n\n"
        "95 pfSense READ tools + 2 documentation guidance tools, 0 WRITE tools.\n\n"
        "shows 97 tools available\n\n"
        "| Category | Tools | Examples |\n|---|---:|---|\n| System | 26 | ... |\n| VPN | 17 | ... |\n"
        "## Next section\n"
    )
    failures = readme_tool_count_mismatches(readme_text, read_count=95, guidance_count=2)
    assert any("per-category" in failure for failure in failures)


def test_missing_claims_are_reported_not_silently_skipped():
    failures = readme_tool_count_mismatches("# Empty README\n", read_count=95, guidance_count=2)
    assert len(failures) == 4
