"""Structural tests for the Makefile's `quick` target composition.

These tests parse the Makefile text directly (never invoke `make`) to
confirm the constraints agreed for `make quick`: it must show its own
11-stage progress labels (never validate's 20-stage labels), must not
generate a JUnit report, and must not call any of the validate-only
tooling (fixture safety, bounded-parameter audit, JUnit post-processing,
public-contract/documentation validation, or the git report). `validate` must
contain all 20 stages (the original 13, three WRITE-infrastructure stages, the
public contract snapshot, documentation consistency validation, the bandit
static security analysis stage, and the git-identity leak check).
"""

from __future__ import annotations

import re
from pathlib import Path

MAKEFILE = Path(__file__).resolve().parent.parent / "Makefile"

_TARGET_HEADER_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*):", re.MULTILINE)


def _makefile_text() -> str:
    return MAKEFILE.read_text(encoding="utf-8")


def _target_block(text: str, target: str) -> str:
    """Return the full text of `target`'s definition (its prerequisite
    line(s), including any backslash continuations, plus its recipe
    body), up to but not including the next top-level target header."""
    match = re.search(rf"^{re.escape(target)}:", text, re.MULTILINE)
    assert match is not None, f"target {target!r} not found in Makefile"
    start = match.start()

    next_header = None
    for header_match in _TARGET_HEADER_RE.finditer(text, pos=match.end()):
        next_header = header_match.start()
        break

    return text[start : next_header if next_header is not None else len(text)]


def test_quick_target_exists():
    text = _makefile_text()
    assert re.search(r"^quick:", text, re.MULTILINE) is not None


def test_quick_has_exactly_eleven_numbered_stage_labels():
    block = _target_block(_makefile_text(), "quick")
    labels = re.findall(r"\[\d+/11\]", block)
    assert labels == [f"[{n}/11]" for n in range(1, 12)]


def test_no_validate_stage_labels_occur_inside_quick_recipe():
    block = _target_block(_makefile_text(), "quick")
    assert "/20]" not in block


def test_validate_contains_all_20_stages():
    text = _makefile_text()
    validate_block = _target_block(text, "validate")
    # validate's own summary line, plus each dependency's recipe carries
    # its own [N/20] label — collect labels from validate's prerequisite
    # targets, not just validate's own (mostly prerequisite-only) block.
    prereqs = [
        "syntax-check",
        "lint",
        "typecheck",
        "test",
        "live-skip-check",
        "endpoint-registry-check",
        "profile-registration-check",
        "get-only-check",
        "tools-write-check",
        "security-scan",
        "git-identity-check",
        "security-static-check",
        "fixture-safety-check",
        "query-param-check",
        "write-infrastructure-check",
        "write-allow-list-check",
        "write-capability-check",
        "contract-check",
        "docs-check",
        "git-report",
    ]
    for target in prereqs:
        assert re.search(rf"^{target}\b", validate_block, re.MULTILINE) or re.search(
            rf"\b{target}\b", validate_block
        ), f"{target} missing from validate's prerequisite list"

    all_labels = set()
    for target in prereqs:
        block = _target_block(text, target)
        all_labels.update(re.findall(r"\[\s*\d+/20\]", block))
    assert len(all_labels) == 20, f"expected 20 distinct stage labels, found {sorted(all_labels)}"


def test_ruff_and_mypy_commands_defined_only_in_internal_shared_targets():
    text = _makefile_text()

    ruff_format_cmd = "ruff format --check ."
    ruff_check_cmd = "ruff check ."
    mypy_cmd = "mypy src/pfsense_mcp scripts"

    for cmd, owner in (
        (ruff_format_cmd, "_ruff-format"),
        (ruff_check_cmd, "_ruff-check"),
        (mypy_cmd, "_mypy"),
    ):
        owner_block = _target_block(text, owner)
        assert cmd in owner_block, f"{cmd!r} not found in {owner}'s recipe"

    # No other target may contain the literal command — they must call
    # the shared internal target via $(MAKE) instead.
    for target in ("lint", "typecheck", "quick"):
        block = _target_block(text, target)
        assert ruff_format_cmd not in block, f"{target} duplicates the ruff format command directly"
        assert ruff_check_cmd not in block, f"{target} duplicates the ruff check command directly"
        assert mypy_cmd not in block, f"{target} duplicates the mypy command directly"
        assert "_ruff-format" in block or target == "typecheck", f"{target} does not call the shared ruff target"


def test_quick_does_not_generate_junit_xml():
    block = _target_block(_makefile_text(), "quick")
    assert "--junit-xml" not in block


def test_quick_does_not_call_validate_only_tooling():
    block = _target_block(_makefile_text(), "quick")
    for forbidden in (
        "validate_junit.py",
        "fixture_safety.py",
        "bounded_params_check.py",
        "validate_docs.py",
        "public_contract.py",
        "git_report.py",
    ):
        assert forbidden not in block, f"quick's recipe unexpectedly calls {forbidden}"


def test_quick_does_call_the_expected_scripts():
    block = _target_block(_makefile_text(), "quick")
    for expected in (
        "get_only_check.py",
        "tools_write_check.py",
        "security_scan.py",
        "git_identity_check.py",
        "write_allow_list_check.py",
        "write_capability_check.py",
    ):
        assert expected in block, f"quick's recipe is missing the expected call to {expected}"
    assert re.search(r"pytest\s+-q\s*$", block, re.MULTILINE), "quick's recipe is missing a bare `pytest -q` run"


def test_bandit_command_defined_only_in_shared_security_static_target():
    text = _makefile_text()
    bandit_cmd = "bandit -c pyproject.toml -r src/pfsense_mcp scripts"

    owner_block = _target_block(text, "security-static")
    assert bandit_cmd in owner_block, "bandit command not found in security-static's recipe"

    # quick and security-static-check (validate's wrapper) must both call
    # the shared security-static target via $(MAKE), never duplicate the
    # bandit command directly -- the same pattern already enforced above
    # for ruff/mypy, so a CI-only bandit failure like the one this stage
    # closes a gap for can never silently diverge between quick/validate.
    for target in ("quick", "security-static-check"):
        block = _target_block(text, target)
        assert bandit_cmd not in block, f"{target} duplicates the bandit command directly"
        assert "security-static" in block, f"{target} does not call the shared security-static target"


def test_quick_pytest_invocation_has_no_junit_flag_on_the_same_line():
    block = _target_block(_makefile_text(), "quick")
    pytest_lines = [line for line in block.splitlines() if "$(PYTHON) -m pytest" in line]
    assert len(pytest_lines) == 1
    assert "--junit-xml" not in pytest_lines[0]


def test_makefile_uses_no_print_directory_for_recursive_make_calls():
    text = _makefile_text()
    recursive_calls = re.findall(r"\$\(MAKE\)[^\n]*", text)
    assert recursive_calls, "expected at least one recursive $(MAKE) call"
    for call in recursive_calls:
        assert "--no-print-directory" in call, f"recursive call missing --no-print-directory: {call!r}"
