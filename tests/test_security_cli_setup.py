"""Focused + adversarial tests for `pfsense-mcp-security setup`
(`pfsense_mcp.security_cli`, Slice 1 + the two Slice 1 UX corrections).
Proves, at the actual CLI surface: the guided, numbered-menu wizard
never lets an invalid or unavailable choice reach the plan model; bare
setup/interactive planning/non-interactive setup all cannot mutate;
malformed arguments cannot reach mutation code; Back/Quit/EOF/Ctrl+C
all terminate or navigate cleanly from every step; progressive
disclosure holds (read-only never asks a write-protection question,
switching modes clears irrelevant state); step numbering is consistent
("Step N of M") across the whole numbered sequence, including Review;
Advanced discovery-input configuration is never a mandatory stop on the
default happy path and is reached only as an explicit choice from
Review; secrets are absent from every output surface; the human-mode
completion screen shows only a short Plan ID, never the full digest;
and no live network call of any kind is ever made, using a hostile
transport that raises immediately if `httpx.Client` is ever
constructed."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest

from pfsense_mcp.security_cli import (
    _MCP_CLIENT_CA_FILE_PLACEHOLDER,
    _MCP_CLIENT_COMMAND_PLACEHOLDER,
    _resolve_mcp_client_command,
    main,
)


def _clear_relevant_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("PFSENSE_TIER1_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("PFSENSE_PROFILE", raising=False)


def _run(monkeypatch, argv, stdin_text="", env=None):
    _clear_relevant_env(monkeypatch)
    if env:
        for key, value in env.items():
            monkeypatch.setenv(key, value)
    out = io.StringIO()
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    monkeypatch.setattr("sys.stdout", out)
    exit_code = main(argv)
    return exit_code, out.getvalue()


def _answers(*parts: str) -> str:
    return "\n".join(parts) + "\n"


#: A complete, valid answer sequence for the read-only happy path:
#: usage=1 (read-only), address=192.0.2.1, confirm-https=1,
#: name=Home pfSense, connection=1 (verify), review=1 (generate).
#: Advanced options is never part of this sequence -- it is reached
#: only as an explicit choice from Review (see the "Advanced options"
#: section below).
_READ_ONLY_HAPPY_PATH = _answers("1", "192.0.2.1", "1", "Home pfSense", "1", "1")

#: usage=2 (write_protected), protection=1 (hardware witness), then the
#: same firewall/connection/review sequence.
_WRITE_PROTECTED_HAPPY_PATH = _answers("2", "1", "192.0.2.1", "1", "Lab pfSense", "1", "1")


# ===========================================================================
# Hostile transport: proves zero network client construction
# ===========================================================================


def _install_hostile_httpx(monkeypatch):
    import httpx

    def _hostile_init(self, *args, **kwargs):
        raise AssertionError("httpx.Client must never be constructed by `setup` (Slice 1 is fully offline)")

    monkeypatch.setattr(httpx.Client, "__init__", _hostile_init)


def test_hostile_transport_bare_interactive_setup_never_constructs_an_httpx_client(monkeypatch):
    _install_hostile_httpx(monkeypatch)
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text="")
    assert exit_code == 3
    assert "Setup cancelled." in out


def test_hostile_transport_non_interactive_usage_error_never_constructs_an_httpx_client(monkeypatch):
    _install_hostile_httpx(monkeypatch)
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "--non-interactive"])
    assert excinfo.value.code == 2


def test_hostile_transport_full_non_interactive_setup_never_constructs_an_httpx_client(monkeypatch):
    _install_hostile_httpx(monkeypatch)
    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "hardware_witness",
        ],
    )
    assert exit_code == 0
    assert "setup plan created" in out


def test_hostile_transport_read_only_happy_path_never_constructs_an_httpx_client(monkeypatch):
    _install_hostile_httpx(monkeypatch)
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "setup plan created" in out


def test_hostile_transport_write_protected_happy_path_never_constructs_an_httpx_client(monkeypatch):
    _install_hostile_httpx(monkeypatch)
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_WRITE_PROTECTED_HAPPY_PATH)
    assert exit_code == 0
    assert "setup plan created" in out


def test_hostile_transport_advanced_options_path_never_constructs_an_httpx_client(monkeypatch, tmp_path):
    _install_hostile_httpx(monkeypatch)
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps({"paths": {}}), encoding="utf-8")
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "1", "3", "2", "2.10", str(schema_file), "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "setup plan created" in out


# ===========================================================================
# Happy paths
# ===========================================================================


def test_read_only_happy_path_completes_with_friendly_summary(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "Mode:        Read-only" in out
    assert "Firewall:    Home pfSense" in out
    assert "Address:     https://192.0.2.1" in out
    assert "Connection:  Verify TLS certificate" in out
    assert "No changes were made to pfSense." in out
    assert "Plan ID:" in out


def test_write_protected_happy_path_uses_hardware_witness_and_completes(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_WRITE_PROTECTED_HAPPY_PATH)
    assert exit_code == 0
    assert "Mode:        Protected write" in out
    assert "Firewall:    Lab pfSense" in out
    assert "No changes were made to pfSense." in out


def test_read_only_happy_path_requires_exactly_six_answers(monkeypatch):
    """Documents the actual happy-path decision count now that Advanced
    options is no longer a mandatory stop: usage, address,
    confirm-https, name, connection, review -- 6 real prompts, matching
    the original design goal of "approximately 3-4 real operator
    decisions" (address/confirm-https/name are all part of the single
    "Firewall" step)."""

    assert _READ_ONLY_HAPPY_PATH.count("\n") == 6
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "setup plan created" in out


# ===========================================================================
# Step numbering consistency ("Step N of M")
# ===========================================================================


def test_read_only_path_shows_step_n_of_4_throughout(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "Step 1 of 4 -- Usage" in out
    assert "Step 2 of 4 -- Firewall" in out
    assert "Step 3 of 4 -- Connection" in out
    assert "Step 4 of 4 -- Review" in out


def test_write_protected_path_shows_step_n_of_5_throughout(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_WRITE_PROTECTED_HAPPY_PATH)
    assert exit_code == 0
    assert "Step 1 of 4 -- Usage" in out  # total unknown before mode is chosen -- defaults to read-only's 4
    assert "Step 2 of 5 -- Protection" in out
    assert "Step 3 of 5 -- Firewall" in out
    assert "Step 4 of 5 -- Connection" in out
    assert "Step 5 of 5 -- Review" in out


def test_advanced_options_step_is_never_numbered(monkeypatch, tmp_path):
    """Advanced configuration is explicitly not a mandatory normal-flow
    step (it is reached only as an explicit Review menu choice) -- it
    must never carry a "Step N of M" heading of its own."""

    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps({"paths": {}}), encoding="utf-8")
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "1", "3", "2", "2.10", str(schema_file), "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Advanced options" in out
    for line in out.splitlines():
        if "Advanced options" in line:
            assert not line.strip().startswith("Step")


# ===========================================================================
# Numbered choices, defaults, invalid input
# ===========================================================================


def test_default_enter_selects_read_only_at_usage(monkeypatch):
    # blank line at usage -> default (1, read-only); rest is the normal
    # read-only happy path minus the explicit "1".
    answers = _answers("", "192.0.2.1", "1", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Mode:        Read-only" in out


def test_invalid_numeric_selection_reprompts_without_crashing(monkeypatch):
    answers = _answers("9", "1", "192.0.2.1", "1", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Please enter a number from 1 to 2." in out


def test_arbitrary_text_at_numeric_menu_reprompts(monkeypatch):
    answers = _answers("banana", "1", "192.0.2.1", "1", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Please enter a number from 1 to 2." in out


def test_repeated_invalid_input_eventually_succeeds(monkeypatch):
    answers = _answers("x", "y", "z", "0", "99", "1", "192.0.2.1", "1", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert out.count("Please enter a number from 1 to 2.") == 5
    assert "Mode:        Read-only" in out


def test_whitespace_only_input_at_menu_is_treated_as_default(monkeypatch):
    answers = _answers("   ", "192.0.2.1", "1", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Mode:        Read-only" in out


def test_unavailable_option_selection_explains_and_reprompts(monkeypatch):
    # usage=2 (write_protected) -> protection menu -> select "2"
    # (software, not available) -> must explain and re-prompt, never
    # silently select it -> protection=1 (hardware witness) -> normal
    # rest of the write_protected flow.
    answers = _answers("2", "2", "1", "192.0.2.1", "1", "Lab pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "is not available yet in this build" in out
    assert "Mode:        Protected write" in out


# ===========================================================================
# Progressive disclosure
# ===========================================================================


def test_read_only_branch_never_asks_protection_question(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "-- Protection" not in out
    assert "How should approved changes be protected?" not in out
    assert "Hardware TPM witness" not in out


def test_write_protected_branch_shows_protection_question(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_WRITE_PROTECTED_HAPPY_PATH)
    assert exit_code == 0
    assert "Step 2 of 5 -- Protection" in out
    assert "Hardware TPM witness" in out


def test_switching_write_protected_to_read_only_clears_protection_state(monkeypatch):
    # usage=2 (write_protected) -> protection=1 (hardware witness) ->
    # firewall address: 'b' (back to protection) -> protection: 'b'
    # (back to usage) -> usage=1 (read_only) -> normal read-only flow.
    answers = _answers("2", "1", "b", "b", "1", "192.0.2.1", "1", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Mode:        Read-only" in out
    # The review screen (shown once, right before "Generate plan?") must
    # never describe hardware-witness protection once the operator
    # switched back to read-only.
    assert "hardware TPM witness" not in out.lower()


# ===========================================================================
# Back / Quit / EOF / Ctrl+C navigation
# ===========================================================================


def test_back_at_firewall_returns_to_protection_for_write_protected(monkeypatch):
    # usage=2, protection=1, firewall-address='b' (back to protection),
    # protection=1 again, then complete normally.
    answers = _answers("2", "1", "b", "1", "192.0.2.1", "1", "Lab pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert out.count("Step 2 of 5 -- Protection") == 2
    assert "Address:     https://192.0.2.1" in out


def test_back_at_firewall_returns_to_usage_for_read_only(monkeypatch):
    # usage=1, firewall-address='b' (back to usage, since read-only has
    # no protection step), usage=1 again, then complete normally.
    answers = _answers("1", "b", "1", "192.0.2.1", "1", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert out.count("Step 1 of 4 -- Usage") == 2


def test_quit_at_usage_cancels_cleanly(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_answers("q"))
    assert exit_code == 3
    assert "Setup cancelled." in out
    assert "No changes were made." in out
    assert "Traceback" not in out


def test_quit_at_review_exit_option_cancels_cleanly(monkeypatch):
    # Review's menu is now Generate(1)/Go back(2)/Advanced options(3)/Exit(4).
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "1", "4")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 3
    assert "Setup cancelled." in out


def test_quit_shortcut_at_review_cancels_cleanly(monkeypatch):
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "1", "q")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 3
    assert "Setup cancelled." in out


@pytest.mark.parametrize("truncate_at", [0, 1, 2, 3, 4, 5])
def test_eof_at_every_step_of_the_happy_path_cancels_cleanly(monkeypatch, truncate_at):
    full = ["1", "192.0.2.1", "1", "Home pfSense", "1", "1"]
    answers = _answers(*full[:truncate_at])
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 3
    assert "Setup cancelled." in out
    assert "Traceback" not in out


def test_keyboard_interrupt_during_prompting_cancels_cleanly(monkeypatch):
    class _RaisingStdin(io.StringIO):
        def readline(self, *args, **kwargs):
            raise KeyboardInterrupt

    _clear_relevant_env(monkeypatch)
    out = io.StringIO()
    monkeypatch.setattr("sys.stdin", _RaisingStdin(""))
    monkeypatch.setattr("sys.stdout", out)
    exit_code = main(["setup"])
    assert exit_code == 3
    assert "Setup cancelled." in out.getvalue()
    assert "No changes were made." in out.getvalue()
    assert "Traceback" not in out.getvalue()


def test_review_back_then_modify_then_regenerate(monkeypatch):
    """The exact regression scenario this UX polish task named
    explicitly: Review -> Go back -> change an earlier choice -> return
    to Review -> generate plan -> the resulting plan reflects the
    changed value. Back from Review now lands directly on Connection
    (Advanced options is no longer an intervening step in the main
    sequence), so this no longer needs to navigate through it."""

    answers = _answers(
        "1",  # usage: read-only
        "192.0.2.1",
        "1",  # confirm https
        "Home pfSense",
        "1",  # connection: verify TLS
        "2",  # review: go back -> lands directly on Connection
        "3",  # connection: skip TLS verification
        "1",  # review: generate plan
    )
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Connection:  Skip TLS verification (not recommended)" in out


def test_wizard_signal_string_never_leaks_into_any_output(monkeypatch):
    """Regression guard for the `_WizardSignal.BACK` leakage bug found
    during the previous UX correction (`_WizardSignal` is a `str`
    subclass, so an `isinstance(x, str)` check could not distinguish a
    real value from a BACK/QUIT sentinel -- fixed with explicit `is`
    identity checks everywhere a prompt result is consumed). Exercises
    'b' at the address prompt, the exact path that leaked before, then
    asserts the sentinel's own repr never appears anywhere in output."""

    answers = _answers("1", "b", "1", "192.0.2.1", "1", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "_WizardSignal" not in out
    assert "Address:     https://192.0.2.1" in out


# ===========================================================================
# Address normalization / validation
# ===========================================================================


def test_bare_host_offers_https_confirmation(monkeypatch):
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Use HTTPS?" in out
    assert "Use https://192.0.2.1" in out
    assert "Address:     https://192.0.2.1" in out


def test_address_with_explicit_scheme_skips_https_confirmation(monkeypatch):
    answers = _answers("1", "https://fw.example.test", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Use HTTPS?" not in out
    assert "Address:     https://fw.example.test" in out


def test_malformed_address_reprompts_without_claiming_reachability(monkeypatch):
    answers = _answers("1", "not a valid address", "192.0.2.1", "1", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "That doesn't look like a valid address" in out
    assert "Address:     https://192.0.2.1" in out


def test_declining_https_confirmation_reprompts_for_address(monkeypatch):
    answers = _answers("1", "192.0.2.1", "2", "192.0.2.5", "1", "Home pfSense", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Address:     https://192.0.2.5" in out


# ===========================================================================
# TLS UX
# ===========================================================================


def test_tls_advanced_path_allows_insecure_and_marks_it_not_recommended(monkeypatch):
    """The "Skip TLS verification" option is now a direct top-level
    choice (3), not nested inside a separate "Advanced connection
    settings" submenu -- redesigned to make the private-CA option a
    first-class, directly-chosen alternative alongside it (v1.0.0
    clean-room finding, 2026-08-28)."""
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "3", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Advanced · Not recommended" in out
    assert "Connection:  Skip TLS verification (not recommended)" in out


def test_connection_menu_offers_a_private_ca_option_directly(monkeypatch):
    """v1.0.0 clean-room finding (2026-08-28): a real private-CA pfSense
    LAB target found the wizard had no way to express this at all.
    Choice 2 selects it directly (not buried in "Advanced"); the
    CA-file-path sub-prompt is optional (blank = skip)."""
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "2", "/path/to/lab-ca.crt", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Connection:  Verify TLS certificate (private/internal certificate authority)" in out
    assert "PFSENSE_TLS_CA_FILE" in out
    assert "/path/to/lab-ca.crt" in out
    assert 'PFSENSE_TLS_MODE="auto"' in out or '"PFSENSE_TLS_MODE": "auto"' in out


def test_private_ca_option_ca_file_path_is_optional(monkeypatch):
    """Leaving the CA-file-path prompt blank is a valid, explicitly
    supported skip -- the plan is still generated, with a placeholder
    and guidance shown instead of a personalized path."""
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "2", "", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Connection:  Verify TLS certificate (private/internal certificate authority)" in out
    assert _MCP_CLIENT_CA_FILE_PLACEHOLDER in out


def test_operator_never_types_verify_or_insecure_literal(monkeypatch):
    """Every interactive TLS choice is numeric -- 'verify'/'insecure'
    are never something the operator has to type."""

    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "verify\n" not in out
    assert "insecure\n" not in out


def test_review_wording_for_verify_choice_names_a_future_connection(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "TLS verification will be required when setup connects to pfSense." in out


def test_review_wording_for_insecure_choice_never_claims_verification_is_required(monkeypatch):
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "3", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "TLS verification will be skipped when setup connects to pfSense." in out
    assert "TLS verification will be required" not in out


def test_review_wording_never_implies_a_live_connection_already_happened(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "is verified" not in out.lower()
    assert "was verified" not in out.lower()


# ===========================================================================
# REST version / OpenAPI schema absent from the normal happy path;
# reachable only via the explicit "Advanced options" choice at Review
# ===========================================================================


def test_rest_version_prompt_absent_from_normal_happy_path(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "REST API package version" not in out


def test_openapi_schema_prompt_absent_from_normal_happy_path(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "OpenAPI schema file path" not in out


def test_advanced_options_never_shown_between_connection_and_review(monkeypatch):
    """The exact "must not interrupt the default flow" requirement:
    the normal READ-only path proceeds directly from Connection to
    Review, never stopping at an "Advanced options" menu in between."""

    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    connection_index = out.index("Step 3 of 4 -- Connection")
    review_index = out.index("Step 4 of 4 -- Review")
    between = out[connection_index:review_index]
    assert "Advanced options" not in between
    assert "Configure advanced discovery inputs" not in between


def test_advanced_options_reachable_as_explicit_choice_from_review(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "3) Advanced options" in out


def test_advanced_options_path_configures_schema_and_version(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps({"paths": {}}), encoding="utf-8")
    # connection(1) -> review(3=Advanced options) -> advanced-menu(2=configure)
    # -> version(2.10) -> schema(path) -> [back at review] review(1=generate)
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "1", "3", "2", "2.10", str(schema_file), "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Configure advanced discovery inputs" in out
    assert "setup plan created" in out


def test_advanced_options_reached_from_review_can_be_skipped_with_defaults(monkeypatch):
    # connection(1) -> review(3=Advanced options) -> advanced-menu(1=defaults)
    # -> [back at review, unchanged] review(1=generate)
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "1", "3", "1", "1")
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Continue with recommended defaults" in out
    assert "Mode:        Read-only" in out


def test_advanced_options_configured_values_appear_in_json_output(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps({"paths": {}}), encoding="utf-8")
    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "1", "3", "2", "2.10", str(schema_file), "1")
    exit_code, out = _run(monkeypatch, ["setup", "--json"], stdin_text=answers)
    assert exit_code == 0
    # Interactive + --json still mixes prompt text with the JSON payload
    # on the same stream (a pre-existing, documented limitation of
    # combining the two, not something this task changes) -- extract
    # just the JSON object from the tail of the output.
    json_start = out.index("{\n")
    payload = json.loads(out[json_start:])
    assert payload["version_evidence"]["declared_package_version"] == "2.10.0"
    assert payload["privilege_plan"]["schema_provided"] is True


# ===========================================================================
# Review screen
# ===========================================================================


def test_review_screen_shown_before_plan_generation(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    review_index = out.index("Review setup plan")
    created_index = out.index("setup plan created")
    assert review_index < created_index


def test_review_screen_states_planning_only_and_nothing_changes(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "This is a planning step only." in out
    assert "No pfSense settings, accounts, credentials, or local" in out


def test_review_menu_offers_generate_back_advanced_and_exit_in_order(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "1) Generate plan" in out
    assert "2) Go back and change selections" in out
    assert "3) Advanced options" in out
    assert "4) Exit" in out


# ===========================================================================
# Narrow-terminal rendering
# ===========================================================================


def test_no_wizard_line_is_unreasonably_wide(monkeypatch):
    # The Claude Desktop (JSON) / Codex CLI (TOML) config snippets are
    # exempt: they are meant to be copy-pasted verbatim into a client
    # config file, so they are never word-wrapped, and they legitimately
    # embed a real, resolved absolute filesystem path (e.g. the detected
    # pfsense-mcp-server executable) whose length depends on the host's
    # own install location -- not something this codebase can bound.
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    lines = out.splitlines()
    in_config_snippet = False
    for raw_line in lines:
        if raw_line in ("Claude Desktop (JSON):", "Codex CLI / ChatGPT desktop (shared TOML config):"):
            in_config_snippet = True
            continue
        if in_config_snippet:
            if raw_line == "":
                in_config_snippet = False
            continue
        assert len(raw_line) <= 90, f"line too wide for a narrow terminal: {raw_line!r}"


def test_no_wide_table_or_multi_column_layout(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "\t" not in out
    assert "|" not in out


# ===========================================================================
# Plan ID / digest presentation
# ===========================================================================


def test_human_output_shows_only_a_short_plan_id_not_the_full_digest(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "Plan ID:" in out
    plan_id_line = next(line for line in out.splitlines() if line.startswith("Plan ID:"))
    plan_id = plan_id_line.split("Plan ID:", 1)[1].strip().split()[0]
    assert len(plan_id) == 12
    int(plan_id, 16)  # raises if not hex
    assert "Setup plan digest:" not in out


def test_json_output_still_contains_the_full_64_character_digest(monkeypatch):
    exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"],
    )
    assert exit_code == 0
    payload = json.loads(out)
    assert len(payload["setup_plan_digest"]) == 64


def test_short_plan_id_is_a_prefix_of_the_full_digest(monkeypatch):
    exit_code, human_out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none"],
    )
    assert exit_code == 0
    plan_id_line = next(line for line in human_out.splitlines() if line.startswith("Plan ID:"))
    short_plan_id = plan_id_line.split("Plan ID:", 1)[1].strip().split()[0]

    _exit_code, json_out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--json",
        ],
    )
    full_digest = json.loads(json_out)["setup_plan_digest"]
    assert full_digest.startswith(short_plan_id)


# ===========================================================================
# Non-interactive / JSON compatibility (machine contract unchanged)
# ===========================================================================


def test_non_interactive_still_uses_canonical_enum_names(monkeypatch):
    exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"],
    )
    assert exit_code == 0
    payload = json.loads(out)
    assert payload["privilege_plan"]["intended_capability_posture"] == "read_only"
    assert payload["posture_plan"]["target"]["anchor_assurance"] == "none"


def test_non_interactive_without_required_flags_is_a_usage_error(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "--non-interactive"])
    assert excinfo.value.code == 2


def test_non_interactive_with_only_one_required_flag_is_a_usage_error(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "--non-interactive", "--capability-posture", "read_only"])
    assert excinfo.value.code == 2


def test_non_interactive_never_shows_menu_prompts(monkeypatch):
    exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none"],
    )
    assert exit_code == 0
    assert "Select [" not in out
    assert "Review setup plan" not in out


def test_json_output_is_valid_json_with_no_extra_stdout_noise(monkeypatch):
    exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"],
    )
    assert exit_code == 0
    json.loads(out)


def test_json_output_is_deterministic_and_sorted(monkeypatch):
    argv = ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"]
    _, first = _run(monkeypatch, argv)
    _, second = _run(monkeypatch, argv)
    assert first == second
    payload = json.loads(first)
    assert list(payload.keys()) == sorted(payload.keys())


def test_json_output_includes_the_setup_plan_digest(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"],
    )
    payload = json.loads(out)
    assert len(payload["setup_plan_digest"]) == 64
    assert payload["setup_plan_digest_schema_version"] == 1


def test_interactive_and_non_interactive_produce_the_same_plan_for_equivalent_input(monkeypatch):
    interactive_exit, interactive_out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    non_interactive_exit, non_interactive_out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--target-origin",
            "https://192.0.2.1",
            "--target-identity",
            "Home pfSense",
            "--tls-mode",
            "verify",
            "--json",
        ],
    )
    assert interactive_exit == 0
    assert non_interactive_exit == 0
    non_interactive_payload = json.loads(non_interactive_out)
    assert non_interactive_payload["target"]["origin"] == "https://192.0.2.1"
    assert non_interactive_payload["target"]["identity"] == "Home pfSense"
    assert "Mode:        Read-only" in interactive_out


# ===========================================================================
# Malformed arguments cannot reach mutation code
# ===========================================================================


def test_malformed_capability_posture_choice_is_rejected_by_argparse(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "--non-interactive", "--capability-posture", "not-a-real-posture", "--anchor-assurance", "none"])
    assert excinfo.value.code == 2


def test_malformed_anchor_assurance_choice_is_rejected_by_argparse(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "unknown"])
    assert excinfo.value.code == 2


def test_unknown_flag_is_rejected_by_argparse(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "setup",
                "--non-interactive",
                "--capability-posture",
                "read_only",
                "--anchor-assurance",
                "none",
                "--apply",
            ]
        )
    assert excinfo.value.code == 2


def test_malformed_tls_mode_choice_is_rejected_by_argparse(monkeypatch):
    _clear_relevant_env(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "setup",
                "--non-interactive",
                "--capability-posture",
                "read_only",
                "--anchor-assurance",
                "none",
                "--tls-mode",
                "yolo",
            ]
        )
    assert excinfo.value.code == 2


def test_no_invalid_finite_choice_value_reaches_the_plan_model(monkeypatch):
    """Every interactive menu selection funnels through `_prompt_menu()`,
    which only ever returns a validated index or a `_WizardSignal` --
    never raw operator text. This test drives a hostile sequence of
    garbage at every single menu in the default flow and asserts the
    final plan still only ever contains the two real posture/anchor
    values."""

    answers = _answers(
        "garbage",
        "1",  # usage
        "not-an-address with spaces",
        "192.0.2.1",
        "also garbage",
        "1",  # confirm https
        "Home pfSense",
        "-1",
        "1",  # connection
        "nope",
        "1",  # review
    )
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=answers)
    assert exit_code == 0
    assert "Mode:        Read-only" in out
    assert "garbage" not in out.split("Review setup plan")[-1]


# ===========================================================================
# schema-file: local read only, never a network fetch, fails safely
# ===========================================================================


def test_missing_schema_file_produces_a_warning_and_continues(monkeypatch, tmp_path):
    missing_path = tmp_path / "does-not-exist.json"
    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--schema-file",
            str(missing_path),
        ],
    )
    assert exit_code == 0
    assert "warning: could not read --schema-file" in out


def test_malformed_json_schema_file_produces_a_warning_and_continues(monkeypatch, tmp_path):
    bad_file = tmp_path / "schema.json"
    bad_file.write_text("{not valid json", encoding="utf-8")
    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--schema-file",
            str(bad_file),
        ],
    )
    assert exit_code == 0
    assert "is not valid JSON" in out


def test_non_object_json_schema_file_produces_a_warning_and_continues(monkeypatch, tmp_path):
    array_file = tmp_path / "schema.json"
    array_file.write_text("[1, 2, 3]", encoding="utf-8")
    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--schema-file",
            str(array_file),
        ],
    )
    assert exit_code == 0
    assert "is not a JSON object" in out


def test_valid_schema_file_is_used(monkeypatch, tmp_path):
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps({"paths": {}}), encoding="utf-8")
    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--schema-file",
            str(schema_file),
            "--json",
        ],
    )
    assert exit_code == 0
    payload = json.loads(out)
    assert payload["privilege_plan"]["schema_provided"] is True


# ===========================================================================
# Invalid target combination still exits appropriately
# ===========================================================================


def test_invalid_target_combination_exits_nonzero(monkeypatch):
    exit_code, _out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "write_protected", "--anchor-assurance", "none"],
    )
    assert exit_code == 2


def test_not_yet_implemented_target_still_exits_zero_and_reports_accurately(monkeypatch):
    """`software` anchor assurance is architecturally valid but has no
    implemented backend -- this must never be silently downgraded to
    'blocked' (a usage-shaped failure) or to 'satisfied' (a false
    claim); `plan`'s own BLOCKED_NOT_IMPLEMENTED convention (still exit
    0) is reused verbatim, and human output surfaces it as "Not
    available yet", never "Ready"."""

    exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "software",
        ],
    )
    assert exit_code == 0
    assert "Not available yet" in out


# ===========================================================================
# Secrets are absent from every output surface
# ===========================================================================


def test_no_secret_shaped_env_value_ever_appears_in_json_setup_output(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "hardware_witness",
            "--json",
        ],
        env={"PFSENSE_ADMIN_API_KEY": "totally-secret-value-should-never-appear"},
    )
    assert "totally-secret-value-should-never-appear" not in out


def test_no_secret_shaped_env_value_ever_appears_in_human_setup_output(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "hardware_witness",
        ],
        env={"PFSENSE_ADMIN_API_KEY": "totally-secret-value-should-never-appear"},
    )
    assert "totally-secret-value-should-never-appear" not in out


def test_no_secret_shaped_env_value_ever_appears_in_interactive_wizard_output(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        ["setup"],
        stdin_text=_READ_ONLY_HAPPY_PATH,
        env={"PFSENSE_ADMIN_API_KEY": "totally-secret-value-should-never-appear"},
    )
    assert "totally-secret-value-should-never-appear" not in out


def test_no_secret_shaped_env_value_leaks_through_the_new_private_ca_and_credential_guidance_text(monkeypatch):
    """The v1.0.0 clean-room finding added static credential-file and
    private-CA guidance prose to the wizard's completion screen (see
    _credential_guidance_lines()/_private_ca_guidance_lines()) -- this
    proves that new prose block, specifically, still never echoes an
    unrelated secret-shaped environment value."""

    answers = _answers("1", "192.0.2.1", "1", "Home pfSense", "2", "/path/to/lab-ca.crt", "1")
    _exit_code, out = _run(
        monkeypatch,
        ["setup"],
        stdin_text=answers,
        env={"PFSENSE_ADMIN_API_KEY": "totally-secret-value-should-never-appear"},
    )
    assert "totally-secret-value-should-never-appear" not in out
    assert "Your pfSense target uses a certificate signed by a private" in out


# ===========================================================================
# Isolation: setup never imports the runtime/MCP application
# ===========================================================================


def test_setup_module_never_imports_mcp_application_or_tool_registry():
    import ast
    from pathlib import Path

    root = Path(__file__).parents[1]
    tree = ast.parse((root / "src/pfsense_mcp/security_setup_plan.py").read_text(encoding="utf-8"))
    imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert "application" not in imports
    assert "tools.registry" not in imports
    assert not any(name.startswith("tools.") for name in imports)


# ===========================================================================
# Help text sanity
# ===========================================================================


def test_help_documents_no_setup_apply_and_no_mutation(capsys):
    with pytest.raises(SystemExit):
        main(["setup", "--help"])
    # v1.0.0 Product/UX closure arc (C3): help text now wraps to the
    # terminal width (see _ParagraphHelpFormatter); normalize whitespace
    # before substring matching so this assertion is width-independent.
    out = " ".join(capsys.readouterr().out.split())
    assert "NEVER mutates" in out
    assert "no 'continue and apply' path from this command" in out


def test_top_level_help_lists_setup_and_documents_no_setup_apply(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "setup" in out


# ===========================================================================
# MCP client configuration snippet (Slice 6, print-only)
# ===========================================================================


def test_mcp_client_config_present_in_json_for_a_safe_to_proceed_read_only_plan(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"],
    )
    payload = json.loads(out)
    snippet = payload["mcp_client_config"]
    assert snippet["mcpServers"]["pfsense"]["env"]["PFSENSE_TLS_MODE"] == "strict"
    # v1.0.0 clean-room finding (2026-08-28): the command is now resolved
    # at generation time to the real, currently-installed
    # pfsense-mcp-server executable (see _resolve_mcp_client_command())
    # rather than always being the illustrative placeholder -- in this
    # test's own venv, that means an absolute path ending in the real
    # entry-point name, not the old hardcoded ".venv/bin/..." literal.
    assert snippet["mcpServers"]["pfsense"]["command"].endswith("pfsense-mcp-server")
    assert Path(snippet["mcpServers"]["pfsense"]["command"]).is_absolute()
    assert payload["mcp_client_command_resolved"] is True


def test_mcp_client_config_json_stays_present_but_human_output_omits_it_when_not_safe_to_proceed(monkeypatch):
    """write_protected + none is never a valid ADR-021 target (mutation
    must stay blocked without a witness). `--json` output stays fully
    unabridged (matching this codebase's own "internal identifiers
    remain fully available via --json" convention) -- only human-mode
    output selectively omits the snippet, to avoid printing premature
    connection guidance for a target that cannot actually be used yet."""

    _exit_code, json_out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "none",
            "--json",
        ],
    )
    payload = json.loads(json_out)
    assert payload["posture_plan"]["safe_to_proceed"] is False
    assert payload["mcp_client_config"]["mcpServers"]["pfsense"]["env"]["PFSENSE_IDENTITY"] == "pfsense-mcp"

    _exit_code, human_out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "write_protected", "--anchor-assurance", "none"],
    )
    assert "MCP client configuration" not in human_out
    assert '"mcpServers"' not in human_out


def test_mcp_client_config_uses_service_account_identity_for_write_protected(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "hardware_witness",
            "--target-identity",
            "human-admin-account",
            "--json",
        ],
    )
    payload = json.loads(out)
    if payload["posture_plan"]["safe_to_proceed"]:
        identity = payload["mcp_client_config"]["mcpServers"]["pfsense"]["env"]["PFSENSE_IDENTITY"]
        assert identity == "pfsense-mcp"
        assert identity != "human-admin-account"


def test_mcp_client_config_uses_operator_identity_for_read_only(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--target-identity",
            "my-readonly-key",
            "--json",
        ],
    )
    payload = json.loads(out)
    assert payload["mcp_client_config"]["mcpServers"]["pfsense"]["env"]["PFSENSE_IDENTITY"] == "my-readonly-key"


def test_mcp_client_config_falls_back_to_placeholder_identity_when_none_entered(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"],
    )
    payload = json.loads(out)
    identity = payload["mcp_client_config"]["mcpServers"]["pfsense"]["env"]["PFSENSE_IDENTITY"]
    assert identity == "api-mcp-admin"


def test_mcp_client_config_tls_mode_translates_insecure(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--tls-mode",
            "insecure",
            "--json",
        ],
    )
    payload = json.loads(out)
    assert payload["mcp_client_config"]["mcpServers"]["pfsense"]["env"]["PFSENSE_TLS_MODE"] == "insecure"


def test_mcp_client_config_tls_mode_translates_verify_to_strict(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--tls-mode",
            "verify",
            "--json",
        ],
    )
    payload = json.loads(out)
    assert payload["mcp_client_config"]["mcpServers"]["pfsense"]["env"]["PFSENSE_TLS_MODE"] == "strict"


def test_mcp_client_config_present_in_human_output_with_print_only_disclaimer(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none"],
    )
    assert "MCP client configuration (print-only" in out
    assert "nothing is written to any file" in out
    assert '"mcpServers"' in out


def test_mcp_client_config_never_writes_any_file(monkeypatch, tmp_path):
    before = set(tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)
    _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"],
    )
    _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "hardware_witness",
        ],
    )
    after = set(tmp_path.iterdir())
    assert before == after


def test_no_secret_shaped_env_value_ever_appears_in_the_mcp_client_config_snippet(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "hardware_witness",
            "--json",
        ],
        env={"PFSENSE_ADMIN_API_KEY": "totally-secret-value-should-never-appear"},
    )
    assert "totally-secret-value-should-never-appear" not in out


def test_mcp_client_config_snippet_matches_the_documented_examples_shape(monkeypatch):
    """Structural proof the generated snippet is exactly the shape
    `examples/claude-desktop.md` already documents -- one server named
    'pfsense', with exactly `command` + `env`, and exactly the four
    PFSENSE_* env vars that example already shows."""

    _exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"],
    )
    payload = json.loads(out)
    servers = payload["mcp_client_config"]["mcpServers"]
    assert set(servers) == {"pfsense"}
    assert set(servers["pfsense"]) == {"command", "env"}
    assert set(servers["pfsense"]["env"]) == {
        "PFSENSE_API_URL",
        "PFSENSE_IDENTITY",
        "PFSENSE_API_KEY_FILE",
        "PFSENSE_TLS_MODE",
    }


# ===========================================================================
# MCP client configuration: TOML form (Codex CLI / ChatGPT desktop)
#
# examples/codex-cli.md and examples/chatgpt.md both document a TOML
# config format (`~/.codex/config.toml`, shared by both clients per
# chatgpt.md's own text), not the JSON `mcpServers` block Claude
# Desktop uses -- discovered during this run's own Phase A4 live/local
# client-config validation pass. Printing JSON for Codex/ChatGPT would
# be unusable as-is, so a second, genuinely different-format snippet is
# generated alongside the JSON one, sharing the same env values.
# ===========================================================================


def test_mcp_client_config_toml_present_in_json_output(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none", "--json"],
    )
    payload = json.loads(out)
    assert "mcp_client_config_toml" in payload
    assert "[mcp_servers.pfsense]" in payload["mcp_client_config_toml"]
    assert "[mcp_servers.pfsense.env]" in payload["mcp_client_config_toml"]


def test_mcp_client_config_toml_parses_as_valid_toml_and_matches_json_values(monkeypatch):
    import tomllib

    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--target-identity",
            "my-readonly-key",
            "--target-origin",
            "https://pfsense.lab.example",
            "--json",
        ],
    )
    payload = json.loads(out)
    parsed = tomllib.loads(payload["mcp_client_config_toml"])
    toml_server = parsed["mcp_servers"]["pfsense"]
    json_server = payload["mcp_client_config"]["mcpServers"]["pfsense"]
    assert toml_server["command"] == json_server["command"]
    assert toml_server["required"] is True
    assert toml_server["env"] == json_server["env"]
    assert toml_server["env"]["PFSENSE_IDENTITY"] == "my-readonly-key"


def test_mcp_client_config_toml_escapes_special_characters_and_still_parses(monkeypatch):
    import tomllib

    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "read_only",
            "--anchor-assurance",
            "none",
            "--target-identity",
            'weird"quote\\and\\backslash',
            "--json",
        ],
    )
    payload = json.loads(out)
    parsed = tomllib.loads(payload["mcp_client_config_toml"])
    assert parsed["mcp_servers"]["pfsense"]["env"]["PFSENSE_IDENTITY"] == 'weird"quote\\and\\backslash'


def test_mcp_client_config_toml_present_in_human_output_with_correct_label(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "read_only", "--anchor-assurance", "none"],
    )
    assert "Claude Desktop (JSON):" in out
    assert "Codex CLI / ChatGPT desktop (shared TOML config):" in out
    assert "[mcp_servers.pfsense]" in out
    assert "required = true" in out


def test_mcp_client_config_toml_absent_from_human_output_when_not_safe_to_proceed(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        ["setup", "--non-interactive", "--capability-posture", "write_protected", "--anchor-assurance", "none"],
    )
    assert "[mcp_servers.pfsense]" not in out
    assert "Codex CLI / ChatGPT desktop" not in out


def test_mcp_client_config_toml_uses_service_account_identity_for_write_protected(monkeypatch):
    import tomllib

    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "hardware_witness",
            "--target-identity",
            "human-admin-account",
            "--json",
        ],
    )
    payload = json.loads(out)
    if payload["posture_plan"]["safe_to_proceed"]:
        parsed = tomllib.loads(payload["mcp_client_config_toml"])
        identity = parsed["mcp_servers"]["pfsense"]["env"]["PFSENSE_IDENTITY"]
        assert identity == "pfsense-mcp"
        assert identity != "human-admin-account"


def test_no_secret_shaped_env_value_ever_appears_in_the_mcp_client_config_toml(monkeypatch):
    _exit_code, out = _run(
        monkeypatch,
        [
            "setup",
            "--non-interactive",
            "--capability-posture",
            "write_protected",
            "--anchor-assurance",
            "hardware_witness",
            "--json",
        ],
        env={"PFSENSE_ADMIN_API_KEY": "totally-secret-value-should-never-appear"},
    )
    assert "totally-secret-value-should-never-appear" not in out


# ===========================================================================
# _resolve_mcp_client_command() -- isolated (v1.0.0 clean-room finding:
# pipx/executable-path coherence)
# ===========================================================================


def test_resolve_command_explicit_override_always_wins(monkeypatch, tmp_path):
    # Even when a colocated executable genuinely exists, an explicit
    # --command override must never be second-guessed or re-detected.
    fake_python = tmp_path / "bin" / "python3"
    fake_python.parent.mkdir(parents=True)
    fake_python.touch()
    (tmp_path / "bin" / "pfsense-mcp-server").touch()
    monkeypatch.setattr(sys, "executable", str(fake_python))
    command, resolved = _resolve_mcp_client_command("/opt/custom/pfsense-mcp-server")
    assert command == "/opt/custom/pfsense-mcp-server"
    assert resolved is True


def test_resolve_command_finds_executable_colocated_with_sys_executable(monkeypatch, tmp_path):
    fake_python = tmp_path / "bin" / "python3"
    fake_python.parent.mkdir(parents=True)
    fake_python.touch()
    sibling = tmp_path / "bin" / "pfsense-mcp-server"
    sibling.touch()
    monkeypatch.setattr(sys, "executable", str(fake_python))
    command, resolved = _resolve_mcp_client_command(None)
    assert command == str(sibling)
    assert resolved is True


def test_resolve_command_falls_back_to_which_when_not_colocated(monkeypatch, tmp_path):
    fake_python = tmp_path / "bin" / "python3"
    fake_python.parent.mkdir(parents=True)
    fake_python.touch()
    monkeypatch.setattr(sys, "executable", str(fake_python))
    monkeypatch.setattr("pfsense_mcp.security_cli.shutil.which", lambda name: "/usr/local/bin/pfsense-mcp-server")
    command, resolved = _resolve_mcp_client_command(None)
    assert command == "/usr/local/bin/pfsense-mcp-server"
    assert resolved is True


def test_resolve_command_falls_back_to_placeholder_when_nothing_found(monkeypatch, tmp_path):
    fake_python = tmp_path / "bin" / "python3"
    fake_python.parent.mkdir(parents=True)
    fake_python.touch()
    monkeypatch.setattr(sys, "executable", str(fake_python))
    monkeypatch.setattr("pfsense_mcp.security_cli.shutil.which", lambda name: None)
    command, resolved = _resolve_mcp_client_command(None)
    assert command == _MCP_CLIENT_COMMAND_PLACEHOLDER
    assert resolved is False


# ===========================================================================
# Public-CA (verify) path never emits PFSENSE_TLS_CA_FILE
# ===========================================================================


def test_public_ca_verify_path_never_emits_a_ca_file_env_var(monkeypatch):
    exit_code, out = _run(monkeypatch, ["setup"], stdin_text=_READ_ONLY_HAPPY_PATH)
    assert exit_code == 0
    assert "PFSENSE_TLS_CA_FILE" not in out
    assert '"PFSENSE_TLS_MODE": "strict"' in out or 'PFSENSE_TLS_MODE="strict"' in out
