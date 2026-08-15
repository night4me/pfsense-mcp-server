import write_capability_check
from write_capability_check import (
    find_default_safety_violations,
    find_scope_creep,
    implemented_write_capabilities,
    main,
)

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.profiles import Profile


def test_finds_zero_default_safety_violations_against_real_profiles():
    assert find_default_safety_violations() == []


def test_finds_zero_scope_creep_against_real_profiles():
    assert find_scope_creep() == []


def test_implemented_write_capabilities_matches_the_real_supported_set():
    assert implemented_write_capabilities() == []


def test_main_passes_against_the_real_capabilities_and_profiles():
    assert main() == 0


def test_default_safety_violation_detected_if_auditor_profile_grants_write(monkeypatch):
    monkeypatch.setattr(
        write_capability_check,
        "AuditorProfile",
        Profile(name="auditor", capabilities=frozenset({Capability.ALIAS_WRITE})),
    )
    findings = find_default_safety_violations()
    assert any("ALIAS_WRITE is in AuditorProfile.capabilities" in f for f in findings)
    assert main() == 1


def test_default_safety_violation_detected_if_engineer_profile_grants_write(monkeypatch):
    monkeypatch.setattr(
        write_capability_check,
        "EngineerProfile",
        Profile(name="engineer", capabilities=frozenset({Capability.SERVICE_WRITE})),
    )
    findings = find_default_safety_violations()
    assert any("SERVICE_WRITE is in EngineerProfile.capabilities" in f for f in findings)
    assert main() == 1


def test_scope_creep_detected_if_write_protected_grants_an_unaccepted_capability(monkeypatch):
    monkeypatch.setattr(
        write_capability_check,
        "WriteProtectedProfile",
        Profile(
            name="write_protected",
            capabilities=frozenset({Capability.ALIAS_WRITE, Capability.FIREWALL_WRITE}),
        ),
    )
    findings = find_scope_creep()
    assert any("FIREWALL_WRITE" in f and "not part of the accepted grant" in f for f in findings)
    assert main() == 1


def test_write_protected_granting_exactly_the_accepted_capability_is_not_scope_creep():
    assert find_scope_creep() == []


def test_implemented_reports_a_capability_added_to_supported_without_failing(monkeypatch):
    from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD

    monkeypatch.setattr(
        write_capability_check,
        "SUPPORTED_CAPABILITIES_THIS_BUILD",
        SUPPORTED_CAPABILITIES_THIS_BUILD | {Capability.ALIAS_WRITE},
    )
    assert implemented_write_capabilities() == ["ALIAS_WRITE"]
    # "Implemented" alone is not a default-safety violation or scope creep --
    # AuditorProfile/EngineerProfile/WriteProtectedProfile are untouched by
    # this monkeypatch, so the check must still pass.
    assert main() == 0
