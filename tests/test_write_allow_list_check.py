from write_allow_list_check import (
    EXPECTED_ACTIVE_ENTRIES,
    find_allow_list_violations,
    find_write_endpoint_entries,
    main,
)


def test_finds_exactly_the_expected_entry_against_the_real_write_endpoints():
    assert set(find_write_endpoint_entries()) == set(EXPECTED_ACTIVE_ENTRIES)


def test_main_passes_against_the_real_write_endpoints():
    assert main() == 0


def test_find_allow_list_violations_flags_unexpected_entries(monkeypatch):
    import write_allow_list_check

    monkeypatch.setattr(
        write_allow_list_check, "find_write_endpoint_entries", lambda: ["FIREWALL_ALIAS_DESCRIPTION", "SOMETHING_ELSE"]
    )
    violations = find_allow_list_violations()
    assert any("unexpected" in v and "SOMETHING_ELSE" in v for v in violations)


def test_find_allow_list_violations_flags_missing_expected_entry(monkeypatch):
    import write_allow_list_check

    monkeypatch.setattr(write_allow_list_check, "find_write_endpoint_entries", lambda: [])
    violations = find_allow_list_violations()
    assert any("missing" in v and "FIREWALL_ALIAS_DESCRIPTION" in v for v in violations)
