from write_capability_check import find_active_write_capabilities, main


def test_finds_zero_active_write_capabilities():
    assert find_active_write_capabilities() == []


def test_main_passes_against_the_real_capabilities_and_profiles():
    assert main() == 0
