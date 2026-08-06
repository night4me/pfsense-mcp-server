from write_allow_list_check import find_write_endpoint_entries, main


def test_finds_zero_entries_against_the_real_write_endpoints():
    assert find_write_endpoint_entries() == []


def test_main_passes_against_the_real_write_endpoints():
    assert main() == 0
