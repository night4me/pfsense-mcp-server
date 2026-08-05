"""Unit tests for scripts/validate_junit.py, using synthetic JUnit XML
rather than a real pytest run's report."""

from __future__ import annotations

from validate_junit import (
    CaseResult,
    check_endpoint_registry,
    check_get_only,
    check_live_skip,
    check_profile_registration,
    check_query_param,
    parse_junit,
)


def _write_junit(tmp_path, testcases_xml: str):
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" tests="1">
    {testcases_xml}
  </testsuite>
</testsuites>
"""
    path = tmp_path / "report.xml"
    path.write_text(xml)
    return path


def test_parse_junit_reads_passed_case(tmp_path):
    path = _write_junit(tmp_path, '<testcase classname="tests.test_foo" name="test_bar" time="0.01"/>')
    results = parse_junit(path)
    assert results == [CaseResult(classname="tests.test_foo", name="test_bar", outcome="passed")]


def test_parse_junit_reads_skipped_case(tmp_path):
    path = _write_junit(
        tmp_path,
        '<testcase classname="tests.test_foo" name="test_bar"><skipped message="skip"/></testcase>',
    )
    results = parse_junit(path)
    assert results[0].outcome == "skipped"


def test_parse_junit_reads_failed_case(tmp_path):
    path = _write_junit(
        tmp_path,
        '<testcase classname="tests.test_foo" name="test_bar"><failure message="boom"/></testcase>',
    )
    results = parse_junit(path)
    assert results[0].outcome == "failed"


def test_check_live_skip_flags_a_live_test_that_actually_passed():
    results = [CaseResult("tests.test_live_firewall", "test_x", "passed")]
    failures = check_live_skip(results)
    assert failures != []
    assert "expected 'skipped'" in failures[0]


def test_check_live_skip_passes_when_all_live_tests_skipped():
    results = [
        CaseResult("tests.test_live_firewall", "test_x", "skipped"),
        CaseResult("tests.test_live_gateways", "test_y", "skipped"),
    ]
    assert check_live_skip(results) == []


def test_check_live_skip_flags_no_live_tests_found():
    results = [CaseResult("tests.test_other", "test_x", "passed")]
    failures = check_live_skip(results)
    assert "no test_live_*.py test cases found" in failures[0]


def test_check_endpoint_registry_confirms_all_passed():
    results = [
        CaseResult("tests.test_endpoints_verified", "test_a", "passed"),
        CaseResult("tests.test_endpoints_verified", "test_b", "passed"),
    ]
    assert check_endpoint_registry(results) == []


def test_check_endpoint_registry_flags_a_failure():
    results = [CaseResult("tests.test_endpoints_verified", "test_a", "failed")]
    failures = check_endpoint_registry(results)
    assert failures != []


def test_check_profile_registration_covers_both_files():
    results = [
        CaseResult("tests.test_profiles", "test_a", "passed"),
        CaseResult("tests.test_tool_registry", "test_b", "passed"),
    ]
    assert check_profile_registration(results) == []


def test_check_get_only_flags_missing_test():
    assert check_get_only([]) == ["test_post_is_rejected_as_unsupported not found in the report"]


def test_check_get_only_passes_when_present_and_passed():
    results = [CaseResult("tests.test_rest_api_client", "test_post_is_rejected_as_unsupported", "passed")]
    assert check_get_only(results) == []


def test_check_query_param_flags_missing_boundary_tests():
    results = [
        CaseResult("tests.test_pfsense_client", "test_get_firewall_states_rejects_zero_limit", "passed"),
    ]
    failures = check_query_param(results)
    assert any("not found in the report" in f for f in failures)


def test_check_query_param_passes_when_all_present_and_passed():
    from validate_junit import _QUERY_PARAM_TEST_NAMES

    results = [CaseResult("tests.test_pfsense_client", name, "passed") for name in _QUERY_PARAM_TEST_NAMES]
    assert check_query_param(results) == []
