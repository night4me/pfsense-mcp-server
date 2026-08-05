#!/usr/bin/env python3
"""validate_junit.py — derives several validation stages from a single
pytest --junit-xml report, instead of re-running pytest once per stage.

Stages:
  live-skip            every test in a test_live_*.py file is "skipped"
                        (never "passed" — that would mean live tests
                        actually ran without an explicit opt-in)
  endpoint-registry     every test in test_endpoints_verified.py passed
  profile-registration  every test in test_profiles.py / test_tool_registry.py passed
  get-only              test_post_is_rejected_as_unsupported passed
  query-param           the URL-encoding and limit-boundary tests passed

Read-only: only reads the given XML file. Exits 0 or 1.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CaseResult:
    classname: str
    name: str
    outcome: str  # "passed" | "skipped" | "failed" | "error"


def parse_junit(path: Path) -> list[CaseResult]:
    root = ET.parse(path).getroot()
    results = []
    for testcase in root.iter("testcase"):
        outcome = "passed"
        for child_tag, child_outcome in (("skipped", "skipped"), ("failure", "failed"), ("error", "error")):
            if testcase.find(child_tag) is not None:
                outcome = child_outcome
                break
        results.append(
            CaseResult(
                classname=testcase.get("classname", ""),
                name=testcase.get("name", ""),
                outcome=outcome,
            )
        )
    return results


def _select(results: list[CaseResult], *, classname_contains: str) -> list[CaseResult]:
    return [r for r in results if classname_contains in r.classname]


def _select_names(results: list[CaseResult], names: set[str]) -> list[CaseResult]:
    return [r for r in results if r.name in names]


def check_live_skip(results: list[CaseResult]) -> list[str]:
    matched = _select(results, classname_contains="test_live_")
    if not matched:
        return ["no test_live_*.py test cases found in the report"]
    return [f"{r.classname}::{r.name} was '{r.outcome}', expected 'skipped'" for r in matched if r.outcome != "skipped"]


def check_endpoint_registry(results: list[CaseResult]) -> list[str]:
    matched = _select(results, classname_contains="test_endpoints_verified")
    if not matched:
        return ["no test_endpoints_verified.py test cases found in the report"]
    return [f"{r.classname}::{r.name} was '{r.outcome}', expected 'passed'" for r in matched if r.outcome != "passed"]


def check_profile_registration(results: list[CaseResult]) -> list[str]:
    matched = _select(results, classname_contains="test_profiles") + _select(
        results, classname_contains="test_tool_registry"
    )
    if not matched:
        return ["no test_profiles.py / test_tool_registry.py test cases found in the report"]
    return [f"{r.classname}::{r.name} was '{r.outcome}', expected 'passed'" for r in matched if r.outcome != "passed"]


def check_get_only(results: list[CaseResult]) -> list[str]:
    matched = _select_names(results, {"test_post_is_rejected_as_unsupported"})
    if not matched:
        return ["test_post_is_rejected_as_unsupported not found in the report"]
    return [f"{r.classname}::{r.name} was '{r.outcome}', expected 'passed'" for r in matched if r.outcome != "passed"]


_QUERY_PARAM_TEST_NAMES = {
    "test_get_with_params_appends_query_string",
    "test_get_without_params_has_no_query_string",
    "test_get_with_empty_params_has_no_query_string",
    "test_get_firewall_states_passes_custom_limit_in_query_string",
    "test_get_firewall_states_rejects_zero_limit",
    "test_get_firewall_states_rejects_negative_limit",
    "test_get_firewall_states_rejects_limit_above_max",
    "test_get_firewall_states_accepts_max_limit_boundary",
    "test_get_firewall_states_accepts_min_limit_boundary",
    "test_get_firewall_states_accepts_mid_range_limit",
    "test_get_firewall_states_rejects_limit_just_above_max",
    "test_get_firewall_states_invalid_limit_never_calls_transport",
}


def check_query_param(results: list[CaseResult]) -> list[str]:
    matched = _select_names(results, _QUERY_PARAM_TEST_NAMES)
    missing = _QUERY_PARAM_TEST_NAMES - {r.name for r in matched}
    failures = [f"{name}: not found in the report" for name in sorted(missing)]
    failures.extend(
        f"{r.classname}::{r.name} was '{r.outcome}', expected 'passed'" for r in matched if r.outcome != "passed"
    )
    return failures


_STAGES = {
    "live-skip": check_live_skip,
    "endpoint-registry": check_endpoint_registry,
    "profile-registration": check_profile_registration,
    "get-only": check_get_only,
    "query-param": check_query_param,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--stage", required=True, choices=sorted(_STAGES))
    args = parser.parse_args(argv)

    if not args.report.is_file():
        print(f"validate_junit: report file not found: {args.report}", file=sys.stderr)
        return 1

    results = parse_junit(args.report)
    failures = _STAGES[args.stage](results)

    if failures:
        print(f"validate_junit ({args.stage}): FAILED", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1

    print(f"validate_junit ({args.stage}): OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
