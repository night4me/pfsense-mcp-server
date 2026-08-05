"""Unit tests for scripts/bounded_params_check.py, using synthetic
source text rather than the real pfsense_client.py file."""

from __future__ import annotations

from bounded_params_check import BoundedParameter, check_bounded_parameter

_PARAM = BoundedParameter(
    method_name="get_widgets",
    param_name="limit",
    min_constant="WIDGET_MIN_LIMIT",
    max_constant="WIDGET_MAX_LIMIT",
)

_GOOD_SOURCE = """
WIDGET_MIN_LIMIT = 1
WIDGET_MAX_LIMIT = 500


class PfSenseClient:
    def get_widgets(self, *, limit: int = 100):
        if not (WIDGET_MIN_LIMIT <= limit <= WIDGET_MAX_LIMIT):
            raise PfSenseRequestValidationError("out of range")
        return self._rest.get(Endpoints.WIDGETS, params={"limit": limit})

    def get_other(self):
        return self._rest.get(Endpoints.OTHER)
"""


def test_passes_for_known_firewall_states_limit_pattern():
    assert check_bounded_parameter(_GOOD_SOURCE, _PARAM) == []


def test_flags_missing_max_constant():
    source = _GOOD_SOURCE.replace("WIDGET_MAX_LIMIT = 500\n", "")
    failures = check_bounded_parameter(source, _PARAM)
    assert any("WIDGET_MAX_LIMIT is not defined" in f for f in failures)


def test_flags_missing_min_constant():
    source = _GOOD_SOURCE.replace("WIDGET_MIN_LIMIT = 1\n", "")
    failures = check_bounded_parameter(source, _PARAM)
    assert any("WIDGET_MIN_LIMIT is not defined" in f for f in failures)


def test_flags_method_not_found():
    source = _GOOD_SOURCE.replace("def get_widgets", "def get_widgets_renamed")
    failures = check_bounded_parameter(source, _PARAM)
    assert any("not found" in f for f in failures)


def test_flags_method_that_never_raises():
    source = """
WIDGET_MIN_LIMIT = 1
WIDGET_MAX_LIMIT = 500


class PfSenseClient:
    def get_widgets(self, *, limit: int = 100):
        return self._rest.get(Endpoints.WIDGETS, params={"limit": limit})
"""
    failures = check_bounded_parameter(source, _PARAM)
    assert any("no validation raise" in f for f in failures)


def test_flags_method_that_does_not_reference_constants():
    source = """
WIDGET_MIN_LIMIT = 1
WIDGET_MAX_LIMIT = 500


class PfSenseClient:
    def get_widgets(self, *, limit: int = 100):
        if limit <= 0:
            raise PfSenseRequestValidationError("bad")
        return self._rest.get(Endpoints.WIDGETS, params={"limit": limit})
"""
    failures = check_bounded_parameter(source, _PARAM)
    assert any("does not reference both" in f for f in failures)
