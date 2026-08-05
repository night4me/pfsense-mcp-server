"""Sanity tests for the CAPTURE_POLICIES registry itself."""

from __future__ import annotations

import pytest
from lib.capture_policies import CAPTURE_POLICIES, BoundedInt, CapturePolicy, get_policy

from pfsense_mcp.endpoints import Endpoints


def test_every_policy_key_matches_its_own_endpoint_attr():
    for key, policy in CAPTURE_POLICIES.items():
        assert key == policy.endpoint_attr


def test_every_policy_endpoint_attr_exists_and_is_verified():
    for policy in CAPTURE_POLICIES.values():
        endpoint = getattr(Endpoints, policy.endpoint_attr)
        assert endpoint.verified is True


def test_every_policy_has_a_valid_result_shape():
    for policy in CAPTURE_POLICIES.values():
        assert policy.result_shape in ("list", "object")


def test_bounded_int_rejects_inverted_bounds():
    with pytest.raises(ValueError):
        BoundedInt(minimum=10, maximum=1)


def test_bounded_int_validate():
    bound = BoundedInt(minimum=1, maximum=500)
    assert bound.validate(1)
    assert bound.validate(500)
    assert not bound.validate(0)
    assert not bound.validate(501)
    assert not bound.validate(-5)


def test_firewall_states_policy_excludes_zero_as_unlimited():
    """pfSense's own API treats limit=0 as 'no limit' — the capture
    policy's minimum=1 must exclude that value entirely."""
    policy = get_policy("FIREWALL_STATES")
    assert policy is not None
    bound = policy.allowed_params["limit"]
    assert not bound.validate(0)


def test_capture_policy_rejects_unknown_endpoint_attr():
    with pytest.raises(ValueError):
        CapturePolicy(endpoint_attr="NOT_A_REAL_ENDPOINT", result_shape="list")


def test_capture_policy_rejects_invalid_result_shape():
    with pytest.raises(ValueError):
        CapturePolicy(endpoint_attr="SYSTEM_STATUS", result_shape="banana")


def test_get_policy_returns_none_for_unknown_name():
    assert get_policy("NOT_A_REAL_ENDPOINT") is None
