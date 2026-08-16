"""ADR-029: tier1/acceptance.py's AcceptanceExecutionContext and
issue_acceptance_context()."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.config import PfSenseConfig
from pfsense_mcp.profiles import AuditorProfile
from pfsense_mcp.tier1.acceptance import AcceptanceExecutionContext, issue_acceptance_context
from pfsense_mcp.tier1.errors import AcceptanceError
from pfsense_mcp.tls import TLSMode
from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints

_LAB_URL = "https://pfsense-test.lab.invalid"
_LAB_IDENTITY = "pfsense_lab1"


def _config(*, base_url: str = _LAB_URL, identity: str = _LAB_IDENTITY) -> PfSenseConfig:
    return PfSenseConfig(
        base_url=base_url,
        identity=identity,
        key_file=None,
        tls_mode=TLSMode.INSECURE,
        tls_ca_file=None,
        api_version=ApiVersion.V2,
        profile=AuditorProfile,
        log_max_bytes=5_000_000,
        log_backup_count=5,
    )


def _register_test_endpoint(monkeypatch, **overrides):
    defaults = {
        "path_suffix": "/example",
        "http_method": "PATCH",
        "verified": False,
        "min_api_version": ApiVersion.V2,
        "reversible": True,
        "dry_run_supported": True,
        "acceptance_eligible": True,
    }
    defaults.update(overrides)
    monkeypatch.setattr(WriteEndpoints, "TEST_ONLY_ENDPOINT", WriteEndpointInfo(**defaults), raising=False)


# -- issue_acceptance_context() ------------------------------------------


def test_issues_a_context_for_the_real_lab_target_and_endpoint():
    context = issue_acceptance_context(_config())

    assert context.endpoint_symbol == "FIREWALL_ALIAS_DESCRIPTION"
    assert context.http_method == "PATCH"
    assert context.target_identity == _LAB_IDENTITY
    assert context.issued_at.tzinfo is not None


def test_refuses_production_target():
    with pytest.raises(AcceptanceError, match="LAB-only"):
        issue_acceptance_context(_config(base_url="https://pfsense.example.invalid"))


def test_refuses_wrong_identity():
    with pytest.raises(AcceptanceError, match="pfsense_lab1-only"):
        issue_acceptance_context(_config(identity="some-other-identity"))


def test_refuses_unknown_endpoint():
    with pytest.raises(AcceptanceError, match="not in the write allow-list"):
        issue_acceptance_context(_config(), endpoint_symbol="NOT_ALLOW_LISTED")


def test_refuses_endpoint_not_acceptance_eligible(monkeypatch):
    _register_test_endpoint(monkeypatch, acceptance_eligible=False)
    with pytest.raises(AcceptanceError, match="not acceptance_eligible=True"):
        issue_acceptance_context(_config(), endpoint_symbol="TEST_ONLY_ENDPOINT")


def test_refuses_already_verified_endpoint(monkeypatch):
    _register_test_endpoint(monkeypatch, verified=True)
    with pytest.raises(AcceptanceError, match="already verified=True"):
        issue_acceptance_context(_config(), endpoint_symbol="TEST_ONLY_ENDPOINT")


def test_real_endpoint_is_still_unverified_today():
    """Belt-and-braces: if this ever starts failing, it means
    FIREWALL_ALIAS_DESCRIPTION.verified flipped to True without anyone
    updating this test's assumption -- a signal worth surfacing loudly
    rather than silently succeeding either way."""

    assert WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.verified is False
    issue_acceptance_context(_config())  # must not raise


# -- AcceptanceExecutionContext.__post_init__ ----------------------------


def _now():
    return datetime.now(timezone.utc)


def test_rejects_empty_endpoint_symbol():
    with pytest.raises(AcceptanceError):
        AcceptanceExecutionContext(
            endpoint_symbol="", http_method="PATCH", target_identity=_LAB_IDENTITY, issued_at=_now()
        )


def test_rejects_empty_http_method():
    with pytest.raises(AcceptanceError):
        AcceptanceExecutionContext(
            endpoint_symbol="FIREWALL_ALIAS_DESCRIPTION",
            http_method="",
            target_identity=_LAB_IDENTITY,
            issued_at=_now(),
        )


def test_rejects_non_lab_target_identity():
    with pytest.raises(AcceptanceError):
        AcceptanceExecutionContext(
            endpoint_symbol="FIREWALL_ALIAS_DESCRIPTION",
            http_method="PATCH",
            target_identity="production-admin",
            issued_at=_now(),
        )


def test_rejects_naive_issued_at():
    with pytest.raises(AcceptanceError):
        AcceptanceExecutionContext(
            endpoint_symbol="FIREWALL_ALIAS_DESCRIPTION",
            http_method="PATCH",
            target_identity=_LAB_IDENTITY,
            issued_at=datetime.now(),
        )


def test_rejects_non_utc_issued_at():
    tz = timezone(timedelta(hours=5))
    with pytest.raises(AcceptanceError):
        AcceptanceExecutionContext(
            endpoint_symbol="FIREWALL_ALIAS_DESCRIPTION",
            http_method="PATCH",
            target_identity=_LAB_IDENTITY,
            issued_at=datetime.now(tz),
        )


# -- is_fresh() ------------------------------------------------------------


def test_is_fresh_true_immediately_after_issuance():
    context = issue_acceptance_context(_config())
    assert context.is_fresh(now=context.issued_at) is True


def test_is_fresh_false_far_in_the_future():
    context = issue_acceptance_context(_config())
    assert context.is_fresh(now=context.issued_at + timedelta(hours=6)) is False


def test_is_fresh_false_before_issuance():
    context = issue_acceptance_context(_config())
    assert context.is_fresh(now=context.issued_at - timedelta(minutes=1)) is False


def test_is_fresh_requires_utc_now():
    context = issue_acceptance_context(_config())
    with pytest.raises(AcceptanceError):
        context.is_fresh(now=datetime.now())
