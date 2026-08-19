"""Offline tests for the closed ADR-033 authentication transition."""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass

import pytest

from pfsense_mcp.security_auth_transition import (
    AuthMethodTransitionCoordinator,
    AuthTransitionState,
    MutationDelivery,
    ReconnectPolicy,
    TransitionFinding,
)
from pfsense_mcp.transport.base import (
    TransportConnectionError,
    TransportRequestNotSentError,
    TransportResponse,
    TransportTimeoutError,
)

_SETTINGS = "/api/v2/system/restapi/settings"
_USERS = "/api/v2/users"
_KEY_ONLY = ["KeyAuth"]
_ENABLED = ["KeyAuth", "BasicAuth"]


def _settings(methods: list[str], *, marker: str = "preserved") -> TransportResponse:
    return TransportResponse(200, json.dumps({"data": {"auth_methods": methods, "marker": marker}}))


def _patch_response(methods: list[str]) -> TransportResponse:
    return TransportResponse(200, json.dumps({"data": {"auth_methods": methods}}))


def _users() -> TransportResponse:
    return TransportResponse(200, json.dumps({"data": []}))


@dataclass
class _Step:
    outcome: TransportResponse | Exception
    expected_method: str
    expected_path: str
    expected_body: bytes | None = None


class _OneShotTransport:
    def __init__(self, step: _Step, calls: list[tuple[str, str, bytes | None]]) -> None:
        self._step = step
        self._calls = calls
        self.closed = False

    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        self._calls.append((method, path, body))
        assert (method, path, body) == (
            self._step.expected_method,
            self._step.expected_path,
            self._step.expected_body,
        )
        if isinstance(self._step.outcome, Exception):
            raise self._step.outcome
        return self._step.outcome

    def close(self) -> None:
        self.closed = True


class _Factory:
    def __init__(self, steps: list[_Step | Exception]) -> None:
        self.steps = deque(steps)
        self.calls: list[tuple[str, str, bytes | None]] = []
        self.transports: list[_OneShotTransport] = []

    def __call__(self) -> _OneShotTransport:
        if not self.steps:
            raise AssertionError("unexpected fresh transport")
        item = self.steps.popleft()
        if isinstance(item, Exception):
            raise item
        transport = _OneShotTransport(item, self.calls)
        self.transports.append(transport)
        return transport


def _get(outcome: TransportResponse | Exception) -> _Step:
    return _Step(outcome, "GET", _SETTINGS)


def _enable(outcome: TransportResponse | Exception) -> _Step:
    return _Step(outcome, "PATCH", _SETTINGS, b'{"auth_methods":["KeyAuth","BasicAuth"]}')


def _restore(outcome: TransportResponse | Exception) -> _Step:
    return _Step(outcome, "PATCH", _SETTINGS, b'{"auth_methods":["KeyAuth"]}')


def _basic(outcome: TransportResponse | Exception) -> _Step:
    return _Step(outcome, "GET", _USERS)


def _coordinator(
    key_steps: list[_Step | Exception],
    basic_steps: list[_Step | Exception] | None = None,
    *,
    attempts: int = 3,
) -> tuple[AuthMethodTransitionCoordinator, _Factory, _Factory]:
    key = _Factory(key_steps)
    basic = _Factory(basic_steps or [])
    coordinator = AuthMethodTransitionCoordinator(
        keyauth_transport_factory=key,
        basicauth_transport_factory=basic,
        reconnect_policy=ReconnectPolicy(maximum_attempts=attempts, delay_seconds=0),
        sleeper=lambda _: None,
    )
    return coordinator, key, basic


def _confirmed_coordinator(
    restore_steps: list[_Step | Exception], *, attempts: int = 3
) -> tuple[AuthMethodTransitionCoordinator, _Factory]:
    coordinator, key, _ = _coordinator(
        [_get(_settings(_KEY_ONLY)), _enable(_patch_response(_ENABLED)), _get(_settings(_ENABLED)), *restore_steps],
        attempts=attempts,
    )
    assert coordinator.enable_basic_auth().state is AuthTransitionState.BASICAUTH_CONFIRMED
    return coordinator, key


def test_clean_enable_uses_exact_closed_patch_and_fresh_transports():
    coordinator, key, _ = _coordinator(
        [_get(_settings(_KEY_ONLY)), _enable(_patch_response(_ENABLED)), _get(_settings(_ENABLED))]
    )

    result = coordinator.enable_basic_auth()

    assert result.state is AuthTransitionState.BASICAUTH_CONFIRMED
    assert result.delivery is MutationDelivery.RESPONSE_RECEIVED
    assert result.finding is TransitionFinding.EXPECTED_STATE_CONFIRMED
    assert result.unrelated_settings_preserved
    assert [method for method, _, _ in key.calls].count("PATCH") == 1
    assert len(key.transports) == 3
    assert all(transport.closed for transport in key.transports)


def test_clean_restore_uses_exact_closed_patch_and_fresh_keyauth_verification():
    coordinator, key = _confirmed_coordinator(
        [_get(_settings(_ENABLED)), _restore(_patch_response(_KEY_ONLY)), _get(_settings(_KEY_ONLY))]
    )

    result = coordinator.restore_key_auth()

    assert result.state is AuthTransitionState.KEYAUTH_RESTORED
    assert result.delivery is MutationDelivery.RESPONSE_RECEIVED
    assert [call for call in key.calls if call[0] == "PATCH"] == [
        ("PATCH", _SETTINGS, b'{"auth_methods":["KeyAuth","BasicAuth"]}'),
        ("PATCH", _SETTINGS, b'{"auth_methods":["KeyAuth"]}'),
    ]


@pytest.mark.parametrize("failure", [TransportTimeoutError("canary"), TransportConnectionError("canary")])
def test_enable_indeterminate_send_is_never_retried_and_fresh_read_can_confirm(failure: Exception):
    coordinator, key, _ = _coordinator([_get(_settings(_KEY_ONLY)), _enable(failure), _get(_settings(_ENABLED))])

    result = coordinator.enable_basic_auth()

    assert result.state is AuthTransitionState.BASICAUTH_CONFIRMED
    assert result.delivery is MutationDelivery.SENT_RESULT_INDETERMINATE
    assert AuthTransitionState.BASICAUTH_ENABLE_INDETERMINATE in result.state_history
    assert [method for method, _, _ in key.calls].count("PATCH") == 1
    assert "canary" not in repr(result)


def test_timeout_before_send_is_distinguished_and_fresh_read_confirms_no_change():
    coordinator, key, _ = _coordinator(
        [_get(_settings(_KEY_ONLY)), _enable(TransportRequestNotSentError("canary")), _get(_settings(_KEY_ONLY))]
    )

    result = coordinator.enable_basic_auth()

    assert result.state is AuthTransitionState.KEYAUTH_CONFIRMED
    assert result.delivery is MutationDelivery.KNOWN_NOT_SENT
    assert result.finding is TransitionFinding.MUTATION_NOT_OBSERVED
    assert [method for method, _, _ in key.calls].count("PATCH") == 1


def test_factory_failure_before_mutation_does_not_record_sent_state():
    coordinator, key, _ = _coordinator([_get(_settings(_KEY_ONLY)), RuntimeError("hidden"), _get(_settings(_KEY_ONLY))])
    result = coordinator.enable_basic_auth()
    assert result.delivery is MutationDelivery.KNOWN_NOT_SENT
    assert AuthTransitionState.BASICAUTH_ENABLE_SENT not in result.state_history
    assert not any(method == "PATCH" for method, _, _ in key.calls)


def test_indeterminate_enable_fresh_read_can_confirm_mutation_did_not_occur():
    coordinator, _, _ = _coordinator(
        [_get(_settings(_KEY_ONLY)), _enable(TransportTimeoutError("hidden")), _get(_settings(_KEY_ONLY))]
    )
    result = coordinator.enable_basic_auth()
    assert result.state is AuthTransitionState.KEYAUTH_CONFIRMED
    assert result.finding is TransitionFinding.MUTATION_NOT_OBSERVED


def test_unexpected_post_transition_state_requires_out_of_band_recovery():
    coordinator, _, _ = _coordinator(
        [_get(_settings(_KEY_ONLY)), _enable(_patch_response(_ENABLED)), _get(_settings(["JWT"]))]
    )
    result = coordinator.enable_basic_auth()
    assert result.state is AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED
    assert result.finding is TransitionFinding.UNEXPECTED_POST_STATE


def test_restore_disconnect_can_be_confirmed_by_fresh_keyauth_transport():
    coordinator, key = _confirmed_coordinator(
        [_get(_settings(_ENABLED)), _restore(TransportConnectionError("hidden")), _get(_settings(_KEY_ONLY))]
    )
    result = coordinator.restore_key_auth()
    assert result.state is AuthTransitionState.KEYAUTH_RESTORED
    assert result.delivery is MutationDelivery.SENT_RESULT_INDETERMINATE
    assert [method for method, _, _ in key.calls].count("PATCH") == 2


def test_restore_known_not_sent_and_still_enabled_is_reported_without_retry():
    coordinator, key = _confirmed_coordinator(
        [
            _get(_settings(_ENABLED)),
            _restore(TransportRequestNotSentError("hidden")),
            _get(_settings(_ENABLED)),
        ]
    )
    result = coordinator.restore_key_auth()
    assert result.state is AuthTransitionState.BASICAUTH_CONFIRMED
    assert result.finding is TransitionFinding.MUTATION_NOT_OBSERVED
    assert [method for method, _, _ in key.calls].count("PATCH") == 2
    assert coordinator.restore_key_auth().finding is TransitionFinding.INVALID_SEQUENCE
    assert [method for method, _, _ in key.calls].count("PATCH") == 2


def test_delayed_keyauth_availability_is_bounded_and_uses_fresh_transports():
    coordinator, _, _ = _coordinator(
        [
            TransportConnectionError("one"),
            TransportTimeoutError("two"),
            _get(_settings(_KEY_ONLY)),
            _enable(_patch_response(_ENABLED)),
            _get(_settings(_ENABLED)),
        ]
    )
    result = coordinator.enable_basic_auth()
    assert result.state is AuthTransitionState.BASICAUTH_CONFIRMED


def test_delayed_basicauth_availability_is_bounded_and_fresh():
    coordinator, _, basic = _coordinator(
        [_get(_settings(_KEY_ONLY)), _enable(_patch_response(_ENABLED)), _get(_settings(_ENABLED))],
        [TransportConnectionError("one"), _basic(_users())],
    )
    assert coordinator.enable_basic_auth().state is AuthTransitionState.BASICAUTH_CONFIRMED
    result = coordinator.verify_basic_auth_available()
    assert result.available
    assert result.attempts == 2
    assert len(basic.calls) == 1


def test_reconnect_exhaustion_requires_out_of_band_recovery():
    coordinator, _, _ = _coordinator([TransportConnectionError("one"), TransportTimeoutError("two")], attempts=2)
    result = coordinator.enable_basic_auth()
    assert result.state is AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED
    assert result.finding is TransitionFinding.RECONNECT_EXHAUSTED
    assert result.delivery is MutationDelivery.NOT_ATTEMPTED


def test_2026_08_19_regression_persisted_enable_then_reads_timeout_without_resubmit():
    coordinator, key, _ = _coordinator(
        [
            _get(_settings(_KEY_ONLY)),
            _enable(_patch_response(_ENABLED)),
            _get(TransportTimeoutError("first")),
            _get(TransportTimeoutError("second")),
        ],
        attempts=2,
    )
    result = coordinator.enable_basic_auth()
    assert result.state is AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED
    assert result.finding is TransitionFinding.RECONNECT_EXHAUSTED
    assert [method for method, _, _ in key.calls].count("PATCH") == 1
    assert coordinator.restore_key_auth().finding is TransitionFinding.INVALID_SEQUENCE
    assert [method for method, _, _ in key.calls].count("PATCH") == 1


def test_unrelated_setting_change_fails_closed():
    coordinator, _, _ = _coordinator(
        [
            _get(_settings(_KEY_ONLY, marker="before")),
            _enable(_patch_response(_ENABLED)),
            _get(_settings(_ENABLED, marker="after")),
        ]
    )
    result = coordinator.enable_basic_auth()
    assert result.state is AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED
    assert result.finding is TransitionFinding.UNRELATED_SETTINGS_CHANGED


@pytest.mark.parametrize(
    "payload",
    [
        {"auth_methods": "KeyAuth"},
        {"auth_methods": []},
        {"auth_methods": ["KeyAuth", "KeyAuth"]},
        {"auth_methods": ["KeyAuth", 1]},
    ],
)
def test_malformed_settings_fail_closed_without_mutation(payload: dict[str, object]):
    response = TransportResponse(200, json.dumps({"data": payload}))
    coordinator, key, _ = _coordinator([_get(response)])
    result = coordinator.enable_basic_auth()
    assert result.finding is TransitionFinding.MALFORMED_RESPONSE
    assert not any(method == "PATCH" for method, _, _ in key.calls)


def test_factory_exception_is_sanitized_and_fails_closed():
    canary = "SYNTHETIC-SECRET-CANARY"
    coordinator, _, _ = _coordinator([RuntimeError(canary)])
    result = coordinator.enable_basic_auth()
    assert result.state is AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED
    assert canary not in repr(result)


def test_no_cleanup_or_provisioning_continuation_is_imported():
    source = __import__("pathlib").Path("src/pfsense_mcp/security_auth_transition.py").read_text(encoding="utf-8")
    assert "security_bootstrap_engine" not in source
    assert "security_bootstrap_recovery" not in source
    assert "provision_service_account" not in source
    assert "revoke_failed_bootstrap_api_key" not in source
