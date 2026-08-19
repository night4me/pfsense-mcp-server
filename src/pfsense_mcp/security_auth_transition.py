"""Closed ADR-033 LAB authentication-method transition coordinator.

This is an offline-built, owner-directed recovery primitive, not runtime or
CLI wiring.  It can express only ``KeyAuth`` -> ``KeyAuth + BasicAuth`` and the
inverse restoration.  Every post-mutation observation uses a newly constructed
transport because pfSense REST API v2.10 does not promise connection continuity
across its always-applied settings save and the 2026-08-19 LAB incident proved
that the setting may persist while immediate requests time out.

The coordinator never provisions, cleans up, retries a mutation, accepts an
endpoint or payload, or treats a timeout as proof of failure.  Exhausted or
unexpected observations require out-of-band recovery.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum
from time import sleep
from typing import Protocol, TypeVar

from .api_version import ApiVersion
from .errors import BootstrapProvisioningError
from .security_bootstrap_client import BootstrapProvisioningClient, ObservedAuthSettings
from .transport.base import (
    Transport,
    TransportConnectionError,
    TransportRequestNotSentError,
    TransportTimeoutError,
)

_KEY_ONLY = frozenset({"KeyAuth"})
_KEY_AND_BASIC = frozenset({"KeyAuth", "BasicAuth"})


class FreshTransport(Transport, Protocol):
    def close(self) -> None: ...


FreshTransportFactory = Callable[[], FreshTransport]


class AuthTransitionState(str, Enum):
    KEYAUTH_CONFIRMED = "keyauth_confirmed"
    BASICAUTH_ENABLE_SENT = "basicauth_enable_sent"
    BASICAUTH_ENABLE_INDETERMINATE = "basicauth_enable_indeterminate"
    BASICAUTH_CONFIRMED = "basicauth_confirmed"
    RESTORE_SENT = "restore_sent"
    RESTORE_INDETERMINATE = "restore_indeterminate"
    KEYAUTH_RESTORED = "keyauth_restored"
    OUT_OF_BAND_RECOVERY_REQUIRED = "out_of_band_recovery_required"


class MutationDelivery(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    KNOWN_NOT_SENT = "known_not_sent"
    RESPONSE_RECEIVED = "response_received"
    SENT_RESULT_INDETERMINATE = "sent_result_indeterminate"


class TransitionFinding(str, Enum):
    EXPECTED_STATE_CONFIRMED = "expected_state_confirmed"
    MUTATION_NOT_OBSERVED = "mutation_not_observed"
    UNEXPECTED_INITIAL_STATE = "unexpected_initial_state"
    UNEXPECTED_POST_STATE = "unexpected_post_state"
    UNRELATED_SETTINGS_CHANGED = "unrelated_settings_changed"
    MALFORMED_RESPONSE = "malformed_response"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    RECONNECT_EXHAUSTED = "reconnect_exhausted"
    INVALID_SEQUENCE = "invalid_sequence"


@dataclass(frozen=True)
class ReconnectPolicy:
    maximum_attempts: int = 5
    delay_seconds: float = 1.0

    def __post_init__(self) -> None:
        if self.maximum_attempts < 1 or self.maximum_attempts > 20:
            raise ValueError("maximum_attempts must be between 1 and 20")
        if self.delay_seconds < 0 or self.delay_seconds > 30:
            raise ValueError("delay_seconds must be between 0 and 30")


@dataclass(frozen=True)
class AuthTransitionResult:
    state: AuthTransitionState
    delivery: MutationDelivery
    finding: TransitionFinding
    observation_attempts: int
    unrelated_settings_preserved: bool
    state_history: tuple[AuthTransitionState, ...]


@dataclass(frozen=True)
class BasicAuthAvailability:
    available: bool
    attempts: int


_T = TypeVar("_T")


class AuthMethodTransitionCoordinator:
    """One-shot composition around fixed bootstrap-client operations."""

    def __init__(
        self,
        *,
        keyauth_transport_factory: FreshTransportFactory,
        basicauth_transport_factory: FreshTransportFactory,
        api_version: ApiVersion = ApiVersion.V2,
        reconnect_policy: ReconnectPolicy | None = None,
        sleeper: Callable[[float], None] = sleep,
    ) -> None:
        self._keyauth_factory = keyauth_transport_factory
        self._basicauth_factory = basicauth_transport_factory
        self._api_version = api_version
        self._policy = reconnect_policy or ReconnectPolicy()
        self._sleeper = sleeper
        self._state: AuthTransitionState | None = None
        self._baseline_digest: str | None = None
        self._enable_attempted = False
        self._restore_attempted = False
        self._history: list[AuthTransitionState] = []

    @property
    def state(self) -> AuthTransitionState | None:
        return self._state

    def _fresh_call(self, factory: FreshTransportFactory, call: Callable[[BootstrapProvisioningClient], _T]) -> _T:
        try:
            transport = factory()
        except Exception:
            raise TransportRequestNotSentError("Fresh transport construction failed") from None
        try:
            return call(BootstrapProvisioningClient(transport, api_version=self._api_version))
        finally:
            with suppress(Exception):
                transport.close()

    def _fresh_mutation(
        self,
        factory: FreshTransportFactory,
        sent_state: AuthTransitionState,
        call: Callable[[BootstrapProvisioningClient], None],
    ) -> None:
        """Construct first, then cross the auditable one-shot send boundary."""

        try:
            transport = factory()
        except Exception:
            raise TransportRequestNotSentError("Fresh transport construction failed") from None
        self._state = sent_state
        self._history.append(sent_state)
        try:
            call(BootstrapProvisioningClient(transport, api_version=self._api_version))
        finally:
            with suppress(Exception):
                transport.close()

    def _observe_once(self) -> ObservedAuthSettings:
        return self._fresh_call(self._keyauth_factory, lambda client: client._observe_auth_settings_for_transition())

    def _observe_bounded(self) -> tuple[ObservedAuthSettings | None, int, TransitionFinding | None]:
        for attempt in range(1, self._policy.maximum_attempts + 1):
            try:
                return self._observe_once(), attempt, None
            except (TransportConnectionError, TransportTimeoutError):
                if attempt < self._policy.maximum_attempts:
                    self._sleeper(self._policy.delay_seconds)
            except BootstrapProvisioningError:
                return None, attempt, TransitionFinding.MALFORMED_RESPONSE
            except Exception:
                return None, attempt, TransitionFinding.INFRASTRUCTURE_FAILURE
        return None, self._policy.maximum_attempts, TransitionFinding.RECONNECT_EXHAUSTED

    def _result(
        self,
        *,
        state: AuthTransitionState,
        delivery: MutationDelivery,
        finding: TransitionFinding,
        attempts: int,
        preserved: bool,
    ) -> AuthTransitionResult:
        self._state = state
        self._history.append(state)
        return AuthTransitionResult(state, delivery, finding, attempts, preserved, tuple(self._history))

    def enable_basic_auth(self) -> AuthTransitionResult:
        if self._enable_attempted or self._state is not None:
            return self._result(
                state=AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED,
                delivery=MutationDelivery.NOT_ATTEMPTED,
                finding=TransitionFinding.INVALID_SEQUENCE,
                attempts=0,
                preserved=False,
            )
        initial, attempts, observation_failure = self._observe_bounded()
        if initial is None:
            return self._result(
                state=AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED,
                delivery=MutationDelivery.NOT_ATTEMPTED,
                finding=observation_failure or TransitionFinding.RECONNECT_EXHAUSTED,
                attempts=attempts,
                preserved=False,
            )
        if initial.auth_methods != _KEY_ONLY:
            return self._result(
                state=AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED,
                delivery=MutationDelivery.NOT_ATTEMPTED,
                finding=TransitionFinding.UNEXPECTED_INITIAL_STATE,
                attempts=attempts,
                preserved=False,
            )
        self._baseline_digest = initial.unrelated_digest
        self._state = AuthTransitionState.KEYAUTH_CONFIRMED
        self._history.append(self._state)
        self._enable_attempted = True
        delivery = MutationDelivery.RESPONSE_RECEIVED
        try:
            self._fresh_mutation(
                self._keyauth_factory,
                AuthTransitionState.BASICAUTH_ENABLE_SENT,
                lambda client: client._enable_basic_auth_for_transition(),
            )
        except TransportRequestNotSentError:
            delivery = MutationDelivery.KNOWN_NOT_SENT
        except (TransportConnectionError, TransportTimeoutError, BootstrapProvisioningError):
            delivery = MutationDelivery.SENT_RESULT_INDETERMINATE
            self._state = AuthTransitionState.BASICAUTH_ENABLE_INDETERMINATE
            self._history.append(self._state)
        except Exception:
            delivery = MutationDelivery.SENT_RESULT_INDETERMINATE
            self._state = AuthTransitionState.BASICAUTH_ENABLE_INDETERMINATE
            self._history.append(self._state)

        observed, observe_attempts, observation_failure = self._observe_bounded()
        if observed is None:
            return self._result(
                state=AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED,
                delivery=delivery,
                finding=observation_failure or TransitionFinding.RECONNECT_EXHAUSTED,
                attempts=observe_attempts,
                preserved=False,
            )
        preserved = observed.unrelated_digest == self._baseline_digest
        if not preserved:
            return self._result(
                state=AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED,
                delivery=delivery,
                finding=TransitionFinding.UNRELATED_SETTINGS_CHANGED,
                attempts=observe_attempts,
                preserved=False,
            )
        if observed.auth_methods == _KEY_AND_BASIC:
            return self._result(
                state=AuthTransitionState.BASICAUTH_CONFIRMED,
                delivery=delivery,
                finding=TransitionFinding.EXPECTED_STATE_CONFIRMED,
                attempts=observe_attempts,
                preserved=True,
            )
        if observed.auth_methods == _KEY_ONLY and delivery in {
            MutationDelivery.KNOWN_NOT_SENT,
            MutationDelivery.SENT_RESULT_INDETERMINATE,
        }:
            return self._result(
                state=AuthTransitionState.KEYAUTH_CONFIRMED,
                delivery=delivery,
                finding=TransitionFinding.MUTATION_NOT_OBSERVED,
                attempts=observe_attempts,
                preserved=True,
            )
        return self._result(
            state=AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED,
            delivery=delivery,
            finding=TransitionFinding.UNEXPECTED_POST_STATE,
            attempts=observe_attempts,
            preserved=True,
        )

    def verify_basic_auth_available(self) -> BasicAuthAvailability:
        if self._state is not AuthTransitionState.BASICAUTH_CONFIRMED:
            return BasicAuthAvailability(False, 0)
        for attempt in range(1, self._policy.maximum_attempts + 1):
            try:
                self._fresh_call(self._basicauth_factory, lambda client: client.list_users())
                return BasicAuthAvailability(True, attempt)
            except (TransportConnectionError, TransportTimeoutError):
                if attempt < self._policy.maximum_attempts:
                    self._sleeper(self._policy.delay_seconds)
            except BootstrapProvisioningError:
                return BasicAuthAvailability(False, attempt)
            except Exception:
                return BasicAuthAvailability(False, attempt)
        return BasicAuthAvailability(False, self._policy.maximum_attempts)

    def restore_key_auth(self) -> AuthTransitionResult:
        if self._restore_attempted or self._state is not AuthTransitionState.BASICAUTH_CONFIRMED:
            return self._result(
                state=AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED,
                delivery=MutationDelivery.NOT_ATTEMPTED,
                finding=TransitionFinding.INVALID_SEQUENCE,
                attempts=0,
                preserved=False,
            )
        current, attempts, observation_failure = self._observe_bounded()
        if current is None:
            return self._result(
                state=AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED,
                delivery=MutationDelivery.NOT_ATTEMPTED,
                finding=observation_failure or TransitionFinding.RECONNECT_EXHAUSTED,
                attempts=attempts,
                preserved=False,
            )
        if current.auth_methods != _KEY_AND_BASIC or current.unrelated_digest != self._baseline_digest:
            return self._result(
                state=AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED,
                delivery=MutationDelivery.NOT_ATTEMPTED,
                finding=(
                    TransitionFinding.UNRELATED_SETTINGS_CHANGED
                    if current.unrelated_digest != self._baseline_digest
                    else TransitionFinding.UNEXPECTED_INITIAL_STATE
                ),
                attempts=attempts,
                preserved=False,
            )
        self._restore_attempted = True
        delivery = MutationDelivery.RESPONSE_RECEIVED
        try:
            self._fresh_mutation(
                self._keyauth_factory,
                AuthTransitionState.RESTORE_SENT,
                lambda client: client._restore_key_auth_for_transition(),
            )
        except TransportRequestNotSentError:
            delivery = MutationDelivery.KNOWN_NOT_SENT
        except (TransportConnectionError, TransportTimeoutError, BootstrapProvisioningError):
            delivery = MutationDelivery.SENT_RESULT_INDETERMINATE
            self._state = AuthTransitionState.RESTORE_INDETERMINATE
            self._history.append(self._state)
        except Exception:
            delivery = MutationDelivery.SENT_RESULT_INDETERMINATE
            self._state = AuthTransitionState.RESTORE_INDETERMINATE
            self._history.append(self._state)

        observed, observe_attempts, observation_failure = self._observe_bounded()
        if observed is None:
            return self._result(
                state=AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED,
                delivery=delivery,
                finding=observation_failure or TransitionFinding.RECONNECT_EXHAUSTED,
                attempts=observe_attempts,
                preserved=False,
            )
        preserved = observed.unrelated_digest == self._baseline_digest
        if preserved and observed.auth_methods == _KEY_ONLY:
            return self._result(
                state=AuthTransitionState.KEYAUTH_RESTORED,
                delivery=delivery,
                finding=TransitionFinding.EXPECTED_STATE_CONFIRMED,
                attempts=observe_attempts,
                preserved=True,
            )
        if (
            preserved
            and observed.auth_methods == _KEY_AND_BASIC
            and delivery
            in {
                MutationDelivery.KNOWN_NOT_SENT,
                MutationDelivery.SENT_RESULT_INDETERMINATE,
            }
        ):
            return self._result(
                state=AuthTransitionState.BASICAUTH_CONFIRMED,
                delivery=delivery,
                finding=TransitionFinding.MUTATION_NOT_OBSERVED,
                attempts=observe_attempts,
                preserved=True,
            )
        return self._result(
            state=AuthTransitionState.OUT_OF_BAND_RECOVERY_REQUIRED,
            delivery=delivery,
            finding=(
                TransitionFinding.UNRELATED_SETTINGS_CHANGED
                if not preserved
                else TransitionFinding.UNEXPECTED_POST_STATE
            ),
            attempts=observe_attempts,
            preserved=preserved,
        )
