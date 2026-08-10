from __future__ import annotations

import threading

import pytest

from witness_daemon.errors import TpmIncrementAmbiguousError, TpmIncrementRejectedError, TpmUnavailableError
from witness_daemon.service import AdvanceOutcome, WitnessService


class _FakeTpm:
    """A synthetic TPM: real internal counter state, no subprocess, no
    real device -- exactly the "synthetic/mock TPM behavior only" this
    mission's own test list requires."""

    def __init__(self, *, initial: int = 2, increment_calls: list[Exception] | None = None) -> None:
        self._value = initial
        self.increment_call_count = 0
        self.read_call_count = 0
        self._increment_behavior: list[Exception | None] = list(increment_calls) if increment_calls else []

    def read_counter(self) -> int:
        self.read_call_count += 1
        return self._value

    def increment_counter(self) -> None:
        self.increment_call_count += 1
        if self._increment_behavior:
            behavior = self._increment_behavior.pop(0)
            if behavior is not None:
                raise behavior
        self._value += 1


def test_read_returns_current_value():
    tpm = _FakeTpm(initial=2)
    service = WitnessService(tpm)
    assert service.read() == 2


def test_read_propagates_unavailable():
    class _BrokenTpm:
        def read_counter(self) -> int:
            raise TpmUnavailableError("unreachable")

        def increment_counter(self) -> None:
            raise AssertionError("must not be called")

    with pytest.raises(TpmUnavailableError):
        WitnessService(_BrokenTpm()).read()


def test_advance_expected_current_match_increments_exactly_once():
    tpm = _FakeTpm(initial=2)
    service = WitnessService(tpm)

    outcome = service.advance(2)

    assert outcome == AdvanceOutcome(conflict=False, value=3)
    assert tpm.increment_call_count == 1


def test_advance_expected_current_mismatch_is_conflict_with_zero_increments():
    tpm = _FakeTpm(initial=2)
    service = WitnessService(tpm)

    outcome = service.advance(999)

    assert outcome == AdvanceOutcome(conflict=True, value=2)
    assert tpm.increment_call_count == 0


def test_advance_ambiguous_increment_rereads_and_never_retries():
    tpm = _FakeTpm(initial=2, increment_calls=[TpmIncrementAmbiguousError("timeout")])
    service = WitnessService(tpm)

    outcome = service.advance(2)

    # The ambiguous attempt's exception is caught internally; the fake's
    # own _value was never actually bumped by that failed call (it
    # raised before incrementing), so the confirmatory re-read correctly
    # reports the unchanged value -- and, critically, increment_counter
    # was called exactly once, never retried.
    assert outcome == AdvanceOutcome(conflict=False, value=2)
    assert tpm.increment_call_count == 1
    assert tpm.read_call_count == 2  # initial CAS read + confirmatory re-read


def test_advance_ambiguous_increment_that_actually_succeeded_is_reflected_by_reread():
    class _AmbiguousButActuallySucceededTpm:
        def __init__(self) -> None:
            self._value = 2
            self.increment_call_count = 0

        def read_counter(self) -> int:
            return self._value

        def increment_counter(self) -> None:
            self.increment_call_count += 1
            self._value += 1  # the TPM really did increment...
            raise TpmIncrementAmbiguousError("...but the response was lost")

    tpm = _AmbiguousButActuallySucceededTpm()
    service = WitnessService(tpm)

    outcome = service.advance(2)

    assert outcome == AdvanceOutcome(conflict=False, value=3)
    assert tpm.increment_call_count == 1


def test_advance_definite_rejection_propagates_without_reread():
    tpm = _FakeTpm(initial=2, increment_calls=[TpmIncrementRejectedError("rejected")])
    service = WitnessService(tpm)

    with pytest.raises(TpmIncrementRejectedError):
        service.advance(2)

    assert tpm.increment_call_count == 1
    assert tpm.read_call_count == 1  # only the initial CAS read -- no confirmatory reread for a definite rejection


def test_concurrent_advance_calls_are_serialized_exactly_one_succeeds():
    tpm = _FakeTpm(initial=2)
    service = WitnessService(tpm)
    results: list[AdvanceOutcome] = []
    results_lock = threading.Lock()

    def _attempt() -> None:
        outcome = service.advance(2)
        with results_lock:
            results.append(outcome)

    threads = [threading.Thread(target=_attempt) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    successes = [r for r in results if not r.conflict]
    conflicts = [r for r in results if r.conflict]
    assert len(successes) == 1
    assert len(conflicts) == 9
    assert tpm.increment_call_count == 1
    assert successes[0].value == 3
