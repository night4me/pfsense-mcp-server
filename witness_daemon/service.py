"""Compare-and-set witness logic -- pure orchestration over a TPM client
Protocol, with zero subprocess/network code of its own. Fully unit
testable against a synthetic fake TPM client; never talks to a real TPM
or a real socket."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol

from .errors import TpmIncrementAmbiguousError


class TpmClient(Protocol):
    def read_counter(self) -> int: ...
    def increment_counter(self) -> None: ...


@dataclass(frozen=True)
class AdvanceOutcome:
    conflict: bool
    value: int


class WitnessService:
    """Implements the accepted protocol's `read()`/`advance()` exactly
    (anti_rollback_tpm_host_witness.md's "Host service protocol"): the
    CAS check happens in this class's own logic, before any TPM call --
    `TPM2_NV_Increment` itself takes no "expected value" parameter, so
    the comparison must happen here, not be assumed from the TPM
    somehow enforcing it."""

    def __init__(self, tpm: TpmClient) -> None:
        self._tpm = tpm
        # One lock serializes ALL TPM access (read and advance alike) --
        # "the physical device only ever processes one command at a time
        # regardless of client concurrency" (accepted spec's own
        # "Replay protection and concurrency" section), and advance()'s
        # multi-step read-check-increment-reread sequence must never
        # interleave with another advance() (or a read()) call.
        self._lock = threading.Lock()

    def read(self) -> int:
        with self._lock:
            return self._tpm.read_counter()

    def advance(self, expected_current: int) -> AdvanceOutcome:
        """CAS: reads the current value first; if it does not exactly
        equal `expected_current`, returns a conflict WITHOUT calling
        `increment_counter()` at all -- zero TPM mutation on a failed
        check. On a match, increments exactly once. An ambiguous
        increment outcome (`TpmIncrementAmbiguousError` -- subprocess
        timeout or OS-level failure to complete) is never retried:
        instead, a single fresh read determines ground truth, and that
        value -- never a locally-assumed `expected_current + 1` -- is
        what gets returned. A definite rejection
        (`TpmIncrementRejectedError`) propagates directly as a failure;
        it is not ambiguous, so no confirmatory re-read is attempted."""

        with self._lock:
            current = self._tpm.read_counter()
            if current != expected_current:
                return AdvanceOutcome(conflict=True, value=current)
            try:
                self._tpm.increment_counter()
            except TpmIncrementAmbiguousError:
                new_value = self._tpm.read_counter()
                return AdvanceOutcome(conflict=False, value=new_value)
            new_value = self._tpm.read_counter()
            return AdvanceOutcome(conflict=False, value=new_value)
