"""Witness daemon domain failures. Every message here must be safe to
place in a log line -- never the secret value, never raw subprocess
output that might contain it."""

from __future__ import annotations


class WitnessError(Exception):
    """Base class for witness daemon failures."""


class WitnessConfigurationError(WitnessError):
    """Daemon configuration is missing, partial, or unsafe."""


class TpmUnavailableError(WitnessError):
    """The TPM/tooling could not be reached or returned an unusable
    result. Maps to a generic fail-closed HTTP response -- never
    distinguished from other unavailable causes on the wire, to avoid
    giving a network caller an oracle into the host's internal state."""


class TpmIncrementRejectedError(TpmUnavailableError):
    """The TPM explicitly, definitively rejected the increment (the
    subprocess ran and returned promptly with a non-zero exit code) --
    not ambiguous. Safe to report as a definite failure without a
    confirmatory re-read: the command never touched the TPM's stored
    value."""


class TpmIncrementAmbiguousError(TpmUnavailableError):
    """The increment's outcome could not be confirmed (subprocess
    timeout, or the process could not be waited on) -- the TPM may or
    may not have actually incremented. Callers must re-read to determine
    ground truth and must never retry the increment call itself."""
