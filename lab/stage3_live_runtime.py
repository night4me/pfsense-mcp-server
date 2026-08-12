"""Fail-closed integration point for a future owner-authorized live backend.

The closed CLI imports this module only for ``execute``.  The repository has no
configured owner reconciliation verifier/evidence input in LAB-T1, so an
uncertainty-capable live backend cannot yet be safely constructed.  Refusing
here preserves the accepted signed-human boundary without weakening any gate.
"""

from __future__ import annotations

from .stage3_deg import ScenarioId
from .stage3_live_binding import LiveBindingError, LiveExecutionReport


def execute_live_scenario(scenario_value: str) -> LiveExecutionReport:
    """Refuse until the existing signed reconciliation input is wired."""

    if not isinstance(scenario_value, str):
        raise LiveBindingError("scenario selector is not a closed ScenarioId")
    try:
        ScenarioId(scenario_value)
    except ValueError:
        raise LiveBindingError("scenario selector is not a closed ScenarioId") from None
    raise LiveBindingError("live Stage 3D/E/G backend is not configured: owner-signed reconciliation input is required")
