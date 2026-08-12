"""Fail-closed construction point for the closed LAB-T1 Stage 3 backend.

The closed CLI imports this module only for ``execute``.  The repository has no
configured owner reconciliation verifier/evidence input in LAB-T1, so an
uncertainty-capable live backend cannot yet be safely constructed.  Refusing
here preserves the accepted signed-human boundary without weakening any gate.
"""

from __future__ import annotations

from .stage3_backend import ClosedStage3Backend, ClosedStage3ExecutionPort
from .stage3_deg import ScenarioId
from .stage3_live_binding import ClosedLiveBinding, LiveBindingError, LiveExecutionReport


def _execute_with_port(scenario_id: ScenarioId, port: ClosedStage3ExecutionPort) -> LiveExecutionReport:
    """Internal test/construction seam; never exposed through the CLI."""

    return ClosedLiveBinding(ClosedStage3Backend(port)).execute(scenario_id)


def execute_live_scenario(scenario_value: str) -> LiveExecutionReport:
    """Validate one closed ID and fail closed until its fixed port exists."""

    if not isinstance(scenario_value, str):
        raise LiveBindingError("scenario selector is not a closed ScenarioId")
    try:
        ScenarioId(scenario_value)
    except ValueError:
        raise LiveBindingError("scenario selector is not a closed ScenarioId") from None
    raise LiveBindingError("live Stage 3D/E/G execution port is not configured")
