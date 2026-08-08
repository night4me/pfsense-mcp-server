from __future__ import annotations

import pytest

from pfsense_mcp.tier1.errors import IllegalTransitionError
from pfsense_mcp.tier1.state_machine import LEGAL_TRANSITIONS, RecoveryState, is_terminal, require_transition


@pytest.mark.parametrize(
    ("current", "target", "manual"),
    [
        (current, target, rule.manual_only)
        for current, targets in LEGAL_TRANSITIONS.items()
        for target, rule in targets.items()
    ],
)
def test_every_declared_transition_is_accepted(current, target, manual):
    require_transition(current, target, manual=manual)


def test_every_undeclared_transition_is_rejected():
    for current in RecoveryState:
        for target in RecoveryState:
            if target not in LEGAL_TRANSITIONS.get(current, {}):
                with pytest.raises(IllegalTransitionError):
                    require_transition(current, target)


def test_reconciliation_exit_requires_manual_authority():
    with pytest.raises(IllegalTransitionError):
        require_transition(RecoveryState.RECONCILIATION, RecoveryState.VERIFIED)
    require_transition(RecoveryState.RECONCILIATION, RecoveryState.VERIFIED, manual=True)


@pytest.mark.parametrize(
    "state",
    [RecoveryState.FAILED, RecoveryState.ROLLED_BACK, RecoveryState.ROLLBACK_FAILED, RecoveryState.EXPIRED],
)
def test_terminal_states_never_reopen(state):
    assert is_terminal(state)
