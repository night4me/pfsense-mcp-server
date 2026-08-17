"""Tests for `pfsense_mcp.security_bootstrap_transaction` (`ADR-033`
implementation Phase B, requirement 5). Pure state-machine tests --
no pfSense contact is possible from this module at all, so there is
nothing to mock; every test exercises the model directly.
"""

from __future__ import annotations

import pytest

from pfsense_mcp.security_bootstrap_transaction import (
    BOOTSTRAP_ONLY_PRIVILEGE,
    BootstrapState,
    BootstrapTransaction,
    InvariantViolation,
    allowed_next_states,
    check_invariants,
    is_legal_transition,
    is_steady_state_privilege_set,
)

_BASE_PRIVS = frozenset({"api-v2-firewall-aliases-get", "api-v2-firewall-alias-patch"})


def _happy_path_transaction() -> BootstrapTransaction:
    t = BootstrapTransaction(state=BootstrapState.NOT_STARTED)
    t = t.transition(BootstrapState.USER_CREATED, privileges=_BASE_PRIVS)
    t = t.transition(BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED, privileges=_BASE_PRIVS | {BOOTSTRAP_ONLY_PRIVILEGE})
    t = t.transition(BootstrapState.KEY_GENERATED, privileges=_BASE_PRIVS | {BOOTSTRAP_ONLY_PRIVILEGE})
    t = t.transition(BootstrapState.BOOTSTRAP_PRIVILEGE_REVOKED, privileges=_BASE_PRIVS)
    return t.transition(BootstrapState.VERIFIED, privileges=_BASE_PRIVS)


# ---------------------------------------------------------------------------
# 1. Legal transition graph
# ---------------------------------------------------------------------------


def test_full_happy_path_succeeds():
    t = _happy_path_transaction()
    assert t.state is BootstrapState.VERIFIED
    assert BOOTSTRAP_ONLY_PRIVILEGE not in t.privileges


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (BootstrapState.NOT_STARTED, BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED),
        (BootstrapState.NOT_STARTED, BootstrapState.VERIFIED),
        (BootstrapState.USER_CREATED, BootstrapState.KEY_GENERATED),
        (BootstrapState.USER_CREATED, BootstrapState.NOT_STARTED),
        (BootstrapState.VERIFIED, BootstrapState.NOT_STARTED),
        (BootstrapState.VERIFIED, BootstrapState.USER_CREATED),
    ],
)
def test_illegal_transitions_are_rejected(current, target):
    assert not is_legal_transition(current, target)
    with pytest.raises(InvariantViolation, match="illegal transition"):
        BootstrapTransaction(state=current).transition(target, privileges=frozenset())


def test_no_step_can_be_skipped_going_forward():
    """Every non-terminal state's only forward-progress option is
    exactly the next state in sequence (plus FAILED)."""

    sequence = [
        BootstrapState.NOT_STARTED,
        BootstrapState.USER_CREATED,
        BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED,
        BootstrapState.KEY_GENERATED,
        BootstrapState.BOOTSTRAP_PRIVILEGE_REVOKED,
        BootstrapState.VERIFIED,
    ]
    for i, state in enumerate(sequence[:-1]):
        forward_targets = allowed_next_states(state) - {BootstrapState.FAILED}
        assert forward_targets == {sequence[i + 1]}


def test_verified_and_failed_are_terminal():
    assert allowed_next_states(BootstrapState.VERIFIED) == frozenset()
    assert allowed_next_states(BootstrapState.FAILED) == frozenset()


# ---------------------------------------------------------------------------
# 2. The bootstrap-only-privilege invariant (the phase's core requirement)
# ---------------------------------------------------------------------------


def test_bootstrap_privilege_present_before_grant_is_rejected():
    t = BootstrapTransaction(state=BootstrapState.NOT_STARTED)
    with pytest.raises(InvariantViolation, match="must not be present before it is granted"):
        t.transition(BootstrapState.USER_CREATED, privileges=frozenset({BOOTSTRAP_ONLY_PRIVILEGE}))


def test_bootstrap_privilege_still_present_at_revoked_state_is_rejected():
    t = BootstrapTransaction(state=BootstrapState.NOT_STARTED)
    t = t.transition(BootstrapState.USER_CREATED, privileges=_BASE_PRIVS)
    t = t.transition(BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED, privileges=_BASE_PRIVS | {BOOTSTRAP_ONLY_PRIVILEGE})
    t = t.transition(BootstrapState.KEY_GENERATED, privileges=_BASE_PRIVS | {BOOTSTRAP_ONLY_PRIVILEGE})
    with pytest.raises(InvariantViolation, match="steady-state account"):
        t.transition(BootstrapState.BOOTSTRAP_PRIVILEGE_REVOKED, privileges=_BASE_PRIVS | {BOOTSTRAP_ONLY_PRIVILEGE})


def test_bootstrap_privilege_present_at_verified_is_rejected_even_if_revoked_state_was_clean():
    """Defense in depth: even if BOOTSTRAP_PRIVILEGE_REVOKED was
    (incorrectly) constructed clean, VERIFIED must independently refuse
    to hold the privilege too -- check_invariants() checks each state
    on its own terms, not just at the one transition where it's first
    introduced."""

    with pytest.raises(InvariantViolation, match="steady-state account"):
        check_invariants(
            BootstrapTransaction(state=BootstrapState.VERIFIED, privileges=frozenset({BOOTSTRAP_ONLY_PRIVILEGE}))
        )


def test_bootstrap_privilege_is_permitted_during_the_two_states_that_legitimately_hold_it():
    check_invariants(
        BootstrapTransaction(
            state=BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED, privileges=frozenset({BOOTSTRAP_ONLY_PRIVILEGE})
        )
    )
    check_invariants(
        BootstrapTransaction(state=BootstrapState.KEY_GENERATED, privileges=frozenset({BOOTSTRAP_ONLY_PRIVILEGE}))
    )


def test_is_steady_state_privilege_set_matches_the_transaction_invariant():
    assert is_steady_state_privilege_set(_BASE_PRIVS)
    assert not is_steady_state_privilege_set(_BASE_PRIVS | {BOOTSTRAP_ONLY_PRIVILEGE})


# ---------------------------------------------------------------------------
# 3. Failure handling
# ---------------------------------------------------------------------------


def test_fail_is_reachable_from_any_non_terminal_state():
    for state in (
        BootstrapState.NOT_STARTED,
        BootstrapState.USER_CREATED,
        BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED,
        BootstrapState.KEY_GENERATED,
        BootstrapState.BOOTSTRAP_PRIVILEGE_REVOKED,
    ):
        t = BootstrapTransaction(state=state, privileges=frozenset())
        failed = t.fail("simulated failure")
        assert failed.state is BootstrapState.FAILED
        assert failed.failure_detail == "simulated failure"


def test_fail_records_which_privileges_were_held_at_failure_time():
    t = BootstrapTransaction(
        state=BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED, privileges=frozenset({BOOTSTRAP_ONLY_PRIVILEGE})
    )
    failed = t.fail("key generation failed")
    assert failed.privileges == frozenset({BOOTSTRAP_ONLY_PRIVILEGE})


def test_cannot_fail_from_a_terminal_state():
    with pytest.raises(InvariantViolation, match="cannot fail from terminal state"):
        BootstrapTransaction(state=BootstrapState.VERIFIED).fail("too late")
    with pytest.raises(InvariantViolation, match="cannot fail from terminal state"):
        BootstrapTransaction(state=BootstrapState.FAILED).fail("already failed")


def test_partial_failure_after_bootstrap_grant_leaves_the_privilege_visibly_reported():
    """A crash between BOOTSTRAP_PRIVILEGE_GRANTED and revocation must
    leave the fact that the temporary privilege is still outstanding
    directly readable from the failed transaction's own state -- never
    silently forgotten (ADR-033 §3's partial-failure design)."""

    t = BootstrapTransaction(
        state=BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED, privileges=frozenset({BOOTSTRAP_ONLY_PRIVILEGE})
    )
    failed = t.fail("network error during key generation")
    assert BOOTSTRAP_ONLY_PRIVILEGE in failed.privileges  # visible, not hidden
    assert not is_steady_state_privilege_set(failed.privileges)


# ---------------------------------------------------------------------------
# 4. No provisioning capability exists in this module
# ---------------------------------------------------------------------------


def test_module_has_no_http_or_network_dependency():
    import ast
    from pathlib import Path

    source = Path("src/pfsense_mcp/security_bootstrap_transaction.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    forbidden = {"httpx", "requests", "socket", "urllib", "pfsense_mcp.rest_api_client", "pfsense_mcp.pfsense_client"}
    assert not (imported & forbidden)


def test_transactions_are_immutable():
    t = BootstrapTransaction(state=BootstrapState.NOT_STARTED)
    with pytest.raises(AttributeError):
        t.state = BootstrapState.VERIFIED  # type: ignore[misc]
