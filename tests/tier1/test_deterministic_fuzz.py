"""Seeded fuzz-style invariants without adding a property-test dependency."""

from __future__ import annotations

import random

import pytest

from pfsense_mcp.tier1.canonical import canonical_json
from pfsense_mcp.tier1.errors import IllegalTransitionError
from pfsense_mcp.tier1.state_machine import LEGAL_TRANSITIONS, RecoveryState, require_transition


def _value(randomizer: random.Random, depth: int = 0):
    scalar = randomizer.choice([None, True, False, randomizer.randint(-(2**31), 2**31 - 1), "é", "e\u0301", ""])
    if depth >= 4:
        return scalar
    kind = randomizer.randrange(3)
    if kind == 0:
        return scalar
    if kind == 1:
        return [_value(randomizer, depth + 1) for _ in range(randomizer.randrange(5))]
    keys = randomizer.sample(["a", "b", "c", "δ", "z"], randomizer.randrange(6))
    return {key: _value(randomizer, depth + 1) for key in keys}


def _reverse_objects(value):
    if isinstance(value, dict):
        return {key: _reverse_objects(item) for key, item in reversed(tuple(value.items()))}
    if isinstance(value, list):
        return [_reverse_objects(item) for item in value]
    return value


def test_seeded_supported_values_are_deterministic_and_order_independent():
    randomizer = random.Random(0xD15EA5E)
    for _ in range(500):
        value = _value(randomizer)
        encoded = canonical_json(value)
        assert canonical_json(value) == encoded
        assert canonical_json(_reverse_objects(value)) == encoded


def test_seeded_transition_matrix_never_accepts_undeclared_edges():
    randomizer = random.Random(0xC0FFEE)
    states = tuple(RecoveryState)
    for _ in range(2_000):
        current = randomizer.choice(states)
        target = randomizer.choice(states)
        rule = LEGAL_TRANSITIONS.get(current, {}).get(target)
        if rule is None or rule.manual_only:
            with pytest.raises(IllegalTransitionError):
                require_transition(current, target)
        else:
            require_transition(current, target)
