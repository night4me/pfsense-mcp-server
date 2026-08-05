"""Live integration test for GET /api/v2/firewall/rules,
GET /api/v2/firewall/states, GET /api/v2/firewall/states/size, and
GET /api/v2/firewall/apply.

Opt-in only. The presence of API credentials (PFSENSE_API_URL /
PFSENSE_IDENTITY / PFSENSE_API_KEY_FILE) alone must NOT cause this
test to run — it makes a real network call to a live pfSense
instance. It only runs when PFSENSE_RUN_LIVE_TESTS=true is set
explicitly, in addition to credentials, and is marked `live` so it
can also be excluded explicitly (`-m "not live"`).

Credentials are loaded exclusively through the project's existing
config/key-file mechanism (pfsense_mcp.config) — no separate
credential path is introduced for this test.

Only structural properties of the response are asserted. The live
response is never printed or persisted, and identifying fields
(source, destination, created_by, updated_by for rules; source,
destination for states) are asserted to be absent (default
redaction), never compared against real values.

The live states call always passes an explicit small `limit` — this
test must never fetch the full state table from the real device.
"""

from __future__ import annotations

import os

import pytest

from pfsense_mcp.config import load_api_key, load_config
from pfsense_mcp.factory import build_pfsense_client

_RUN_LIVE = os.environ.get("PFSENSE_RUN_LIVE_TESTS", "").strip().lower() == "true"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not _RUN_LIVE,
        reason="Live pfSense test skipped: set PFSENSE_RUN_LIVE_TESTS=true to opt in.",
    ),
]


def test_get_firewall_rules_live_structure_only():
    config = load_config()
    api_key = load_api_key(config)
    transport, client = build_pfsense_client(config, api_key)
    try:
        rules = client.get_firewall_rules()

        assert isinstance(rules, list)

        for rule in rules:
            assert isinstance(rule.id, int)
            assert isinstance(rule.disabled, bool)
            assert isinstance(rule.floating, bool)
            assert isinstance(rule.tracker, int)
            # Default redaction must hold against the live instance too.
            assert rule.source is None
            assert rule.destination is None
            assert rule.created_by is None
            assert rule.updated_by is None
    finally:
        transport.close()


def test_get_firewall_states_live_structure_only():
    config = load_config()
    api_key = load_api_key(config)
    transport, client = build_pfsense_client(config, api_key)
    try:
        # Deliberately small: never pull the full live state table.
        states = client.get_firewall_states(limit=5)

        assert isinstance(states, list)
        assert len(states) <= 5

        for state in states:
            assert isinstance(state.id, int)
            assert isinstance(state.packets_total, int)
            assert isinstance(state.bytes_total, int)
            # Default redaction must hold against the live instance too.
            assert state.source is None
            assert state.destination is None
    finally:
        transport.close()


def test_get_firewall_states_size_live_structure_only():
    config = load_config()
    api_key = load_api_key(config)
    transport, client = build_pfsense_client(config, api_key)
    try:
        size = client.get_firewall_states_size()

        assert isinstance(size.currentstates, int)
        assert isinstance(size.defaultmaximumstates, int)
    finally:
        transport.close()


def test_get_firewall_apply_status_live_structure_only():
    config = load_config()
    api_key = load_api_key(config)
    transport, client = build_pfsense_client(config, api_key)
    try:
        status = client.get_firewall_apply_status()

        assert isinstance(status.applied, bool)
        assert isinstance(status.pending_subsystems, list)
    finally:
        transport.close()
