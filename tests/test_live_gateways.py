"""Live integration test for GET /api/v2/routing/gateways and
GET /api/v2/status/gateways.

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
(gateway, monitor, srcip, monitorip) are asserted to be absent
(default redaction), never compared against real values.
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


def test_get_gateways_live_structure_only():
    config = load_config()
    api_key = load_api_key(config)
    transport, client = build_pfsense_client(config, api_key)
    try:
        gateways = client.get_gateways()

        assert isinstance(gateways, list)
        assert len(gateways) > 0

        for gw in gateways:
            assert isinstance(gw.id, int)
            assert isinstance(gw.disabled, bool)
            assert isinstance(gw.weight, int)
            assert isinstance(gw.latencylow, int)
            assert isinstance(gw.losslow, int)
            # Default redaction must hold against the live instance too.
            assert gw.gateway is None
            assert gw.monitor is None
    finally:
        transport.close()


def test_get_gateway_status_live_structure_only():
    config = load_config()
    api_key = load_api_key(config)
    transport, client = build_pfsense_client(config, api_key)
    try:
        statuses = client.get_gateway_status()

        assert isinstance(statuses, list)
        assert len(statuses) > 0

        for status in statuses:
            assert isinstance(status.id, int)
            assert isinstance(status.delay, float)
            assert isinstance(status.stddev, float)
            assert isinstance(status.loss, float)
            # Default redaction must hold against the live instance too.
            assert status.srcip is None
            assert status.monitorip is None
    finally:
        transport.close()
