"""Live integration test for GET /api/v2/status/interfaces.

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
(macaddr, ipaddr, subnet, linklocal, ipaddrv6, subnetv6, gateway,
gatewayv6) are asserted to be absent (default redaction), never
compared against real values.
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


def test_get_interfaces_live_structure_only():
    config = load_config()
    api_key = load_api_key(config)
    transport, client = build_pfsense_client(config, api_key)
    try:
        interfaces = client.get_interfaces()

        assert isinstance(interfaces, list)
        assert len(interfaces) > 0

        for iface in interfaces:
            assert isinstance(iface.id, int)
            assert isinstance(iface.enable, bool)
            assert isinstance(iface.inerrs, int)
            assert isinstance(iface.outerrs, int)
            assert isinstance(iface.inbytes, int)
            assert isinstance(iface.outbytes, int)
            # Default redaction must hold against the live instance too.
            assert iface.macaddr is None
            assert iface.ipaddr is None
            assert iface.subnet is None
            assert iface.linklocal is None
            assert iface.ipaddrv6 is None
            assert iface.subnetv6 is None
            assert iface.gateway is None
            assert iface.gatewayv6 is None
    finally:
        transport.close()
