"""Live integration test: pfSense's own REST API configuration still
reports read_only=true.

Opt-in only, same gate as every other test_live_*.py file. This is the
one live test Tier 0 adds, and it makes no mutating call whatsoever —
it reuses the already-accepted pfsense_get_system_restapi_settings READ
path (client.get_system_restapi_settings()) to prove that even a bug in
this build's client-side write gates would still be caught by pfSense
itself refusing writes at its own API layer.
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


def test_pfsense_rest_api_is_still_configured_read_only_live():
    config = load_config()
    api_key = load_api_key(config)
    transport, client = build_pfsense_client(config, api_key)
    try:
        settings = client.get_system_restapi_settings()
        assert settings.read_only is True
    finally:
        transport.close()
