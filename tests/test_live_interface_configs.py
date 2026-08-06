"""Live integration test for get_interface_configs.

Opt-in only: requires PFSENSE_RUN_LIVE_TESTS=true in addition to
credentials. Never prints or persists a complete response — only
structural and redaction assertions.
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


def test_get_interface_configs_live_structure_only():
    config = load_config()
    api_key = load_api_key(config)
    transport, client = build_pfsense_client(config, api_key)
    try:
        result = client.get_interface_configs(limit=5)

        assert isinstance(result, list)
        assert len(result) <= 5  # deliberately small: never pull the full live table
        for item in result:
            assert item.ipaddr is None
            assert item.ipaddrv6 is None
            assert item.gateway is None
            assert item.gatewayv6 is None
            assert item.subnet is None
            assert item.subnetv6 is None
            assert item.spoofmac is None
            assert item.alias_address is None
            assert item.dhcphostname is None
    finally:
        transport.close()
