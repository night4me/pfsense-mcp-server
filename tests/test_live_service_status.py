"""Live integration test for get_service_status. GENERATED PROPOSAL — review before use.

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


def test_get_service_status_live_structure_only():
    config = load_config()
    api_key = load_api_key(config)
    transport, client = build_pfsense_client(config, api_key)
    try:
        result = client.get_service_status(limit=5)

        assert isinstance(result, list)
        assert len(result) <= 5  # deliberately small: never pull the full live table
    finally:
        transport.close()
