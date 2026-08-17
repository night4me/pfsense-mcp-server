"""Phase F: the CARP integration seam -- proves NexusSession ->
NexusTransport -> normalize_carp_status()/NexusCarpStatusReader work
together end-to-end, entirely offline (respx-mocked). This wiring
exists in test code only. It is not exposed anywhere in production
code, not registered as a tool, and not reachable through
factory.py/tools/registry.py/application.py or any backend-selection
path -- see test_isolation.py, which already enforces this for
everything under backends/."""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest
import respx

from pfsense_mcp.backends.nexus.carp_status import NexusCarpStatusReader, normalize_carp_status
from pfsense_mcp.backends.nexus.session import NexusSession
from pfsense_mcp.backends.nexus.transport import NexusEndpoints, NexusTransport
from pfsense_mcp.errors import PfSenseAuthError, PfSenseResponseShapeError
from pfsense_mcp.models.carp_status import CarpStatus

CONTROLLER = "https://nexus.example.invalid"
DEVICE_BASE = f"{CONTROLLER}/api/device/pfsense/dev-123/api"


def _jwt(payload: dict) -> str:
    def _b64(obj) -> str:
        raw = json.dumps(obj).encode("utf-8") if not isinstance(obj, bytes) else obj
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{_b64({'alg': 'none'})}.{_b64(payload)}.{_b64(b'sig')}"


@respx.mock
def test_full_chain_login_transport_normalization_success():
    token = _jwt({"exp": int(time.time()) + 3600})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))
    respx.get(f"{DEVICE_BASE}/services/carp/status").mock(
        return_value=httpx.Response(200, json={"enabled": True, "maintenancemode_enabled": False, "my_hostid": "x"})
    )

    session = NexusSession(controller_url=CONTROLLER, username="admin", password="hunter2")
    session.login()
    transport = NexusTransport(controller_url=CONTROLLER, device_type="pfsense", device_id="dev-123", session=session)
    reader = NexusCarpStatusReader(lambda: transport.get_json(NexusEndpoints.CARP_STATUS))

    result = reader.get_carp_status()

    assert result == CarpStatus(enable=True, maintenance_mode=False)


@respx.mock
def test_full_chain_missing_carp_field_fails_closed():
    token = _jwt({"exp": int(time.time()) + 3600})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))
    respx.get(f"{DEVICE_BASE}/services/carp/status").mock(
        return_value=httpx.Response(200, json={"enabled": True})  # maintenancemode_enabled missing
    )

    session = NexusSession(controller_url=CONTROLLER, username="admin", password="hunter2")
    session.login()
    transport = NexusTransport(controller_url=CONTROLLER, device_type="pfsense", device_id="dev-123", session=session)
    reader = NexusCarpStatusReader(lambda: transport.get_json(NexusEndpoints.CARP_STATUS))

    with pytest.raises(PfSenseResponseShapeError):
        reader.get_carp_status()


@respx.mock
def test_full_chain_wrong_type_carp_field_fails_closed():
    token = _jwt({"exp": int(time.time()) + 3600})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))
    respx.get(f"{DEVICE_BASE}/services/carp/status").mock(
        return_value=httpx.Response(200, json={"enabled": [1, 2], "maintenancemode_enabled": False})
    )

    session = NexusSession(controller_url=CONTROLLER, username="admin", password="hunter2")
    session.login()
    transport = NexusTransport(controller_url=CONTROLLER, device_type="pfsense", device_id="dev-123", session=session)
    reader = NexusCarpStatusReader(lambda: transport.get_json(NexusEndpoints.CARP_STATUS))

    with pytest.raises(PfSenseResponseShapeError):
        reader.get_carp_status()


@respx.mock
def test_full_chain_auth_failure_propagates_before_any_carp_call():
    respx.post(f"{CONTROLLER}/api/login").mock(
        return_value=httpx.Response(400, json={"errcode": 1, "errlevel": "error", "errmsg": "bad credentials"})
    )
    carp_route = respx.get(f"{DEVICE_BASE}/services/carp/status").mock(return_value=httpx.Response(200, json={}))

    session = NexusSession(controller_url=CONTROLLER, username="admin", password="hunter2")
    with pytest.raises(PfSenseAuthError):
        session.login()

    assert not carp_route.called


def test_normalize_carp_status_used_by_reader_is_the_same_function():
    """The integration path must reuse the exact same, already-tested
    normalization function -- not a parallel copy."""

    import inspect

    from pfsense_mcp.backends.nexus.carp_status import NexusCarpStatusReader as ReaderCls

    source = inspect.getsource(ReaderCls.get_carp_status)
    assert "normalize_carp_status" in source
    assert normalize_carp_status.__module__ == "pfsense_mcp.backends.nexus.carp_status"
