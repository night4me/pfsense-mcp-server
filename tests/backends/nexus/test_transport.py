"""Phase F: adversarial coverage for NexusTransport -- GET-only,
device-scoped, allow-listed endpoint dispatch, and the "never leak a
token" rule."""

from __future__ import annotations

import inspect

import httpx
import pytest
import respx

from pfsense_mcp.backends.nexus.transport import NexusEndpointInfo, NexusEndpoints, NexusTransport
from pfsense_mcp.errors import PfSenseAPIError, PfSenseConnectionError, PfSenseResponseShapeError

CONTROLLER = "https://nexus.example.invalid"
DEVICE_BASE = f"{CONTROLLER}/api/device/pfsense/dev-123/api"


class _FakeSession:
    """Stand-in for NexusSession -- NexusTransport must not construct
    or manage its own session; it only asks an injected one for a
    token immediately before each request."""

    def __init__(self, token: str = "fake-access-token"):
        self.token = token
        self.calls = 0

    def get_valid_access_token(self) -> str:
        self.calls += 1
        return self.token


def _transport(**kwargs) -> NexusTransport:
    return NexusTransport(
        controller_url=CONTROLLER,
        device_type="pfsense",
        device_id="dev-123",
        session=_FakeSession(),
        **kwargs,
    )


# --- basic success / routing ----------------------------------------


@respx.mock
def test_get_json_success_returns_body():
    respx.get(f"{DEVICE_BASE}/services/carp/status").mock(
        return_value=httpx.Response(200, json={"enabled": True, "maintenancemode_enabled": False})
    )
    transport = _transport()
    body = transport.get_json(NexusEndpoints.CARP_STATUS)
    assert body == {"enabled": True, "maintenancemode_enabled": False}


@respx.mock
def test_get_json_sends_bearer_token_from_session():
    session = _FakeSession(token="specific-token-value")
    route = respx.get(f"{DEVICE_BASE}/services/carp/status").mock(return_value=httpx.Response(200, json={}))
    transport = NexusTransport(controller_url=CONTROLLER, device_type="pfsense", device_id="dev-123", session=session)
    transport.get_json(NexusEndpoints.CARP_STATUS)
    assert route.calls.last.request.headers["Authorization"] == "Bearer specific-token-value"
    assert session.calls == 1


def test_constructor_uses_validated_device_routing():
    """Malformed device_type/device_id must fail at construction, via
    routing.py's build_device_base_path, before any client exists."""

    with pytest.raises(ValueError):
        NexusTransport(
            controller_url=CONTROLLER, device_type="pfsense", device_id="../etc/passwd", session=_FakeSession()
        )


def test_constructor_rejects_path_altering_device_id():
    with pytest.raises(ValueError, match="device_id"):
        NexusTransport(controller_url=CONTROLLER, device_type="pfsense", device_id="a/b", session=_FakeSession())


# --- arbitrary-dispatch prevention -----------------------------------


def test_get_json_rejects_raw_string_path():
    """The core anti-generic-dispatch guarantee: get_json() must
    refuse a caller-supplied raw string, even one that happens to
    match an allowed path -- only a NexusEndpointInfo instance defined
    in this codebase is accepted."""

    transport = _transport()
    with pytest.raises(TypeError):
        transport.get_json("/services/carp/status")  # type: ignore[arg-type]


def test_get_json_rejects_arbitrary_endpoint_info_look_alike():
    """Even a structurally-identical NexusEndpointInfo instance for a
    path NOT in NexusEndpoints is technically accepted by the type
    check (since NexusEndpointInfo is a plain frozen dataclass) -- this
    documents that the real allow-list enforcement is "only
    NexusEndpoints' own attributes are ever referenced by this
    codebase," proven by the isolation/no-generic-dispatch structural
    tests, not by get_json() runtime-validating the path string
    itself. This test exists to make that boundary explicit rather
    than silently assumed."""

    off_allow_list = NexusEndpointInfo(path_suffix="/services/carp/enabled")
    respx_route_would_be = f"{DEVICE_BASE}/services/carp/enabled"
    with respx.mock:
        respx.get(respx_route_would_be).mock(return_value=httpx.Response(200, json={}))
        transport = _transport()
        # This call succeeds mechanically (get_json only checks the
        # *type*, not membership in NexusEndpoints) -- the actual
        # security property is that no production code ever
        # constructs a NexusEndpointInfo outside NexusEndpoints itself
        # (see test_no_endpointinfo_constructed_outside_nexusendpoints
        # below).
        transport.get_json(off_allow_list)


def test_no_endpointinfo_constructed_outside_nexusendpoints():
    """AST-level guard: NexusEndpointInfo(...) must only ever be
    called inside the NexusEndpoints class body -- nowhere else in
    the transport module, and never anywhere a caller-supplied value
    could reach it."""

    import ast

    from pfsense_mcp.backends.nexus import transport as transport_module

    tree = ast.parse(inspect.getsource(transport_module))
    endpoints_class_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "NexusEndpoints":
            for sub in ast.walk(node):
                if hasattr(sub, "lineno"):
                    endpoints_class_lines.add(sub.lineno)

    calls_outside_class = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "NexusEndpointInfo"
            and node.lineno not in endpoints_class_lines
        ):
            calls_outside_class.append(node.lineno)

    assert calls_outside_class == [], (
        f"NexusEndpointInfo constructed outside NexusEndpoints at lines {calls_outside_class}"
    )


def test_transport_has_no_mutation_verb_methods():
    """No method on NexusTransport may issue POST/PUT/PATCH/DELETE --
    those verbs exist only inside NexusSession, scoped to /login and
    /login/refresh."""

    forbidden = ("post", "put", "patch", "delete")
    for name in dir(NexusTransport):
        assert not any(name.lower() == verb or name.lower().startswith(verb + "_") for verb in forbidden), (
            f"NexusTransport defines a mutation-shaped member: {name}"
        )


def test_transport_source_never_calls_httpx_mutation_methods():
    """Structural guard: the transport module's source must never
    call .post/.put/.patch/.delete on its httpx client -- only .get."""

    from pfsense_mcp.backends.nexus import transport as transport_module

    source = inspect.getsource(transport_module)
    for verb in ("_client.post(", "_client.put(", "_client.patch(", "_client.delete("):
        assert verb not in source, f"transport.py must never call {verb}"


# --- error handling ---------------------------------------------------


@respx.mock
def test_non_200_response_raises_api_error():
    respx.get(f"{DEVICE_BASE}/services/carp/status").mock(
        return_value=httpx.Response(400, json={"errcode": 1, "errlevel": "error", "errmsg": "bad request"})
    )
    with pytest.raises(PfSenseAPIError):
        _transport().get_json(NexusEndpoints.CARP_STATUS)


@respx.mock
def test_malformed_json_response_fails_closed():
    respx.get(f"{DEVICE_BASE}/services/carp/status").mock(return_value=httpx.Response(200, text="not json"))
    with pytest.raises(PfSenseResponseShapeError):
        _transport().get_json(NexusEndpoints.CARP_STATUS)


@respx.mock
def test_non_object_json_response_fails_closed():
    respx.get(f"{DEVICE_BASE}/services/carp/status").mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    with pytest.raises(PfSenseResponseShapeError):
        _transport().get_json(NexusEndpoints.CARP_STATUS)


@respx.mock
def test_connect_error_raises_connection_error():
    respx.get(f"{DEVICE_BASE}/services/carp/status").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(PfSenseConnectionError):
        _transport().get_json(NexusEndpoints.CARP_STATUS)


@respx.mock
def test_timeout_raises_connection_error():
    respx.get(f"{DEVICE_BASE}/services/carp/status").mock(side_effect=httpx.TimeoutException("boom"))
    with pytest.raises(PfSenseConnectionError):
        _transport().get_json(NexusEndpoints.CARP_STATUS)


@respx.mock
def test_single_request_on_failure_no_retry():
    route = respx.get(f"{DEVICE_BASE}/services/carp/status").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(PfSenseConnectionError):
        _transport().get_json(NexusEndpoints.CARP_STATUS)
    assert route.call_count == 1


@respx.mock
def test_other_httpx_error_message_is_sanitized():
    secret = "SYNTHETIC-SECRET-MUST-NOT-ESCAPE"
    respx.get(f"{DEVICE_BASE}/services/carp/status").mock(side_effect=httpx.RemoteProtocolError(secret))
    with pytest.raises(PfSenseConnectionError) as excinfo:
        _transport().get_json(NexusEndpoints.CARP_STATUS)
    assert secret not in str(excinfo.value)


# --- redaction ------------------------------------------------------


def test_repr_never_contains_token():
    transport = _transport()
    assert "fake-access-token" not in repr(transport)


# --- TLS / timeout / redirect defaults ------------------------------


def test_verify_defaults_to_strict():
    assert inspect.signature(NexusTransport.__init__).parameters["verify"].default is True


def test_no_hardcoded_insecure_verify_in_source():
    """AST-based, not substring-based, so the module's own docstring
    (which quotes Netgate's `verify_ssl=False` example as prose,
    explaining why this module rejects it) can't produce a false
    positive -- only an actual keyword argument in real code counts."""

    import ast

    from pfsense_mcp.backends.nexus import transport as transport_module

    tree = ast.parse(inspect.getsource(transport_module))
    offenders = []
    for node in ast.walk(tree):
        is_verify_kwarg = isinstance(node, ast.keyword) and node.arg in ("verify", "verify_ssl")
        if is_verify_kwarg and isinstance(node.value, ast.Constant) and node.value.value is False:
            offenders.append(node.lineno)
    assert offenders == [], f"hardcoded insecure verify= found at lines {offenders}"


def test_client_does_not_follow_redirects():
    assert _transport()._client.follow_redirects is False


def test_client_has_explicit_default_timeout():
    transport = _transport()
    assert transport._client.timeout.connect == 10.0
    assert transport._client.timeout.read == 30.0


def test_client_accepts_explicit_custom_timeout():
    custom = httpx.Timeout(connect=1.0, read=2.0, write=1.0, pool=1.0)
    transport = _transport(timeout=custom)
    assert transport._client.timeout.connect == 1.0
