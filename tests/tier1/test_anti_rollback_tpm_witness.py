from __future__ import annotations

import httpx
import pytest
import respx

from pfsense_mcp.tier1.anti_rollback_tpm_witness import TpmHostWitnessAnchor
from pfsense_mcp.tier1.errors import AnchorConflictError, AnchorUnavailableError

_BASE_URL = "https://tpm-witness.example.invalid"


def _anchor() -> TpmHostWitnessAnchor:
    return TpmHostWitnessAnchor(client=httpx.Client(), base_url=_BASE_URL)


@respx.mock
def test_read_returns_the_reported_value():
    respx.get(f"{_BASE_URL}/anchor/read").mock(return_value=httpx.Response(200, json={"value": 47}))
    assert _anchor().read() == 47


@respx.mock
def test_read_connect_error_raises_unavailable():
    respx.get(f"{_BASE_URL}/anchor/read").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(AnchorUnavailableError):
        _anchor().read()


@respx.mock
def test_read_timeout_raises_unavailable():
    respx.get(f"{_BASE_URL}/anchor/read").mock(side_effect=httpx.TimeoutException("boom"))
    with pytest.raises(AnchorUnavailableError):
        _anchor().read()


@respx.mock
def test_read_non_200_status_raises_unavailable():
    respx.get(f"{_BASE_URL}/anchor/read").mock(return_value=httpx.Response(500, text="internal error"))
    with pytest.raises(AnchorUnavailableError):
        _anchor().read()


@respx.mock
def test_read_malformed_body_raises_unavailable():
    respx.get(f"{_BASE_URL}/anchor/read").mock(return_value=httpx.Response(200, text="not json"))
    with pytest.raises(AnchorUnavailableError):
        _anchor().read()


@respx.mock
def test_read_missing_value_key_raises_unavailable():
    respx.get(f"{_BASE_URL}/anchor/read").mock(return_value=httpx.Response(200, json={"unexpected": 1}))
    with pytest.raises(AnchorUnavailableError):
        _anchor().read()


@respx.mock
def test_read_negative_value_raises_unavailable():
    respx.get(f"{_BASE_URL}/anchor/read").mock(return_value=httpx.Response(200, json={"value": -1}))
    with pytest.raises(AnchorUnavailableError):
        _anchor().read()


@respx.mock
def test_advance_success_sends_expected_current_and_returns_new_value():
    route = respx.post(f"{_BASE_URL}/anchor/advance").mock(return_value=httpx.Response(200, json={"value": 48}))
    result = _anchor().advance(expected_current=47)
    assert result == 48
    assert route.calls.last.request.content == b'{"expected_current":47}'


@respx.mock
def test_advance_conflict_raises_anchor_conflict():
    respx.post(f"{_BASE_URL}/anchor/advance").mock(return_value=httpx.Response(409))
    with pytest.raises(AnchorConflictError):
        _anchor().advance(expected_current=47)


@respx.mock
def test_advance_connect_error_raises_unavailable():
    respx.post(f"{_BASE_URL}/anchor/advance").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(AnchorUnavailableError):
        _anchor().advance(expected_current=47)


@respx.mock
def test_advance_timeout_raises_unavailable():
    respx.post(f"{_BASE_URL}/anchor/advance").mock(side_effect=httpx.TimeoutException("boom"))
    with pytest.raises(AnchorUnavailableError):
        _anchor().advance(expected_current=47)


@respx.mock
def test_advance_unexpected_status_raises_unavailable():
    respx.post(f"{_BASE_URL}/anchor/advance").mock(return_value=httpx.Response(503, text="unavailable"))
    with pytest.raises(AnchorUnavailableError):
        _anchor().advance(expected_current=47)


@respx.mock
def test_advance_malformed_body_raises_unavailable():
    respx.post(f"{_BASE_URL}/anchor/advance").mock(return_value=httpx.Response(200, text="not json"))
    with pytest.raises(AnchorUnavailableError):
        _anchor().advance(expected_current=47)


def test_advance_rejects_negative_expected_current():
    with pytest.raises(AnchorUnavailableError):
        _anchor().advance(expected_current=-1)
