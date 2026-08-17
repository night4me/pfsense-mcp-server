"""Unit tests for scripts/get_only_check.py, using a synthetic
temporary directory rather than the real src/pfsense_mcp tree."""

from __future__ import annotations

from get_only_check import _ALLOWED_CALLERS, find_request_call_sites, main


def test_passes_when_only_rest_api_client_calls_transport_request(tmp_path):
    (tmp_path / "rest_api_client.py").write_text("self._transport.request(method, path)\n")
    (tmp_path / "other.py").write_text("self._client.request(method, path)\n")  # a *different* receiver, not Transport

    hits = find_request_call_sites(tmp_path)

    assert hits == {"rest_api_client.py": 1}


def test_write_api_client_is_also_an_allowed_caller(tmp_path):
    (tmp_path / "rest_api_client.py").write_text("self._transport.request(method, path)\n")
    (tmp_path / "write_api_client.py").write_text("self._transport.request(method, path)\n")
    (tmp_path / "security_bootstrap_client.py").write_text("self._transport.request(method, path)\n")

    hits = find_request_call_sites(tmp_path)

    assert hits == {"rest_api_client.py": 1, "write_api_client.py": 1, "security_bootstrap_client.py": 1}
    assert set(hits) == set(_ALLOWED_CALLERS)


def test_flags_a_second_transport_request_call_site(tmp_path):
    (tmp_path / "rest_api_client.py").write_text("self._transport.request(method, path)\n")
    (tmp_path / "bypass.py").write_text("self._transport.request('GET', path)\n")

    hits = find_request_call_sites(tmp_path)

    assert "bypass.py" in hits
    assert hits["bypass.py"] == 1


def test_does_not_flag_unrelated_dot_request_calls(tmp_path):
    (tmp_path / "unrelated.py").write_text("self._httpx_client.request(method, path)\n")

    hits = find_request_call_sites(tmp_path)

    assert hits == {}


def test_main_passes_against_the_real_source_tree():
    assert main() == 0
