"""Unit tests for scripts/fixture_safety.py, using synthetic in-memory
JSON text rather than the real tests/fixtures/*.json files."""

from __future__ import annotations

import json

import pytest
from fixture_safety import check_fixture_text


def _body(data) -> str:
    return json.dumps({"code": 200, "status": "ok", "response_id": "SUCCESS", "data": data})


def test_check_fixture_text_flags_non_rfc5737_ip():
    failures, advisories = check_fixture_text("fake.json", _body([{"source": "192.168.1.3"}]))  # security-scan: allow
    assert any("192.168.1.3" in f for f in failures)  # security-scan: allow
    assert advisories == []


def test_check_fixture_text_passes_rfc5737_ip():
    failures, _advisories = check_fixture_text("fake.json", _body([{"source": "198.51.100.10"}]))
    assert failures == []


def test_check_fixture_text_flags_mac_without_locally_administered_bit():
    body = _body([{"macaddr": "00:1a:2b:3c:4d:5e"}])  # security-scan: allow
    failures, _advisories = check_fixture_text("fake.json", body)
    assert any("00:1a:2b:3c:4d:5e" in f for f in failures)  # security-scan: allow


def test_check_fixture_text_passes_locally_administered_mac():
    failures, _advisories = check_fixture_text("fake.json", _body([{"macaddr": "02:00:00:aa:bb:cc"}]))
    assert failures == []


def test_check_fixture_text_flags_non_placeholder_netgate_id():
    not_the_placeholder = "SYNTHETIC-NOT-THE-APPROVED-PLACEHOLDER"
    failures, _advisories = check_fixture_text("fake.json", _body({"netgate_id": not_the_placeholder}))
    assert any("netgate_id" in f for f in failures)


def test_check_fixture_text_passes_anonymized_netgate_id_placeholder():
    failures, _advisories = check_fixture_text("fake.json", _body({"netgate_id": "ANONYMIZED0000000000"}))
    assert failures == []


def test_check_fixture_text_flags_credential_path():
    body = _body({"note": "~/private/pfsense/api-mcp-admin.key"})  # security-scan: allow
    failures, _advisories = check_fixture_text("fake.json", body)
    assert any("api-mcp-admin.key" in f for f in failures)  # security-scan: allow


def test_check_fixture_text_flags_suspiciously_large_data_array_as_advisory_only():
    large_data = [{"id": i} for i in range(20)]
    failures, advisories = check_fixture_text("fake.json", _body(large_data))
    assert failures == []
    assert len(advisories) == 1
    assert "20 entries" in advisories[0]


def test_check_fixture_text_small_data_array_has_no_advisory():
    small_data = [{"id": i} for i in range(2)]
    _failures, advisories = check_fixture_text("fake.json", _body(small_data))
    assert advisories == []


@pytest.mark.parametrize("field", ["ipsecpsk", "password", "key"])
def test_check_fixture_text_rejects_prohibited_credential_field_even_when_empty(field):
    failures, _advisories = check_fixture_text("fake.json", _body([{field: None}]))
    assert any("prohibited credential field" in failure for failure in failures)
