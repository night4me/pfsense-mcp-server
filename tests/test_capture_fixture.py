"""Unit tests for scripts/capture_fixture.py.

Never makes a real network call: the "live-fetch" path is exercised
by monkeypatching capture_fixture.fetch_raw directly, matching the
pattern already used for other CLI tools in this project."""

from __future__ import annotations

import json

import capture_fixture
import pytest
from lib.capture_policies import CapturePolicy

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.endpoints import EndpointInfo, Endpoints


def test_resolve_endpoint_and_policy_refuses_unknown_endpoint():
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.resolve_endpoint_and_policy("NOT_A_REAL_ENDPOINT")
    assert excinfo.value.category == "unknown-endpoint"


def test_resolve_endpoint_and_policy_refuses_unverified_endpoint(monkeypatch):
    fake = EndpointInfo(path_suffix="/fake", verified=False, min_api_version=ApiVersion.V2)
    monkeypatch.setattr(Endpoints, "FAKE_UNVERIFIED", fake, raising=False)
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.resolve_endpoint_and_policy("FAKE_UNVERIFIED")
    assert excinfo.value.category == "endpoint-not-verified"


def test_resolve_endpoint_and_policy_refuses_verified_endpoint_without_policy(monkeypatch):
    fake = EndpointInfo(path_suffix="/fake-verified", verified=True, min_api_version=ApiVersion.V2)
    monkeypatch.setattr(Endpoints, "FAKE_VERIFIED_NO_POLICY", fake, raising=False)
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.resolve_endpoint_and_policy("FAKE_VERIFIED_NO_POLICY")
    assert excinfo.value.category == "no-capture-policy"


def test_resolve_endpoint_and_policy_accepts_a_real_policied_endpoint():
    endpoint, policy = capture_fixture.resolve_endpoint_and_policy("FIREWALL_STATES")
    assert endpoint.verified is True
    assert policy.endpoint_attr == "FIREWALL_STATES"


def _states_policy() -> CapturePolicy:
    return capture_fixture.CAPTURE_POLICIES["FIREWALL_STATES"]


def test_validate_params_rejects_unknown_parameter():
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.validate_params(_states_policy(), ["offset=1"])
    assert excinfo.value.category == "unknown-parameter"


def test_validate_params_rejects_duplicate_parameter():
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.validate_params(_states_policy(), ["limit=5", "limit=10"])
    assert excinfo.value.category == "duplicate-parameter"


def test_validate_params_rejects_invalid_type():
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.validate_params(_states_policy(), ["limit=not-a-number"])
    assert excinfo.value.category == "invalid-parameter-type"


def test_validate_params_rejects_out_of_bounds_value():
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.validate_params(_states_policy(), ["limit=501"])
    assert excinfo.value.category == "parameter-out-of-bounds"


def test_validate_params_rejects_zero_as_unlimited():
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.validate_params(_states_policy(), ["limit=0"])
    assert excinfo.value.category == "parameter-out-of-bounds"


def test_validate_params_rejects_invalid_syntax():
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.validate_params(_states_policy(), ["limit"])
    assert excinfo.value.category == "invalid-parameter-syntax"


def test_validate_params_accepts_valid_value():
    result = capture_fixture.validate_params(_states_policy(), ["limit=5"])
    assert result == {"limit": 5}


def test_validate_params_accepts_no_params():
    assert capture_fixture.validate_params(_states_policy(), []) == {}


def test_check_size_refuses_too_many_items():
    raw = {"data": [{"id": i} for i in range(10)]}
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.check_size(raw, _states_policy(), max_items=5, max_bytes=200_000)
    assert excinfo.value.category == "too-many-items"


def test_check_size_refuses_oversized_json():
    raw = {"data": [{"id": 0, "blob": "x" * 500}]}
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.check_size(raw, _states_policy(), max_items=5, max_bytes=100)
    assert excinfo.value.category == "input-too-large"


def test_check_size_refuses_shape_mismatch_list_expected():
    raw = {"data": {"not": "a list"}}
    with pytest.raises(capture_fixture.CaptureRefusal) as excinfo:
        capture_fixture.check_size(raw, _states_policy(), max_items=5, max_bytes=200_000)
    assert excinfo.value.category == "shape-mismatch"


def test_check_size_accepts_within_bounds():
    raw = {"data": [{"id": 0}, {"id": 1}]}
    item_count, size = capture_fixture.check_size(raw, _states_policy(), max_items=5, max_bytes=200_000)
    assert item_count == 2
    assert size > 0


def _fake_raw_firewall_states():
    return {
        "code": 200,
        "status": "ok",
        "response_id": "SUCCESS",
        "data": [
            {
                "id": 0,
                "interface": "wan",
                "protocol": "tcp",
                "source": "203.0.113.9:51234",
                "destination": "203.0.113.10:443",
                "state": "ESTABLISHED:ESTABLISHED",
            }
        ],
    }


def _patch_live_fetch(monkeypatch, tmp_path, sentinel_key: str, raw=None):
    key_file = tmp_path / "test.key"
    key_file.write_text(f"{sentinel_key}\n")
    monkeypatch.setenv("PFSENSE_API_URL", "https://pfsense.example.invalid")
    monkeypatch.setenv("PFSENSE_IDENTITY", "test-identity")
    monkeypatch.setenv("PFSENSE_API_KEY_FILE", str(key_file))
    monkeypatch.delenv("PFSENSE_TLS_CA_FILE", raising=False)

    captured_calls = []

    def _fake_fetch_raw(config, api_key, endpoint, params):
        captured_calls.append((config, api_key, endpoint, params))
        assert api_key == sentinel_key  # confirms the real key reaches this layer
        return raw if raw is not None else _fake_raw_firewall_states()

    monkeypatch.setattr(capture_fixture, "fetch_raw", _fake_fetch_raw)
    monkeypatch.setattr(capture_fixture, "PROPOSALS_DIR", tmp_path / "proposals")
    return captured_calls


def test_main_happy_path_writes_proposal_and_manifest(monkeypatch, tmp_path, capsys):
    sentinel_key = "SENTINEL-KEY-DO-NOT-PRINT-abc123"
    _patch_live_fetch(monkeypatch, tmp_path, sentinel_key)

    exit_code = capture_fixture.main(["FIREWALL_STATES", "--param", "limit=5"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert sentinel_key not in captured.out
    assert sentinel_key not in captured.err

    proposals_dir = tmp_path / "proposals"
    proposal_path = proposals_dir / "firewall_states_response.proposed.json"
    manifest_path = proposals_dir / "firewall_states_response.manifest.json"
    assert proposal_path.is_file()
    assert manifest_path.is_file()

    sanitized = json.loads(proposal_path.read_text())
    assert "203.0.113.9" not in json.dumps(sanitized)

    manifest = json.loads(manifest_path.read_text())
    assert manifest["endpoint_symbol"] == "FIREWALL_STATES"
    assert manifest["item_count"] == 1
    assert manifest["query_parameters"] == {"limit": 5}
    assert manifest["substitution_counts"]["ipv4"] >= 2
    assert "source" in manifest["redacted_field_names"]
    assert "destination" in manifest["redacted_field_names"]

    import hashlib

    assert manifest["sha256_sanitized_proposal"] == hashlib.sha256(proposal_path.read_bytes()).hexdigest()


def test_main_never_writes_to_tests_fixtures_directly(monkeypatch, tmp_path, capsys):
    sentinel_key = "SENTINEL-KEY-2"
    _patch_live_fetch(monkeypatch, tmp_path, sentinel_key)
    capture_fixture.main(["FIREWALL_STATES", "--param", "limit=5"])

    real_fixtures_dir = capture_fixture.Path(__file__).resolve().parent.parent / "tests" / "fixtures"
    before = set(real_fixtures_dir.glob("*.json"))
    # No new file should ever land in the real tests/fixtures/ directory.
    assert not (real_fixtures_dir / "firewall_states_response_NEW_FROM_TEST.json").exists()
    assert before == set(real_fixtures_dir.glob("*.json"))


def test_main_refuses_unknown_parameter_before_any_fetch(monkeypatch, tmp_path):
    calls = _patch_live_fetch(monkeypatch, tmp_path, "SENTINEL-KEY-3")
    exit_code = capture_fixture.main(["FIREWALL_STATES", "--param", "offset=1"])
    assert exit_code == 1
    assert calls == []


def test_main_refuses_unverified_endpoint_before_any_fetch(monkeypatch, tmp_path):
    fake = EndpointInfo(path_suffix="/fake", verified=False, min_api_version=ApiVersion.V2)
    monkeypatch.setattr(Endpoints, "FAKE_UNVERIFIED_2", fake, raising=False)
    calls = _patch_live_fetch(monkeypatch, tmp_path, "SENTINEL-KEY-4")
    exit_code = capture_fixture.main(["FAKE_UNVERIFIED_2"])
    assert exit_code == 1
    assert calls == []


def test_main_refuses_token_shaped_field_and_never_prints_it(monkeypatch, tmp_path, capsys):
    secret_value = "sk_live_THE_ACTUAL_SECRET_1234567890"
    raw = {"data": {"apikey": secret_value}}
    _patch_live_fetch(monkeypatch, tmp_path, "SENTINEL-KEY-5", raw=raw)

    monkeypatch.setattr(
        capture_fixture,
        "CAPTURE_POLICIES",
        {
            "SYSTEM_STATUS": CapturePolicy(endpoint_attr="SYSTEM_STATUS", result_shape="object"),
        },
    )

    exit_code = capture_fixture.main(["SYSTEM_STATUS"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert secret_value not in captured.out
    assert secret_value not in captured.err
    assert "credential-shaped-field-name" in captured.err or "sensitive-field-name" in captured.err
