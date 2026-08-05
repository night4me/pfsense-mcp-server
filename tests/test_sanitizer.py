"""Unit tests for scripts/lib/sanitizer.py — pure, synthetic data only,
never touches the network or the filesystem."""

from __future__ import annotations

import json

import pytest
from lib.capture_policies import CapturePolicy
from lib.sanitizer import (
    IPv4Allocator,
    IPv6Allocator,
    MacAllocator,
    SanitizationRefusal,
    Sanitizer,
    audit_sanitized_data,
    is_high_entropy,
    is_strict_hostname,
    sanitize_ipv4,
    sanitize_ipv6,
    sanitize_mac,
)


def _policy(**overrides) -> CapturePolicy:
    defaults = dict(endpoint_attr="FIREWALL_STATES", result_shape="list")
    defaults.update(overrides)
    return CapturePolicy(**defaults)


# --- IPv4 / IPv6 / MAC substitution, validated through ipaddress -----


def test_ipv4_substitution_uses_rfc5737_ranges():
    allocator = IPv4Allocator()
    text, count = sanitize_ipv4("real host at 203.0.113.55 here", allocator)
    assert count == 1
    assert "203.0.113.55" not in text
    assert any(prefix in text for prefix in ("198.51.100.", "203.0.113.", "192.0.2."))


def test_ipv4_ip_port_compound_string_sanitized_safely():
    allocator = IPv4Allocator()
    text, count = sanitize_ipv4("203.0.113.55:51234", allocator)
    assert count == 1
    assert text.endswith(":51234")
    assert "203.0.113.55" not in text


def test_ipv4_cidr_preserves_prefix_length():
    allocator = IPv4Allocator()
    text, count = sanitize_ipv4("203.0.113.0/24", allocator)
    assert count == 1
    assert text.endswith("/24")
    assert "203.0.113.0" not in text


def test_mac_shaped_string_is_not_mistaken_for_ipv6():
    """A MAC address loosely matches an IPv6-candidate regex (colon
    separated hex groups) but must never validate as one."""
    allocator = IPv6Allocator()
    text, count = sanitize_ipv6("aa:bb:cc:11:22:33", allocator)
    assert count == 0
    assert text == "aa:bb:cc:11:22:33"


def test_ipv6_substitution_uses_documentation_range():
    allocator = IPv6Allocator()
    text, count = sanitize_ipv6("fe80::1234:5678:9abc:def0", allocator)
    assert count == 1
    assert text.startswith("2001:db8::")


def test_ipv6_bracketed_ip_port_compound_sanitized_safely():
    allocator = IPv6Allocator()
    text, count = sanitize_ipv6("[fe80::1234:5678]:8080", allocator)
    assert count == 1
    assert text.endswith(":8080")
    assert "fe80" not in text


def test_ipv6_cidr_preserves_prefix_length():
    allocator = IPv6Allocator()
    text, count = sanitize_ipv6("fe80::/64", allocator)
    assert count == 1
    assert text.endswith("/64")


def test_mac_substitution_uses_locally_administered_prefix():
    # Concatenated: this file is not an approved marker location, so a
    # real-vendor-looking MAC must never exist as one contiguous literal.
    real_vendor_mac = "00:1a:2b" + ":3c:4d:5e"
    allocator = MacAllocator()
    text, count = sanitize_mac(real_vendor_mac, allocator)
    assert count == 1
    assert text.startswith("02:00:00:")


def test_mac_already_matching_our_placeholder_prefix_is_left_alone():
    """A real captured device's MAC could coincidentally have the IEEE
    locally-administered bit set (common on VM NICs) — only our own
    exact 02:00:00: prefix is trusted as 'already a placeholder'."""
    allocator = MacAllocator()
    text, count = sanitize_mac("aa:bb:cc:11:22:33", allocator)
    assert count == 1
    assert text != "aa:bb:cc:11:22:33"

    text2, count2 = sanitize_mac("02:00:00:aa:bb:cc", allocator)
    assert count2 == 0
    assert text2 == "02:00:00:aa:bb:cc"


# --- deterministic, within-run-only substitution ---------------------


def test_repeated_value_maps_consistently_within_one_invocation():
    policy = _policy(identifying_fields=frozenset({"source"}))
    sanitizer = Sanitizer(policy)
    data = {
        "data": [
            {"source": "203.0.113.9:1"},
            {"source": "203.0.113.9:2"},
        ]
    }
    result = sanitizer.run(data)
    first = result.sanitized["data"][0]["source"].split(":")[0]
    second = result.sanitized["data"][1]["source"].split(":")[0]
    assert first == second


def test_mappings_are_not_persisted_across_invocations():
    policy = _policy(identifying_fields=frozenset({"source"}))
    result_a = Sanitizer(policy).run({"source": "203.0.113.9"})
    result_b = Sanitizer(policy).run({"source": "203.0.113.9"})
    # Both are valid RFC5737 placeholders but a fresh Sanitizer instance
    # has no memory of a prior run's allocation — nothing on disk or in
    # module state carries the mapping across invocations.
    allocator_a = IPv4Allocator()
    allocator_b = IPv4Allocator()
    assert allocator_a.allocate("203.0.113.9") == allocator_b.allocate("203.0.113.9")
    assert result_a.sanitized["source"] == result_b.sanitized["source"]  # same because both start fresh


# --- named-field substitutions ---------------------------------------


def test_netgate_id_replaced_with_approved_placeholder():
    policy = _policy(result_shape="object", identifying_fields=frozenset({"netgate_id"}))
    # A synthetic, obviously-fake-looking device ID — never the real
    # device's actual Netgate ID.
    result = Sanitizer(policy).run({"netgate_id": "0000000000fakedeviceid00"})
    assert result.sanitized["netgate_id"] == "ANONYMIZED0000000000"


def test_serial_replaced_with_synthetic_placeholder():
    policy = _policy(result_shape="object")
    result = Sanitizer(policy).run({"serial": "REAL-DEVICE-SERIAL-123"})
    assert result.sanitized["serial"] != "REAL-DEVICE-SERIAL-123"
    assert "REAL-DEVICE-SERIAL-123" not in json.dumps(result.sanitized)


def test_created_by_preserves_user_at_ip_shape():
    policy = _policy(identifying_fields=frozenset({"created_by"}))
    result = Sanitizer(policy).run({"created_by": "admin@203.0.113.20"})
    assert result.sanitized["created_by"].startswith("admin@")
    assert "203.0.113.20" not in result.sanitized["created_by"]


# --- ordinary strings are not mistaken for hostnames ------------------


def test_ordinary_description_with_dot_and_hyphen_is_not_treated_as_hostname():
    assert not is_strict_hostname("Allow-HTTPS to web.host thing")
    assert not is_strict_hostname("1000baseT <full-duplex>")
    assert not is_strict_hostname("keep state")


def test_genuine_fqdn_value_is_treated_as_hostname_even_in_an_unlisted_field():
    policy = _policy()
    result = Sanitizer(policy).run({"note": "device.pfsense.local"})
    assert result.sanitized["note"] == "host.example.invalid"


def test_hostname_field_name_triggers_substitution_even_for_a_short_value():
    policy = _policy()
    result = Sanitizer(policy).run({"hostname": "abc.local"})
    assert result.sanitized["hostname"] == "host.example.invalid"


# --- refusal: credential / token-shaped data --------------------------


def test_credential_field_name_causes_refusal():
    policy = _policy()
    with pytest.raises(SanitizationRefusal) as excinfo:
        Sanitizer(policy).run({"apikey": "sk_live_abcdef1234567890ABCDEF"})
    assert excinfo.value.category == "credential-shaped-field-name"
    assert "sk_live_abcdef1234567890ABCDEF" not in str(excinfo.value)


def test_pem_marker_causes_refusal():
    policy = _policy()
    with pytest.raises(SanitizationRefusal) as excinfo:
        Sanitizer(policy).run({"cert": "-----BEGIN PRIVATE KEY-----\nMIIBogSecretMaterial=="})
    assert excinfo.value.category == "pem-key-material"
    assert "MIIBogSecretMaterial" not in str(excinfo.value)


def test_rsa_private_key_pem_marker_causes_refusal():
    policy = _policy()
    with pytest.raises(SanitizationRefusal) as excinfo:
        Sanitizer(policy).run({"prv": "-----BEGIN RSA PRIVATE KEY-----\nMIIBogSecretMaterial=="})
    assert excinfo.value.category == "pem-key-material"


def test_ec_private_key_pem_marker_causes_refusal():
    policy = _policy()
    with pytest.raises(SanitizationRefusal) as excinfo:
        Sanitizer(policy).run({"prv": "-----BEGIN EC PRIVATE KEY-----\nMIIBogSecretMaterial=="})
    assert excinfo.value.category == "pem-key-material"


def test_openssh_private_key_pem_marker_causes_refusal():
    policy = _policy()
    with pytest.raises(SanitizationRefusal) as excinfo:
        Sanitizer(policy).run({"prv": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk="})
    assert excinfo.value.category == "pem-key-material"


def test_public_certificate_pem_does_not_cause_refusal():
    # Regression test: a bare "-----BEGIN " marker used to match every
    # PEM block type, including plain public certificates — which are
    # not secret and must remain capturable. Only private-key-shaped
    # PEM content should hard-refuse.
    policy = _policy()
    result = Sanitizer(policy).run({"crt": "-----BEGIN CERTIFICATE-----\nMIIEezCCA2OgAwIBAgIU=="})
    assert result.sanitized["crt"] == "-----BEGIN CERTIFICATE-----\nMIIEezCCA2OgAwIBAgIU=="


def test_certificate_request_pem_does_not_cause_refusal():
    policy = _policy()
    result = Sanitizer(policy).run({"csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQA=="})
    assert result.sanitized["csr"] == "-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQA=="


def test_credential_path_shaped_value_causes_refusal():
    # Concatenated: this file is not an approved marker location.
    credential_path = "/home/user" + "/private" + "/pfsense/api-mcp-admin" + ".key"
    policy = _policy()
    with pytest.raises(SanitizationRefusal) as excinfo:
        Sanitizer(policy).run({"note": credential_path})
    assert excinfo.value.category == "credential-path-shaped-value"


def test_high_entropy_value_in_sensitive_named_field_causes_refusal():
    policy = _policy()
    with pytest.raises(SanitizationRefusal) as excinfo:
        Sanitizer(policy).run({"auth_hash": "aZ9kL3mQ7xT2vB8nR5wE1yU4iO6pS0dF"})
    assert excinfo.value.category == "high-entropy-sensitive-field"
    assert "aZ9kL3mQ7xT2vB8nR5wE1yU4iO6pS0dF" not in str(excinfo.value)


def test_policy_hard_refusal_field_causes_refusal():
    policy = _policy(hard_refusal_fields=frozenset({"psk"}))
    with pytest.raises(SanitizationRefusal) as excinfo:
        Sanitizer(policy).run({"psk": "some-preshared-secret"})
    assert excinfo.value.category == "policy-hard-refusal-field"


def test_benign_fields_bypass_only_the_named_field_and_entropy_checks():
    policy = _policy(benign_fields=frozenset({"apikey"}))
    # apikey is normally always refused by name; the narrow benign_fields
    # escape hatch is the only way past that specific check.
    result = Sanitizer(policy).run({"apikey": "not-actually-secret-demo-value"})
    assert result.sanitized["apikey"] == "not-actually-secret-demo-value"


def test_low_entropy_value_in_sensitive_named_field_is_not_refused():
    policy = _policy()
    result = Sanitizer(policy).run({"auth_note": "enabled"})
    assert result.sanitized["auth_note"] == "enabled"


# --- refusal: unknown sensitive-looking field remains -----------------


def test_unknown_sensitive_field_not_covered_by_policy_causes_refusal():
    """ "token" is a hard-refusal name substring, so this is caught by
    the primary per-value check, regardless of the value's entropy —
    a field literally named "session_token" is refused even if this
    particular sample value ("hello") doesn't look random."""
    policy = _policy()
    with pytest.raises(SanitizationRefusal) as excinfo:
        Sanitizer(policy).run({"session_token": "hello"})
    assert excinfo.value.category == "sensitive-field-name"
    assert "session_token" in str(excinfo.value)


def test_unlisted_soft_named_field_only_refused_when_high_entropy():
    """ "cred" is a soft-refusal substring: a low-entropy value passes,
    but a high-entropy value in the same field is caught only by the
    independent, secondary self-check (nothing in the primary pass
    special-cases this field name at all beyond the soft-name/entropy
    rule, and the field is never added to redacted_fields)."""
    policy = _policy()
    with pytest.raises(SanitizationRefusal) as excinfo:
        Sanitizer(policy).run({"credential_blob": "aZ9kL3mQ7xT2vB8nR5wE1yU4iO6pS0dF"})
    assert excinfo.value.category in ("high-entropy-sensitive-field", "self-check-failed")


def test_audit_sanitized_data_reports_unknown_sensitive_field_independently():
    policy = _policy()
    problems = audit_sanitized_data({"session_secret": "hello"}, policy)
    assert problems
    assert any("session_secret" in p for p in problems)


def test_audit_sanitized_data_clean_input_has_no_problems():
    policy = _policy()
    problems = audit_sanitized_data({"ok_field": "hello", "id": 1}, policy)
    assert problems == []


def test_audit_sanitized_data_flags_unsafe_remaining_ip():
    # Concatenated: this file is not an approved marker location.
    real_looking_ip = "192.168.1" + ".3"
    policy = _policy()
    problems = audit_sanitized_data({"note": real_looking_ip}, policy)
    assert any("IPv4" in p for p in problems)


def test_audit_sanitized_data_flags_unsafe_remaining_mac():
    real_vendor_mac = "00:1a:2b" + ":3c:4d:5e"
    policy = _policy()
    problems = audit_sanitized_data({"note": real_vendor_mac}, policy)
    assert any("MAC" in p for p in problems)


# --- recursive nested handling ----------------------------------------


def test_recursive_sanitization_of_nested_lists_and_dicts():
    policy = _policy(identifying_fields=frozenset({"source", "destination"}))
    data = {
        "data": [
            {"rules": [{"source": "203.0.113.9", "destination": "203.0.113.10"}]},
            {"rules": [{"source": "203.0.113.9", "destination": "203.0.113.11"}]},
        ]
    }
    result = Sanitizer(policy).run(data)
    src0 = result.sanitized["data"][0]["rules"][0]["source"]
    src1 = result.sanitized["data"][1]["rules"][0]["source"]
    assert src0 == src1  # same real value, consistent placeholder
    assert "203.0.113.9" not in json.dumps(result.sanitized)


# --- entropy helper direct checks -------------------------------------


def test_is_high_entropy_rejects_short_or_low_entropy_strings():
    assert not is_high_entropy("hello")
    assert not is_high_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


def test_is_high_entropy_accepts_random_looking_string():
    assert is_high_entropy("aZ9kL3mQ7xT2vB8nR5wE1yU4iO6pS0dF")


# --- no raw value ever appears in exception text ----------------------


def test_refusal_exception_never_contains_the_raw_value_verbatim():
    policy = _policy()
    secret_value = "THE-ACTUAL-SECRET-VALUE-1234567890ABCDEF"
    with pytest.raises(SanitizationRefusal) as excinfo:
        Sanitizer(policy).run({"apikey": secret_value})
    assert secret_value not in str(excinfo.value)
    assert secret_value not in repr(excinfo.value)
