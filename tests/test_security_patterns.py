"""Unit tests for scripts/lib/security_patterns.py — the shared, generic
pattern helpers used by security_scan.py and fixture_safety.py."""

from __future__ import annotations

from lib.security_patterns import find_ipv4_literals, find_mac_literals, is_locally_administered_mac, is_safe_ipv4


def test_is_safe_ipv4_accepts_all_three_rfc5737_ranges():
    assert is_safe_ipv4("192.0.2.1")
    assert is_safe_ipv4("198.51.100.10")
    assert is_safe_ipv4("203.0.113.5")


def test_is_safe_ipv4_accepts_loopback():
    assert is_safe_ipv4("127.0.0.1")


def test_is_safe_ipv4_accepts_netmask_literals():
    assert is_safe_ipv4("255.255.255.0")
    assert is_safe_ipv4("255.255.0.0")


def test_is_safe_ipv4_rejects_real_lan_ip():
    assert not is_safe_ipv4("192.168.1.3")  # security-scan: allow


def test_is_safe_ipv4_rejects_public_ip():
    assert not is_safe_ipv4("8.8.8.8")  # security-scan: allow


def test_find_ipv4_literals_extracts_all_addresses_from_text():
    text = "host at 192.168.1.3 and 198.51.100.10, mask 255.255.255.0"  # security-scan: allow
    assert find_ipv4_literals(text) == ["192.168.1.3", "198.51.100.10", "255.255.255.0"]  # security-scan: allow


def test_is_locally_administered_mac_accepts_project_placeholder():
    assert is_locally_administered_mac("02:00:00:aa:bb:cc")


def test_is_locally_administered_mac_rejects_real_vendor_prefix():
    # 00:1a:2b:... has the locally-administered bit (0x02) unset.
    assert not is_locally_administered_mac("00:1a:2b:3c:4d:5e")  # security-scan: allow


def test_find_mac_literals_extracts_full_matches():
    text = "interface mac 02:00:00:aa:bb:cc here"
    assert find_mac_literals(text) == ["02:00:00:aa:bb:cc"]
