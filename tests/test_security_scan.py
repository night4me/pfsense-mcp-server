"""Unit tests for scripts/security_scan.py, using synthetic in-memory
text rather than the real repository tree.

This file is one of the three entries in security_scan.py's own
_APPROVED_MARKER_FILES allow-list, so a `security-scan: allow` marker
IS honored here — deliberately, since these tests must embed
known-bad example values (a real-looking IP, a vendor MAC, a
credential path) to prove the checkers catch them. Every such line
below carries the marker for that reason. The regression tests further
down prove the marker does NOT work anywhere else (src/, scripts/,
tests/fixtures/), and that using it there is itself reported.
"""

from __future__ import annotations

from pathlib import Path

from security_scan import _APPROVED_MARKER_FILES, _SUPPRESSION_MARKER, scan_line, scan_text

_APPROVED_PATH = Path("tests/test_security_scan.py")


def test_scan_text_flags_real_lan_ip():
    findings = scan_text(Path("fake/file.py"), 'HOST = "192.168.1.3"')  # security-scan: allow
    assert any("192.168.1.3" in f for f in findings)  # security-scan: allow


def test_scan_text_passes_rfc5737_ip():
    findings = scan_text(Path("fake/file.py"), 'HOST = "198.51.100.10"')
    assert findings == []


def test_scan_text_flags_mac_without_locally_administered_bit():
    findings = scan_text(Path("fake/file.py"), 'MAC = "00:1a:2b:3c:4d:5e"')  # security-scan: allow
    assert any("00:1a:2b:3c:4d:5e" in f for f in findings)  # security-scan: allow


def test_scan_text_passes_locally_administered_mac():
    findings = scan_text(Path("fake/file.py"), 'MAC = "02:00:00:aa:bb:cc"')
    assert findings == []


def test_scan_text_flags_credential_path_pattern():
    line = 'KEY_FILE = "~/private/pfsense/api-mcp-admin.key"'  # security-scan: allow
    findings = scan_text(Path("fake/file.py"), line)
    assert any("api-mcp-admin.key" in f for f in findings)  # security-scan: allow


def test_approved_marker_suppresses_only_that_line():
    """An authorized marker (path is in _APPROVED_MARKER_FILES) on one
    line suppresses only that line's finding."""
    findings = scan_line(_APPROVED_PATH, 1, 'KNOWN_TEST_VALUE = "192.168.1.3"  # security-scan: allow')
    assert findings == []


def test_unmarked_line_in_an_approved_file_with_a_marked_line_is_still_flagged():
    """The mechanism this test proves: a suppression marker is
    line-scoped, not file-scoped, even within an approved file. A
    marked line's known-bad value is suppressed, but a *different*
    unmarked line in the exact same text blob — a real leaked value
    would land here — is still caught."""
    text = "\n".join(
        [
            'KNOWN_TEST_VALUE = "192.168.1.3"  # security-scan: allow',
            'ACCIDENTAL_LEAK = "192.168.1.99"',  # security-scan: allow (marks this source line only — the
        ]  # string value fed to scan_text() below intentionally has no marker inside it)
    )
    findings = scan_text(_APPROVED_PATH, text)
    assert any("192.168.1.99" in f for f in findings)  # security-scan: allow
    assert not any('192.168.1.3"' in f for f in findings)  # security-scan: allow


def test_marker_does_not_work_in_src():
    line = 'LEAK = "192.168.1.3"  # security-scan: allow'  # security-scan: allow
    findings = scan_line(Path("src/pfsense_mcp/pfsense_client.py"), 1, line)
    assert any("192.168.1.3" in f for f in findings)  # security-scan: allow
    assert any("unauthorized suppression marker" in f for f in findings)


def test_marker_does_not_work_in_scripts():
    line = 'LEAK = "192.168.1.3"  # security-scan: allow'  # security-scan: allow
    findings = scan_line(Path("scripts/security_scan.py"), 1, line)
    assert any("192.168.1.3" in f for f in findings)  # security-scan: allow
    assert any("unauthorized suppression marker" in f for f in findings)


def test_marker_does_not_work_in_tests_fixtures():
    line = 'LEAK = "192.168.1.3"  # security-scan: allow'  # security-scan: allow
    findings = scan_line(Path("tests/fixtures/firewall_states_response.json"), 1, line)
    assert any("192.168.1.3" in f for f in findings)  # security-scan: allow
    assert any("unauthorized suppression marker" in f for f in findings)


def test_unauthorized_marker_is_itself_reported():
    """Even on a line with no other finding at all, an unauthorized
    marker is reported in its own right."""
    findings = scan_line(Path("src/pfsense_mcp/pfsense_client.py"), 7, "x = 1  # security-scan: allow")
    assert len(findings) == 1
    assert "unauthorized suppression marker" in findings[0]
    assert "src/pfsense_mcp/pfsense_client.py:7" in findings[0]


def test_no_file_path_is_wholly_exempt_from_scanning():
    """Regression guard against reintroducing a whole-file exclusion
    list: even a path name identical to security_scan.py's own file,
    or to one of this project's approved test files, must still be
    scanned line by line when the value itself carries no marker —
    only an explicit, authorized per-line marker suppresses anything."""
    for path_str in (
        "scripts/security_scan.py",
        "scripts/fixture_safety.py",
        "tests/test_security_patterns.py",
        "tests/test_security_scan.py",
        "tests/test_fixture_safety.py",
        "src/pfsense_mcp/pfsense_client.py",
        "tests/fixtures/firewall_states_response.json",
    ):
        findings = scan_text(Path(path_str), 'LEAK = "192.168.1.3"')  # security-scan: allow
        assert findings != [], f"{path_str} was silently skipped instead of being scanned"


def test_approved_marker_files_allow_list_matches_expected_set():
    assert _APPROVED_MARKER_FILES == {
        "tests/test_security_patterns.py",
        "tests/test_security_scan.py",
        "tests/test_fixture_safety.py",
    }


def test_scan_line_suppression_marker_constant_is_the_expected_string():
    assert _SUPPRESSION_MARKER == "security-scan: allow"


def test_scan_line_without_marker_is_never_silently_suppressed():
    findings = scan_line(Path("fake/file.py"), 1, 'LEAK = "192.168.1.3"')  # security-scan: allow
    assert findings != []


def test_scan_line_with_marker_in_unapproved_file_is_not_suppressed():
    line = 'LEAK = "192.168.1.3"  # security-scan: allow'  # security-scan: allow
    findings = scan_line(Path("fake/file.py"), 1, line)
    assert any("192.168.1.3" in f for f in findings)  # security-scan: allow
    assert any("unauthorized suppression marker" in f for f in findings)


def test_scan_line_with_marker_in_approved_file_is_suppressed():
    findings = scan_line(_APPROVED_PATH, 1, 'LEAK = "192.168.1.3"  # security-scan: allow')
    assert findings == []
