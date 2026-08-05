"""Recursive fixture sanitizer.

Turns a raw pfSense API response dict into a fully synthetic one,
suitable for a review proposal. Never prints or logs the values it
processes — callers are responsible for keeping raw data out of any
log/stdout path entirely; this module only transforms in memory.

IPv4/IPv6 classification is authoritative via the stdlib `ipaddress`
module — regexes here only locate *candidate* substrings inside
strings (including compound forms like "ip:port", "[ipv6]:port", and
CIDR notation); every candidate is validated with
`ipaddress.ip_address()` / `ipaddress.ip_network()` before any
substitution occurs. A regex match that fails that validation (e.g. a
MAC address, which is never a valid IP) is left completely unchanged.

Refusal (via SanitizationRefusal) always takes precedence over
substitution for anything credential/token/key-shaped — this module
never attempts to sanitize such values into a "safe-looking"
placeholder and continue; it stops the whole capture and reports only
the field path, category, and reason, never the triggering value.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any

from lib.capture_policies import CapturePolicy
from lib.security_patterns import (
    find_ipv4_literals,
    find_mac_literals,
    is_locally_administered_mac,
    is_safe_ipv4,
)

APPROVED_NETGATE_ID_PLACEHOLDER = "ANONYMIZED0000000000"
_SERIAL_PLACEHOLDER = "SYNTHETIC-SERIAL-0000"
_HOSTNAME_PLACEHOLDER = "host.example.invalid"
_USERNAME_PLACEHOLDER_LOCAL = "admin"
_USERNAME_FALLBACK = "admin@198.51.100.20"

# Field names treated as identifying regardless of which endpoint's
# policy is active — a small, deliberately narrow global baseline on
# top of each policy's own identifying_fields.
_GLOBAL_IDENTIFYING_FIELD_NAMES = frozenset({"netgate_id", "serial", "created_by", "updated_by", "username"})

_HOSTNAME_FIELD_NAMES = frozenset({"hostname", "fqdn", "host_name", "domain"})

_CREDENTIAL_FIELD_NAMES = frozenset(
    {
        "apikey",
        "api_key",
        "password",
        "passwd",
        "token",
        "secret",
        "psk",
        "private_key",
        "privatekey",
        "pre_shared_key",
        "preshared_key",
    }
)
# A field name containing any of these substrings is refused regardless
# of the value's entropy — these are precise enough that they are very
# rarely part of an unrelated, benign field name (e.g. "session_token",
# "csrf_token", "reset_token" should always be treated with suspicion).
_HARD_SUSPICIOUS_NAME_SUBSTRINGS = ("token", "secret", "password", "passwd", "psk", "privatekey", "apikey")

# A field name containing any of these substrings is refused only if
# the value is ALSO high-entropy — these are common enough in ordinary,
# non-sensitive field names (e.g. "authenticated", "credential_type")
# that refusing on name alone would create false positives.
_SOFT_SUSPICIOUS_NAME_SUBSTRINGS = ("key", "auth", "cred")


def _is_suspicious_by_name_and_value(field_name: str, value: str) -> bool:
    lname = field_name.lower()
    if any(s in lname for s in _HARD_SUSPICIOUS_NAME_SUBSTRINGS):
        return True
    if any(s in lname for s in _SOFT_SUSPICIOUS_NAME_SUBSTRINGS) and is_high_entropy(value):
        return True
    return False


# Deliberately specific to private-key material only. A bare
# "-----BEGIN " marker would also match plain public certificates,
# CSRs, and CRLs (e.g. "-----BEGIN CERTIFICATE-----"), which are not
# secret and must remain capturable — only PEM blocks that are
# themselves private-key-shaped are hard-refused here.
_PEM_MARKERS = ("PRIVATE KEY", "BEGIN RSA", "BEGIN OPENSSH", "BEGIN EC PRIVATE KEY")
_CREDENTIAL_PATH_RE = re.compile(r"\.(key|pem|p12|pfx)\b", re.IGNORECASE)
_HIGH_ENTROPY_SHAPE_RE = re.compile(r"^[A-Za-z0-9+/=_-]{20,}$")
_ENTROPY_THRESHOLD_BITS_PER_CHAR = 3.5

_IPV4_CANDIDATE_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?")
# One alternation, matched in a single left-to-right pass: either a
# bracketed form "[addr]" (group 1 captures the inside) or a bare
# colon-separated candidate. Using one regex — rather than two
# sequential passes — guarantees each span in the text is considered
# exactly once.
_IPV6_UNIFIED_RE = re.compile(r"\[([0-9a-fA-F:]+)\]|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?")
_MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")

_HOSTNAME_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

_RFC5737_RANGE_PREFIXES = ("198.51.100.", "203.0.113.", "192.0.2.")


class SanitizationRefusal(Exception):
    def __init__(self, field_path: str, category: str, reason: str) -> None:
        self.field_path = field_path
        self.category = category
        self.reason = reason
        super().__init__(f"{field_path}: [{category}] {reason}")


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_credential_shaped_field(field_name: str) -> bool:
    return field_name.lower() in _CREDENTIAL_FIELD_NAMES


def contains_pem_marker(value: str) -> bool:
    return any(marker in value for marker in _PEM_MARKERS)


def looks_like_credential_path(value: str) -> bool:
    return bool(_CREDENTIAL_PATH_RE.search(value)) and ("/" in value or "\\" in value)


def is_high_entropy(value: str) -> bool:
    if len(value) < 20 or not _HIGH_ENTROPY_SHAPE_RE.match(value):
        return False
    return _shannon_entropy(value) >= _ENTROPY_THRESHOLD_BITS_PER_CHAR


def is_strict_hostname(value: str) -> bool:
    """Deliberately strict: requires >=2 dot-separated labels, each a
    valid DNS label, and rejects anything that is actually a bare
    dotted-decimal IPv4 address. An ordinary descriptive string with a
    dot or hyphen (e.g. "keep-state", "1000baseT") will not match this
    unless every single label independently satisfies DNS label rules
    AND there are at least two of them."""
    if not value or " " in value or len(value) > 253:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    if all(label.isdigit() for label in labels):
        return False
    return all(_HOSTNAME_LABEL_RE.match(label) for label in labels)


def _validate_ip_or_network(
    candidate: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    if "/" in candidate:
        try:
            return ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            pass
    return None


class IPv4Allocator:
    def __init__(self) -> None:
        self._map: dict[str, str] = {}
        self._range_idx = 0
        self._host = 10

    def allocate(self, real_value: str) -> str:
        if real_value in self._map:
            return self._map[real_value]
        prefix = _RFC5737_RANGE_PREFIXES[self._range_idx % len(_RFC5737_RANGE_PREFIXES)]
        placeholder = f"{prefix}{self._host}"
        self._host += 1
        if self._host > 250:
            self._host = 10
            self._range_idx += 1
        self._map[real_value] = placeholder
        return placeholder


class IPv6Allocator:
    def __init__(self) -> None:
        self._map: dict[str, str] = {}
        self._counter = 1

    def allocate(self, real_value: str) -> str:
        if real_value in self._map:
            return self._map[real_value]
        placeholder = f"2001:db8::{self._counter:x}"
        self._counter += 1
        self._map[real_value] = placeholder
        return placeholder


_MAC_PLACEHOLDER_PREFIX = "02:00:00:"


class MacAllocator:
    def __init__(self) -> None:
        self._map: dict[str, str] = {}
        self._counter = 1

    def allocate(self, real_value: str) -> str:
        if real_value in self._map:
            return self._map[real_value]
        placeholder = f"{_MAC_PLACEHOLDER_PREFIX}00:{(self._counter >> 8) & 0xFF:02x}:{self._counter & 0xFF:02x}"
        self._counter += 1
        self._map[real_value] = placeholder
        return placeholder


def sanitize_ipv4(text: str, allocator: IPv4Allocator) -> tuple[str, int]:
    count = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal count
        candidate = m.group(0)
        result = _validate_ip_or_network(candidate)
        if result is None or result.version != 4:
            return candidate
        count += 1
        if "/" in candidate:
            addr_str, _, prefix_len = candidate.partition("/")
            return f"{allocator.allocate(addr_str)}/{prefix_len}"
        return allocator.allocate(candidate)

    return _IPV4_CANDIDATE_RE.sub(_repl, text), count


def sanitize_ipv6(text: str, allocator: IPv6Allocator) -> tuple[str, int]:
    """Single unified pass (bracketed-or-bare, one alternation regex)
    so a span is never matched — and never re-substituted — twice.
    Running the bracketed and bare regexes as two separate passes
    would re-match an already-substituted placeholder still sitting
    inside its own brackets during the second pass, corrupting it."""
    count = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal count
        bracketed = m.group(1)
        if bracketed is not None:
            candidate = bracketed
            wrap = "[{}]"
        else:
            candidate = m.group(0)
            if candidate.count(":") < 2:
                return candidate
            wrap = "{}"

        result = _validate_ip_or_network(candidate)
        if result is None or result.version != 6:
            return m.group(0)

        count += 1
        if "/" in candidate:
            addr_str, _, prefix_len = candidate.partition("/")
            return wrap.format(f"{allocator.allocate(addr_str)}/{prefix_len}")
        return wrap.format(allocator.allocate(candidate))

    return _IPV6_UNIFIED_RE.sub(_repl, text), count


def sanitize_mac(text: str, allocator: MacAllocator) -> tuple[str, int]:
    """Substitutes every MAC address except ones already matching this
    project's own placeholder prefix (02:00:00:). Deliberately does
    NOT treat "any locally-administered MAC" as already-safe-skip —
    a real captured device's MAC can coincidentally have the IEEE
    locally-administered bit set (common for many VM NICs), which
    would otherwise cause a real value to be wrongly left untouched.
    The broader locally-administered-bit check is still the right
    tool for fixture_safety.py's/security_scan.py's *acceptance* test
    on the output side; here, on the *input* side, only our own exact
    prefix is trusted as "already a placeholder"."""
    count = 0

    def _repl(m: re.Match[str]) -> str:
        nonlocal count
        mac = m.group(0)
        if mac.lower().startswith(_MAC_PLACEHOLDER_PREFIX):
            return mac
        count += 1
        return allocator.allocate(mac)

    return _MAC_RE.sub(_repl, text), count


@dataclass
class SanitizationResult:
    sanitized: Any
    substitution_counts: dict[str, int]
    redacted_field_names: set[str] = field(default_factory=set)


class Sanitizer:
    def __init__(self, policy: CapturePolicy) -> None:
        self.policy = policy
        self._ipv4 = IPv4Allocator()
        self._ipv6 = IPv6Allocator()
        self._mac = MacAllocator()
        self.counts: dict[str, int] = {
            "ipv4": 0,
            "ipv6": 0,
            "mac": 0,
            "netgate_id": 0,
            "serial": 0,
            "hostname": 0,
            "username": 0,
            "generic_redacted": 0,
        }
        self.redacted_fields: set[str] = set()

    def run(self, data: Any) -> SanitizationResult:
        sanitized = self._sanitize(data, field_name="", field_path="$")
        self._post_sanitization_self_check(sanitized)
        return SanitizationResult(
            sanitized=sanitized,
            substitution_counts=dict(self.counts),
            redacted_field_names=set(self.redacted_fields),
        )

    def _sanitize(self, value: Any, field_name: str, field_path: str) -> Any:
        if isinstance(value, dict):
            return {k: self._sanitize(v, k, f"{field_path}.{k}") for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize(v, field_name, f"{field_path}[{i}]") for i, v in enumerate(value)]
        if isinstance(value, str):
            return self._sanitize_string(value, field_name, field_path)
        return value

    def _sanitize_string(self, value: str, field_name: str, field_path: str) -> str:
        if not value:
            return value
        lname = field_name.lower()
        benign = field_name in self.policy.benign_fields

        if field_name in self.policy.hard_refusal_fields and not benign:
            raise SanitizationRefusal(
                field_path,
                "policy-hard-refusal-field",
                f"field {field_name!r} is configured hard-refusal for this endpoint",
            )
        if is_credential_shaped_field(lname) and not benign:
            raise SanitizationRefusal(
                field_path,
                "credential-shaped-field-name",
                f"field name {field_name!r} matches a credential/token/secret pattern",
            )
        if contains_pem_marker(value):
            raise SanitizationRefusal(field_path, "pem-key-material", "value contains PEM/private-key marker text")
        if looks_like_credential_path(value):
            raise SanitizationRefusal(
                field_path, "credential-path-shaped-value", "value looks like a credential file path"
            )
        if not benign and any(s in lname for s in _HARD_SUSPICIOUS_NAME_SUBSTRINGS):
            raise SanitizationRefusal(
                field_path,
                "sensitive-field-name",
                f"field name {field_name!r} matches a token/secret-shaped naming pattern",
            )
        if not benign and any(s in lname for s in _SOFT_SUSPICIOUS_NAME_SUBSTRINGS) and is_high_entropy(value):
            raise SanitizationRefusal(
                field_path,
                "high-entropy-sensitive-field",
                f"field name {field_name!r} looks sensitive and its value is high-entropy",
            )

        if field_name in self.policy.identifying_fields or lname in _GLOBAL_IDENTIFYING_FIELD_NAMES:
            return self._substitute_identifying(value, field_name, lname)

        return self._substitute_generic(value, field_name)

    def _substitute_identifying(self, value: str, field_name: str, lname: str) -> str:
        if lname == "netgate_id":
            self.counts["netgate_id"] += 1
            self.redacted_fields.add(field_name)
            return APPROVED_NETGATE_ID_PLACEHOLDER
        if lname == "serial":
            self.counts["serial"] += 1
            self.redacted_fields.add(field_name)
            return _SERIAL_PLACEHOLDER
        if lname in ("created_by", "updated_by", "username"):
            self.counts["username"] += 1
            self.redacted_fields.add(field_name)
            if "@" in value:
                _local, _, host = value.partition("@")
                new_host, n = sanitize_ipv4(host, self._ipv4)
                if n:
                    self.counts["ipv4"] += n
                    return f"{_USERNAME_PLACEHOLDER_LOCAL}@{new_host}"
            return _USERNAME_FALLBACK

        substituted, changed = self._substitute_generic(value, field_name, return_changed=True)
        self.redacted_fields.add(field_name)
        if changed:
            return substituted
        self.counts["generic_redacted"] += 1
        return f"REDACTED-{field_name}"

    def _substitute_generic(self, value: str, field_name: str, *, return_changed: bool = False) -> Any:
        text = value
        text, n4 = sanitize_ipv4(text, self._ipv4)
        self.counts["ipv4"] += n4
        text, n6 = sanitize_ipv6(text, self._ipv6)
        self.counts["ipv6"] += n6
        text, nm = sanitize_mac(text, self._mac)
        self.counts["mac"] += nm
        changed = (n4 + n6 + nm) > 0

        if not changed and (field_name.lower() in _HOSTNAME_FIELD_NAMES or is_strict_hostname(value)):
            self.counts["hostname"] += 1
            self.redacted_fields.add(field_name)
            text = _HOSTNAME_PLACEHOLDER
            changed = True

        if return_changed:
            return text, changed
        return text

    def _post_sanitization_self_check(self, sanitized: Any) -> None:
        """Dry-run of the same checks the audit step will perform:
        catches anything that slipped through before a human ever sees
        the proposal. Delegates to the standalone audit_sanitized_data
        so capture-time and audit-time share one implementation."""
        problems = audit_sanitized_data(sanitized, self.policy, redacted_field_names=self.redacted_fields)
        if problems:
            raise SanitizationRefusal("$", "self-check-failed", problems[0])


def audit_sanitized_data(
    data: Any, policy: CapturePolicy, *, redacted_field_names: frozenset[str] | set[str] = frozenset()
) -> list[str]:
    """Independent re-verification of already-sanitized data: no real
    values are involved here, only checking that what remains is safe.
    Used both as the capture-time self-check (via Sanitizer, passing
    the fields it just redacted) and, completely independently, by
    audit_fixture.py re-loading a proposal fresh from disk (passing
    the field-name list recorded in that proposal's manifest) — the
    same logic runs in both places, never duplicated."""
    problems: list[str] = []

    text = json.dumps(data)
    for ip in find_ipv4_literals(text):
        if not is_safe_ipv4(ip):
            problems.append("a non-RFC5737 IPv4 literal remains after sanitization")
    for mac in find_mac_literals(text):
        if not is_locally_administered_mac(mac):
            problems.append("a MAC without the locally-administered bit remains after sanitization")

    problems.extend(_find_unknown_sensitive_fields(data, policy, redacted_field_names, field_path="$"))
    return problems


def _find_unknown_sensitive_fields(
    value: Any, policy: CapturePolicy, redacted_field_names: frozenset[str] | set[str], field_path: str
) -> list[str]:
    problems: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            problems.extend(_find_unknown_sensitive_fields(v, policy, redacted_field_names, f"{field_path}.{k}"))
        return problems
    if isinstance(value, list):
        for i, item in enumerate(value):
            problems.extend(_find_unknown_sensitive_fields(item, policy, redacted_field_names, f"{field_path}[{i}]"))
        return problems
    if isinstance(value, str):
        field_name = field_path.rsplit(".", 1)[-1].split("[")[0]
        if (
            field_name not in redacted_field_names
            and field_name not in policy.benign_fields
            and _is_suspicious_by_name_and_value(field_name, value)
        ):
            problems.append(
                f"{field_path}: field name {field_name!r} looks sensitive and was not redacted "
                "or explicitly allow-listed"
            )
    return problems
