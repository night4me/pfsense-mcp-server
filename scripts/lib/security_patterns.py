"""Low-level, generic pattern helpers shared by security_scan.py and
fixture_safety.py. Deliberately principle-based rather than allow-list
based where possible (e.g. the locally-administered MAC bit check),
so a new synthetic fixture value doesn't require updating a hardcoded
list here.
"""

from __future__ import annotations

import re

_IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")

# The three IPv4 documentation/test-net ranges (RFC 5737) this project
# uses for all synthetic fixture data.
_RFC5737_RANGES = (
    (192, 0, 2),
    (198, 51, 100),
    (203, 0, 113),
)


def find_ipv4_literals(text: str) -> list[str]:
    matches = []
    for m in _IPV4_RE.finditer(text):
        octets = tuple(int(g) for g in m.groups())
        if all(0 <= o <= 255 for o in octets):
            matches.append(m.group(0))
    return matches


def _is_netmask(octets: tuple[int, ...]) -> bool:
    """A netmask is a contiguous run of 1 bits followed by 0 bits when
    the 32-bit value is written in binary (e.g. 255.255.255.0).
    Recognizing this generically avoids hardcoding specific netmask
    literals as an allow-list."""
    value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    binary = f"{value:032b}"
    return re.fullmatch(r"1*0*", binary) is not None


def is_safe_ipv4(ip: str) -> bool:
    """True if `ip` is safe to appear anywhere in this repository:
    an RFC 5737 documentation address, a loopback address, or a
    syntactically valid netmask (not a host address at all)."""
    octets = tuple(int(part) for part in ip.split("."))
    if octets[0] == 127:
        return True
    if _is_netmask(octets):
        return True
    return any(octets[:3] == range_ for range_ in _RFC5737_RANGES)


def find_mac_literals(text: str) -> list[str]:
    return _MAC_RE.findall(text)


def is_locally_administered_mac(mac: str) -> bool:
    """The IEEE-defined locally-administered bit is the second-least
    -significant bit of the first octet. A MAC with this bit set can
    never collide with a real vendor-assigned address, so this is a
    generic safety check rather than a hardcoded placeholder allow-list."""
    first_octet = int(mac.split(":")[0], 16)
    return bool(first_octet & 0b00000010)
