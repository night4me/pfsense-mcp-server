"""Nexus device base-path construction (Phase E, ADR-032).

Pure, stateless, zero network I/O, zero credentials, zero session
state -- proves the confirmed
`{CONTROLLER_URL}/api/device/{device_type}/{device_id}/api{operation_path}`
routing scheme (docs/NEXUS_COMPATIBILITY_MATRIX.md's Phase B section)
with real, executable, tested code, without building any part of "the
transport" itself (no HTTP client, no JWT/session handling -- see
ADR-032, which this module implements exactly the one piece of).

Deliberately does not accept or construct the Controller URL prefix or
the operation-specific suffix path -- those are the caller's concern;
this function's only job is the one path segment whose contents
(`device_type`, `device_id`) are unconstrained strings in the official
Nexus OpenAPI schema and therefore the one place a malformed or
adversarial value could redirect a request somewhere unintended if not
validated before concatenation.
"""

from __future__ import annotations

import re

# Conservative allow-list: matches every `device_type`/`device_id`
# value observed in Netgate's own official examples ("pfsense",
# alphanumeric-looking device IDs) while rejecting anything that could
# alter the resulting URL path (`/`, `..`, whitespace, `?`, `#`, etc.).
# No format/length constraint exists in the official schema for either
# field (confirmed directly, ADR-032 Section 2) -- this allow-list is
# this project's own conservative choice, not a documented Nexus rule.
_SAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def build_device_base_path(device_type: str, device_id: str) -> str:
    """Returns `/api/device/{device_type}/{device_id}/api` -- the
    device-scoped base path segment confirmed in Phase B, to be
    appended to a separately-supplied Controller URL prefix.

    Raises `ValueError` (fail closed) if either value is empty,
    contains a path-altering character (`/`, `..`, whitespace, `?`,
    `#`, `%`, etc.), or exceeds a conservative length bound -- never
    silently percent-encodes around a suspicious value."""

    for label, value in (("device_type", device_type), ("device_id", device_id)):
        if not isinstance(value, str) or not _SAFE_PATH_SEGMENT.fullmatch(value):
            raise ValueError(f"{label} is not a safe URL path segment: {value!r}")

    return f"/api/device/{device_type}/{device_id}/api"
