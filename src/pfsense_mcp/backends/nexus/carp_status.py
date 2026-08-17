"""Nexus `CarpStatus` normalization (Phase D).

Field-by-field diff (docs/NEXUS_COMPATIBILITY_MATRIX.md's Phase D
section) found this is the first Nexus capability whose mapping is
complete, deterministic, and semantically equivalent to the existing
community-backed model -- unlike gateway status and firewall aliases,
whose required fields (`id`, `substatus`, `srcip`, `monitorip`, etc.)
have no Nexus source at all.

Nexus's own official generated client (`py/pfapi/models/carp_status.py`
in `Netgate/pfsense-api`) types `enabled`/`maintenancemode_enabled` as
`bool | Unset` -- genuinely optional, may be entirely absent from a
real response, not merely nullable. This module treats that exactly
like the community model already treats a missing required key: fail
closed, never default to `False`. `False` and "not present" are not
the same fact, and this project does not coerce the difference away.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from ...errors import PfSenseResponseShapeError
from ...models.carp_status import CarpStatus
from ..ports import CarpStatusReader


def normalize_carp_status(raw: dict[str, Any]) -> CarpStatus:
    """Turn one already-parsed Nexus `GET /services/carp/status`
    response body into `CarpStatus`. Ignores `my_hostid`,
    `state_sync_hostids`, and `vips` -- richer fields the current
    model has no use for, not required, safe to ignore.

    Raises `PfSenseResponseShapeError`, matching the community
    backend's own `_parse_object_response()` failure mode exactly,
    if `enabled`/`maintenancemode_enabled` are missing or not
    booleans. Never defaults either field."""

    try:
        return CarpStatus(
            enable=raw["enabled"],
            maintenance_mode=raw["maintenancemode_enabled"],
        )
    except (KeyError, TypeError, ValidationError):
        raise PfSenseResponseShapeError(
            "Nexus /services/carp/status response did not contain both 'enabled' and "
            "'maintenancemode_enabled' as booleans."
        ) from None


class NexusCarpStatusReader(CarpStatusReader):
    """Explicitly implements `CarpStatusReader` (PEP 544 structural
    typing would accept this without the inheritance too; declaring it
    documents the intent). Takes an injected `fetch_raw` callable
    returning the already-authenticated, already-parsed JSON body of
    one `GET .../services/carp/status` call -- this class owns none of
    the HTTP transport, JWT session, or device base-path construction;
    see the package docstring for why that's out of scope for this
    phase."""

    def __init__(self, fetch_raw: Callable[[], dict[str, Any]]) -> None:
        self._fetch_raw = fetch_raw

    def get_carp_status(self) -> CarpStatus:
        return normalize_carp_status(self._fetch_raw())
