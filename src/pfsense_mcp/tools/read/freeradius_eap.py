"""pfsense_get_freeradius_eap tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.free_radius_eap import FreeRadiusEap
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., FreeRadiusEap]:
    def pfsense_get_freeradius_eap() -> FreeRadiusEap:
        """Get pfSense FreeRADIUS EAP (Extensible Authentication
        Protocol) settings: default EAP type, TLS options, and OCSP
        configuration. Read-only."""
        return client.get_freeradius_eap()

    return pfsense_get_freeradius_eap
