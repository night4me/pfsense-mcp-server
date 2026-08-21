"""pfsense_get_system_webgui_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.web_gui_settings import WebGUISettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., WebGUISettings]:
    def pfsense_get_system_webgui_settings() -> WebGUISettings:
        """Return the current web GUI listener settings: protocol,
        port, and assigned TLS certificate reference. Read-only."""
        return client.get_system_webgui_settings()

    return pfsense_get_system_webgui_settings
