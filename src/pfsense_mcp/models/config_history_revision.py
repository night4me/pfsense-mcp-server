"""Model for the pfSense config-history revision list
(`/api/v2/diagnostics/config_history/revisions`).

Field shape confirmed against a real pfSense v2 API response (2026-08-16,
disposable LAB appliance, ADR-026 row 18 evidence-gathering). No secret or
credential material is present in this response shape; `description` is a
free-text audit line pfSense itself generates (e.g. "admin@<lab-ip>:
Modified Firewall Alias via API") and is treated as ordinary object
metadata, consistent with this codebase's existing non-disclosure policy
(which excludes only genuine secrets: passwords, private keys, tokens)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ConfigHistoryRevision(BaseModel):
    id: int
    time: int
    description: str
    version: str
    filesize: int

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "ConfigHistoryRevision":
        return cls(
            id=data["id"],
            time=data["time"],
            description=data["description"],
            version=data["version"],
            filesize=data["filesize"],
        )
