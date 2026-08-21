"""Model for the SystemConsole capability endpoint.

Field type was derived from the pinned v2.10 OpenAPI schema's
`SystemConsole` component (already-captured evidence, not a new live
call). No secret material present -- `passwd_protect_console` is
whether a password is required at the console, not the password
itself -- and stays visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class SystemConsole(BaseModel):
    passwd_protect_console: bool

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "SystemConsole":
        return cls(passwd_protect_console=data["passwd_protect_console"])
