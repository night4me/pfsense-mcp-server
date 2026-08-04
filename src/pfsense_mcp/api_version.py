"""API version abstraction.

Endpoint definitions declare a minimum required API version. The
active version is configured once, at startup. Only RestApiClient and
this module need to change when the pfSense REST API's URL-level
version changes — endpoints.py, models/, and tools/ are unaffected as
long as response shapes stay compatible (a separate, model-level
concern).
"""

from __future__ import annotations

from enum import Enum


class ApiVersion(str, Enum):
    V2 = "v2"


_VERSION_ORDER: dict[ApiVersion, int] = {
    ApiVersion.V2: 2,
}


def version_at_least(current: ApiVersion, minimum: ApiVersion) -> bool:
    return _VERSION_ORDER[current] >= _VERSION_ORDER[minimum]
