"""Named capability profiles — Auditor vs Engineer.

Application selects a profile via configuration rather than
hardcoding a capability set itself. This is the long-term
authorization model referenced in capabilities.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from .capabilities import Capability
from .errors import ConfigurationError


@dataclass(frozen=True)
class Profile:
    name: str
    capabilities: frozenset[Capability]


AuditorProfile = Profile(
    name="auditor",
    capabilities=frozenset(
        {
            Capability.SYSTEM_READ,
            Capability.INTERFACE_READ,
            Capability.GATEWAY_READ,
            Capability.FIREWALL_READ,
            Capability.ALIAS_READ,
            Capability.SERVICE_READ,
            Capability.SYSTEM_INFO_READ,
            Capability.INTERFACE_CONFIG_READ,
        }
    ),
)

EngineerProfile = Profile(
    name="engineer",
    capabilities=frozenset(),
    # No write capability is implemented in this build. This profile
    # exists as a named placeholder for when tools/write/ is built
    # under a separate, explicitly authorized phase.
)

_PROFILES_BY_NAME: dict[str, Profile] = {
    AuditorProfile.name: AuditorProfile,
    EngineerProfile.name: EngineerProfile,
}


def get_profile(name: str) -> Profile:
    try:
        return _PROFILES_BY_NAME[name]
    except KeyError:
        valid = ", ".join(_PROFILES_BY_NAME)
        raise ConfigurationError(f"Unknown profile {name!r}; must be one of: {valid}") from None
