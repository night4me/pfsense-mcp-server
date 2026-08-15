"""Named capability profiles — Auditor vs Engineer vs the explicit
write_protected posture.

Application selects a profile via configuration rather than
hardcoding a capability set itself. This is the long-term
authorization model referenced in capabilities.py.

ADR-028 (W3-D2, owner-accepted 2026-08-15) fixes the profile/capability
relationship: `AuditorProfile` (the default profile) grants exactly
`READ_CAPABILITIES` -- never `SUPPORTED_CAPABILITIES_THIS_BUILD` directly,
since that constant means "implemented by this build", not "granted by
default". `WriteProtectedProfile` is the one explicit posture permitted to
grant `ALIAS_WRITE`, and grants nothing beyond `READ_CAPABILITIES |
{ALIAS_WRITE}`. Granting `ALIAS_WRITE` here does not by itself make any
WRITE capability reachable: `ADR-028`'s three-condition WRITE-tool
registration gate (profile grant + `WriteEndpoints` entry + a successfully
constructed production runtime) is owned by the tool-registration layer, not
here -- as of this slice, no registration code exists for `ALIAS_WRITE` at
all, so selecting this profile changes nothing observable yet.
"""

from __future__ import annotations

from dataclasses import dataclass

from .capabilities import READ_CAPABILITIES, Capability
from .errors import ConfigurationError


@dataclass(frozen=True)
class Profile:
    name: str
    capabilities: frozenset[Capability]


AuditorProfile = Profile(
    name="auditor",
    capabilities=READ_CAPABILITIES,
)

EngineerProfile = Profile(
    name="engineer",
    capabilities=frozenset(),
    # No write capability is implemented in this build. This profile
    # exists as a named placeholder for when tools/write/ is built
    # under a separate, explicitly authorized phase.
)

WriteProtectedProfile = Profile(
    name="write_protected",
    capabilities=READ_CAPABILITIES | {Capability.ALIAS_WRITE},
    # The one explicit posture permitted to grant ALIAS_WRITE (ADR-021's
    # write_protected vocabulary, reused per ADR-028 W3-D2). Selectable via
    # PFSENSE_PROFILE like any other named profile; inert until a future,
    # separately authorized slice adds a registration path gated on
    # ALIAS_WRITE and satisfies the full three-condition gate.
)

_PROFILES_BY_NAME: dict[str, Profile] = {
    AuditorProfile.name: AuditorProfile,
    EngineerProfile.name: EngineerProfile,
    WriteProtectedProfile.name: WriteProtectedProfile,
}


def get_profile(name: str) -> Profile:
    try:
        return _PROFILES_BY_NAME[name]
    except KeyError:
        valid = ", ".join(_PROFILES_BY_NAME)
        raise ConfigurationError(f"Unknown profile {name!r}; must be one of: {valid}") from None
