"""Shared, capability-agnostic primitives reused by the ADR-037 Batch 1
capability adapters/preparers (`ntp_settings_observability.py`,
`log_display_preferences.py`, `log_retention_settings.py`,
`system_timezone_write.py`, `ntp_time_server_prefer.py`).

Inert, like every module it is used by: no tool, endpoint, policy,
capability, or runtime is registered here. This module owns exactly two
kinds of duplication-reduction, both explicitly authorized by the owner's
ADR-037 Batch 1 approval ("Design reusable INTERNAL infrastructure...
singleton target resolution... protected-field comparison"), and nothing
resembling generic dispatch: every function here is a pure helper a
capability's own statically-bound adapter/preparer calls, never something
that chooses an endpoint, method, or privilege at runtime.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Protocol

from .canonical import CanonicalValue, DigestPurpose, digest_value
from .errors import PreparedExecutionIntentError

#: The fixed transport locator every SINGLETON-shaped capability in this
#: batch uses (`NtpSettingsObservabilityAdapterV1`, `LogDisplayPreferences
#: AdapterV1`, `LogRetentionSettingsAdapterV1`, `SystemTimezoneAdapterV1`).
#: A singleton pfSense settings object (`NTPSettings`, `LogSettings`,
#: `SystemTimezone`) has no natural numeric identifier of its own -- there
#: is exactly one instance, always. `MutationExecutor._resolve_transport_
#: target()` requires `adapter.transport_locator(raw_target) -> int` purely
#: to prove "the same incarnation of the target that was read before is
#: still there after" (target-incarnation continuity, sealed_executor.md);
#: for a true singleton that continuity is trivially, permanently true --
#: there can never be a second incarnation to confuse it with. Using a
#: fixed constant (rather than inventing a fake numeric id) makes that
#: triviality explicit rather than fabricating meaning the API does not
#: provide. Every singleton adapter in this batch returns this same value
#: from `transport_locator()`; `NTP_TIME_SERVER_PREFER`'s adapter does NOT
#: use this constant -- it targets one entry of a real collection
#: (`services/ntp/time_servers`) and uses that entry's own genuine `id`.
SINGLETON_LOCATOR = 0


class ApplianceIdentityReadClient(Protocol):
    """The narrow read surface `read_appliance_target_digest()` needs.
    Every capability's own richer `*ReadClient` Protocol (adding whichever
    `get_*` method it needs for its own target) already satisfies this
    structurally -- Python Protocols are structural, so no additional
    inheritance is required at any call site."""

    def get_system_status(self, *, include_identifying_metadata: bool = False) -> object: ...
    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> object: ...


class _TlsModeLike(Protocol):
    @property
    def value(self) -> str: ...


class ConfiguredApplianceTargetLike(Protocol):
    """Structural shape `read_appliance_target_digest()` needs from its
    `configured_target` argument -- exactly `ConfiguredApplianceTargetV1`'s
    shape (`alias_description.py`), matched structurally rather than by
    inheritance so this module has no import dependency on that file.
    Declared via read-only `@property` members (not plain attributes) so a
    frozen dataclass -- whose fields are read-only -- satisfies this
    Protocol structurally; a plain mutable-attribute Protocol member does
    not match a read-only dataclass field under mypy's structural typing."""

    @property
    def base_url(self) -> str: ...
    @property
    def tls_mode(self) -> _TlsModeLike: ...
    @property
    def ca_certificate_digest(self) -> str | None: ...


def read_appliance_target_digest(
    read_client: ApplianceIdentityReadClient, configured_target: ConfiguredApplianceTargetLike
) -> str:
    """Identical algorithm to (and factored out of) `AliasDescriptionPreparerV1.
    _read_appliance_target_digest()` -- copied here as shared infrastructure
    rather than imported from `alias_description.py`, so this module has no
    dependency on that capability's own file and that capability's own file
    is never touched by this batch (ADR-036 Gap 2: consolidating an
    *existing* live capability's code path is explicitly out of scope for
    an unrelated hardening/expansion pass). Every NEW capability in this
    batch calls this shared function instead of duplicating the algorithm
    a fifth time.

    `configured_target` must expose `.base_url`, `.tls_mode` (an object
    with a `.value` attribute), and `.ca_certificate_digest` -- exactly
    `ConfiguredApplianceTargetV1`'s shape (imported directly by every
    caller from `alias_description.py`, since that dataclass itself is
    already generic appliance-target-binding infrastructure, not
    alias-specific, and constructing a second copy of it would be the
    real duplication).
    """

    status = read_client.get_system_status(include_identifying_metadata=True)
    netgate_id = getattr(status, "netgate_id", None)
    identity_kind = "netgate_id"
    identity = netgate_id
    if not identity:
        identity_kind = "pfhostid"
        hasync = read_client.get_system_hasync(include_identifying_metadata=True)
        identity = getattr(hasync, "pfhostid", None)
    if not isinstance(identity, str) or not identity:
        raise PreparedExecutionIntentError("Stable appliance identity is unavailable.")
    tls_mode = configured_target.tls_mode
    return digest_value(
        DigestPurpose.TARGET_IDENTITY,
        {
            "configured_base_url": configured_target.base_url,
            "tls_mode": tls_mode.value,
            "ca_certificate_digest": configured_target.ca_certificate_digest,
            "installation_identity_kind": identity_kind,
            "installation_identity": identity,
        },
        context=("configured-pfsense-appliance-v1",),
    )


def fields_equal(
    before: Mapping[str, CanonicalValue], after: Mapping[str, CanonicalValue], *, fields: Iterable[str]
) -> bool:
    """`True` iff every named field has the identical value in both
    mappings. Shared "protected-field comparison" primitive: every new
    adapter's `is_semantically_verified()` uses this to prove every
    NON-projected field of its target is byte-identical before/after --
    the same "every projected AND every forbidden field" discipline
    `AliasDescriptionAdapterV1.is_semantically_verified()` established,
    factored out so five adapters do not each hand-roll the same
    all()-comprehension five times."""

    keys = list(fields)
    return all(key in before and key in after and before[key] == after[key] for key in keys)


def fields_match(actual: Mapping[str, CanonicalValue], expected: Mapping[str, CanonicalValue]) -> bool:
    """`True` iff every key in `expected` has the identical value in
    `actual`. Shared "requested value was actually applied" primitive --
    the projected-fields half of postcondition verification, complementing
    `fields_equal()`'s forbidden-fields half."""

    return all(key in actual and actual[key] == value for key, value in expected.items())
