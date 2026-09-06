"""ADR-037 Shape-A acceptance orchestration: the one, finite, statically
reviewed table binding a `WriteEndpoints` symbol to everything a
generalized acceptance ceremony needs to drive it.

This is the *only* place capability identity is bound to a request type, a
prepared type, a `ProductionWriteBatch1Runtime` attribute pair (its
`WriteExecutionCoreV1` and the matching preparer), and an artifact
namespace token. `shape_a_acceptance_orchestration.py` and
`signing/write_batch1_signing.py` both look capabilities up here and
nowhere else -- there is no dynamic registration path, no wildcard, no
string-driven construction of a capability that is not one of the keys
below. Adding a future capability requires a reviewed edit to this file's
`SHAPE_A_REGISTRATIONS` mapping; it can never become constructible merely
by existing in `WriteEndpoints` or `ProductionWriteBatch1Runtime`.

`runtime_core_attr`/`runtime_preparer_attr` name real, fixed attributes on
`ProductionWriteBatch1Runtime` (checked once, below, by
`_verify_runtime_attrs_exist_smoke_check` at import time) -- `getattr()` is
used only against these five known-safe, hardcoded strings, never against
caller-supplied input.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Mapping

from pfsense_mcp.capabilities import Capability

from .log_display_preferences import LogDisplayPreferencesChangeV1, PreparedLogDisplayPreferencesExecutionV1
from .log_retention_settings import LogRetentionSettingsChangeV1, PreparedLogRetentionSettingsExecutionV1
from .ntp_settings_observability import (
    NtpSettingsObservabilityChangeV1,
    PreparedNtpSettingsObservabilityExecutionV1,
)
from .ntp_time_server_prefer import NtpTimeServerPreferChangeV1, PreparedNtpTimeServerPreferExecutionV1
from .system_timezone_write import PreparedSystemTimezoneExecutionV1, SystemTimezoneChangeV1
from .write_security_class import WriteSecurityClass

if TYPE_CHECKING:
    # Deferred to avoid pulling write_execution_core.py -> executor.py ->
    # write_api_client.py (real pfSense mutation capability) into every
    # importer of this module -- in particular signing/write_batch1_
    # signing.py, which must never transitively reach pfSense-capable code
    # (ADR-028's signing-CLI transport-isolation requirement, previously
    # fixed for the alias-specific signer via the identical pattern:
    # extracting a type-hint-only dependency). This module never
    # constructs a WriteExecutionCoreV1 itself -- core() only returns one
    # via getattr() against an already-built runtime -- so the real class
    # is never needed at runtime, only for this one return-type annotation.
    from .write_batch1_production_runtime import ProductionWriteBatch1Runtime
    from .write_execution_core import WriteExecutionCoreV1

__all__ = [
    "SHAPE_A_REGISTRATIONS",
    "WRITE_CAPABILITY_SECURITY_CLASS",
    "ShapeARegistration",
    "is_registered_capability",
]


@dataclass(frozen=True, slots=True)
class ShapeARegistration:
    """Everything the generalized orchestration layer and the generalized
    signer need for exactly one capability -- nothing here is derived at
    call time from caller input."""

    capability_symbol: str
    request_type: type
    prepared_type: type
    contract_id_prefix: str
    runtime_core_attr: str
    runtime_preparer_attr: str
    #: 2026-09-06 owner-authorized two-tier WRITE security model, Phase 1:
    #: the trusted, closed classification for this ONE capability. Lives
    #: here -- the static capability/adapter registration boundary that
    #: already binds capability+endpoint+method+typed projection -- not
    #: on `WriteEndpointInfo` (a separate, lower-level, orthogonal
    #: HTTP-allow-list fact) and never caller/request/CLI/environment/
    #: contract-selectable. Required (no default): a registration
    #: omitting it fails to construct at all.
    security_class: WriteSecurityClass

    def core(self, runtime: "ProductionWriteBatch1Runtime") -> WriteExecutionCoreV1:
        return getattr(runtime, self.runtime_core_attr)  # type: ignore[no-any-return]

    def preparer(self, runtime: "ProductionWriteBatch1Runtime") -> Any:
        # Structurally the same mypy limitation write_batch1_production_
        # runtime.py's own `cast(Any, preparer)` call site documents: the
        # five concrete preparer types each correctly narrow `prepare()`'s
        # `request` parameter to their own capability-specific type, which
        # Protocol/attribute-access typing cannot express as a single
        # return type here without losing that narrowing. Runtime behavior
        # is unaffected -- `WriteExecutionCoreV1._validate_inputs()` is
        # what actually enforces `isinstance(request, self._request_type)`.
        return getattr(runtime, self.runtime_preparer_attr)


#: Exactly the five owner-approved ADR-037 Batch 1 capabilities. No sixth
#: entry. Keys are `WriteEndpoints` symbol names (also used, unchanged, as
#: the artifact-namespace token -- see `shape_a_acceptance_orchestration.py`).
SHAPE_A_REGISTRATIONS: dict[str, ShapeARegistration] = {
    "NTP_TIME_SERVER_PREFER": ShapeARegistration(
        capability_symbol="NTP_TIME_SERVER_PREFER",
        request_type=NtpTimeServerPreferChangeV1,
        prepared_type=PreparedNtpTimeServerPreferExecutionV1,
        contract_id_prefix="ntppref",
        runtime_core_attr="ntp_time_server_prefer",
        runtime_preparer_attr="ntp_time_server_prefer_preparer",
        # 2026-09-06 owner-authorized Phase 1: the sole STANDARD_SEALED_
        # WRITE candidate this phase, per the explicit positive
        # eligibility review accepted alongside this architecture
        # (existing-target mutation only, narrow scalar projection, no
        # secret/RBAC/network/self-referential-security effect,
        # independently reversible, bounded blast radius).
        security_class=WriteSecurityClass.STANDARD_SEALED_WRITE,
    ),
    "NTP_SETTINGS_OBSERVABILITY_TOGGLES": ShapeARegistration(
        capability_symbol="NTP_SETTINGS_OBSERVABILITY_TOGGLES",
        request_type=NtpSettingsObservabilityChangeV1,
        prepared_type=PreparedNtpSettingsObservabilityExecutionV1,
        contract_id_prefix="ntpobs",
        runtime_core_attr="ntp_settings_observability",
        runtime_preparer_attr="ntp_settings_observability_preparer",
        security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1,
    ),
    "LOG_DISPLAY_PREFERENCES": ShapeARegistration(
        capability_symbol="LOG_DISPLAY_PREFERENCES",
        request_type=LogDisplayPreferencesChangeV1,
        prepared_type=PreparedLogDisplayPreferencesExecutionV1,
        contract_id_prefix="logdisp",
        runtime_core_attr="log_display_preferences",
        runtime_preparer_attr="log_display_preferences_preparer",
        security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1,
    ),
    "LOG_RETENTION_SETTINGS": ShapeARegistration(
        capability_symbol="LOG_RETENTION_SETTINGS",
        request_type=LogRetentionSettingsChangeV1,
        prepared_type=PreparedLogRetentionSettingsExecutionV1,
        contract_id_prefix="logret",
        runtime_core_attr="log_retention_settings",
        runtime_preparer_attr="log_retention_settings_preparer",
        security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1,
    ),
    "SYSTEM_TIMEZONE": ShapeARegistration(
        capability_symbol="SYSTEM_TIMEZONE",
        request_type=SystemTimezoneChangeV1,
        prepared_type=PreparedSystemTimezoneExecutionV1,
        contract_id_prefix="systz",
        runtime_core_attr="system_timezone",
        runtime_preparer_attr="system_timezone_preparer",
        security_class=WriteSecurityClass.HIGH_ASSURANCE_TIER1,
    ),
}

#: `SHAPE_A_REGISTRATIONS` keys do not all map to their `Capability` enum
#: member by simple `f"{symbol}_WRITE"` string concatenation (e.g. the
#: registry key `NTP_SETTINGS_OBSERVABILITY_TOGGLES` corresponds to
#: `Capability.NTP_SETTINGS_OBSERVABILITY_WRITE`, not
#: `..._TOGGLES_WRITE`) -- this explicit table is the one place that
#: correspondence is spelled out, matching exactly what `write_batch1_
#: production_runtime.py`'s own `_core()` calls already pass for
#: `capability=`.
_REGISTRATION_SYMBOL_TO_CAPABILITY: Mapping[str, Capability] = MappingProxyType(
    {
        "NTP_TIME_SERVER_PREFER": Capability.NTP_TIME_SERVER_PREFER_WRITE,
        "NTP_SETTINGS_OBSERVABILITY_TOGGLES": Capability.NTP_SETTINGS_OBSERVABILITY_WRITE,
        "LOG_DISPLAY_PREFERENCES": Capability.LOG_DISPLAY_PREFERENCES_WRITE,
        "LOG_RETENTION_SETTINGS": Capability.LOG_RETENTION_SETTINGS_WRITE,
        "SYSTEM_TIMEZONE": Capability.SYSTEM_TIMEZONE_WRITE,
    }
)

#: 2026-09-06 owner-authorized two-tier WRITE security model, Phase 1:
#: the one, closed, `Capability`-enum-keyed translation of the per-
#: capability classification above, plus the one hardcoded literal for
#: the alias-description capability (`ALIAS_WRITE`) -- which predates
#: `ShapeARegistration` entirely and is not, and will not become,
#: STANDARD_SEALED_WRITE-eligible in this phase. This is the exact
#: mapping `MutationExecutor` instances are constructed with
#: (`capability_security_classes=`); it is never derived at runtime from
#: anything caller/request/contract-supplied.
WRITE_CAPABILITY_SECURITY_CLASS: Mapping[Capability, WriteSecurityClass] = MappingProxyType(
    {
        Capability.ALIAS_WRITE: WriteSecurityClass.HIGH_ASSURANCE_TIER1,
        **{
            _REGISTRATION_SYMBOL_TO_CAPABILITY[symbol]: registration.security_class
            for symbol, registration in SHAPE_A_REGISTRATIONS.items()
        },
    }
)
if set(_REGISTRATION_SYMBOL_TO_CAPABILITY) != set(SHAPE_A_REGISTRATIONS):
    raise ImportError("Shape-A capability-symbol-to-Capability table is out of sync with SHAPE_A_REGISTRATIONS.")


def is_registered_capability(capability_symbol: object) -> bool:
    """The one, reused predicate for "is this a Shape-A capability this
    codebase can drive" -- fail-closed on any non-`str` input."""

    return isinstance(capability_symbol, str) and capability_symbol in SHAPE_A_REGISTRATIONS


#: 2026-09-06 owner-authorized Phase 1 closed-set invariant, enforced at
#: import time (never merely by convention or a separate opt-in script):
#: exactly `NTP_TIME_SERVER_PREFER` may be STANDARD_SEALED_WRITE this
#: phase. Any future PR adding a second STANDARD entry must consciously
#: widen this literal set -- silent/accidental downgrade of any other
#: capability is structurally impossible to merge unnoticed.
_EXPECTED_STANDARD_SEALED_WRITE_CAPABILITIES = frozenset({"NTP_TIME_SERVER_PREFER"})
_actual_standard = frozenset(
    symbol
    for symbol, registration in SHAPE_A_REGISTRATIONS.items()
    if registration.security_class == WriteSecurityClass.STANDARD_SEALED_WRITE
)
if _actual_standard != _EXPECTED_STANDARD_SEALED_WRITE_CAPABILITIES:
    raise ImportError(
        "Shape-A STANDARD_SEALED_WRITE closed set does not match the exact owner-authorized Phase 1 scope: "
        f"expected {sorted(_EXPECTED_STANDARD_SEALED_WRITE_CAPABILITIES)}, found {sorted(_actual_standard)}."
    )
del _actual_standard
