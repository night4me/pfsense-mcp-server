"""ADR-037 Batch 1 / ADR-029 acceptance-path production wiring for the five
Batch 1 capabilities (`NTP_TIME_SERVER_PREFER`, `NTP_SETTINGS_OBSERVABILITY_
TOGGLES`, `LOG_DISPLAY_PREFERENCES`, `LOG_RETENTION_SETTINGS`,
`SYSTEM_TIMEZONE`). Built 2026-09-04 per owner authorization, to be
exercised only once the missing witness/authority infrastructure this
module requires is separately provisioned -- **no LAB or production call is
made by this module or its own tests.**

## Why a second module rather than extending `production_runtime.py`

`production_runtime.py`'s own module docstring already frames it as "the
fixed production runtime for the alias-description first-WRITE path" --
every name, constant, and doc comment in that file is alias-specific, and
consolidating it onto something generic would be exactly the kind of
"materially different, separately-risky change" `write_execution_core.py`'s
own docstring already declined to make for the execution-core layer one
level down. This module is the analogous, one-level-up generalization:
it composes `WriteExecutionCoreV1` (not `AliasDescriptionExecutionCoreV1`)
against real, environment-derived dependencies for the five Batch 1
capabilities. `production_runtime.py` remains completely untouched.

## Deliberately NOT included: ADR-028's W3 Slice 3 product composition

`production_runtime.py`'s `request_alias_description_change()` and its
four fixed artifact-exchange files (authorization inbox, confirmation
pending/signed, authorization preview) exist to expose the alias
capability as an async, five-state MCP-facing product (`ProductOutcome`).
None of that is needed here: these five capabilities are not MCP-exposed,
this module is not imported by `application.py`/`factory.py`/`server.py`,
and `tier1/acceptance.py`'s own stated purpose -- "gather the live
evidence ... before `verified` may be promoted" -- only requires driving
the raw `authorize_and_create()`/`confirm_and_handoff()` gate, exactly
like `production_runtime.py`'s own W1/W2 layer did before W3 Slice 3
existed. `ProductionWriteBatch1Runtime` therefore exposes five named
`WriteExecutionCoreV1` attributes directly -- nothing else -- mirroring
`ProductionAliasDescriptionRuntime.execution_core`'s own exposed-attribute
discipline for a single capability, generalized to five.

## Why a dedicated contract store and consumption store, not the alias
## capability's existing ones

`SqliteRecoveryContractStore`/`SqliteAuthorizationConsumptionStore` both
bind a fixed `store_id` into their own on-disk integrity metadata at
first use (`_initialize_schema()`'s `{"schema_version": ..., "store_id":
...}` check) -- opening an existing file with a different `store_id` than
it was created with fails closed, by design. Reusing
`production_runtime.CONSUMPTION_STORE_ID` ("...alias-description-
consumption") here would be both semantically wrong (these five
capabilities are not the alias capability) and would couple this new,
unreviewed-in-production wiring's own on-disk state to whatever the
already-`verified=True` alias capability's production deployment might
already have written. This module therefore requires its own dedicated
store/consumption-store file paths and encryption key -- a bug here can
never corrupt or interfere with the alias capability's own production
state, in this or any future environment. `CONTRACT_STORE_ID`/
`CONSUMPTION_STORE_ID` below are this module's own fixed, non-configurable
identifiers, exactly mirroring `production_runtime.py`'s own
`CONSUMPTION_STORE_ID` discipline (a store_id is a fixed identity, never
sourced from environment).

## Why the pinned authorities and witness anchor ARE shared

Unlike a contract/consumption store, a `PinnedAuthority` is just Ed25519
*public* key material identifying "the owner" (or confirmation/
reconciliation authority) -- it carries no store-bound identity and
verifies a signature over any signed artifact that authority ever
produces, regardless of which WRITE capability the underlying plan
authorizes. Likewise the TPM-witness anti-rollback anchor is one physical
daemon connection for one appliance, not a per-capability resource. This
module therefore reuses the *exact same* environment variable names
`production_runtime.py` already defines for these six values (three
authority files, four witness-client values) -- duplicated here as
literal string constants rather than imported (these are private,
module-internal names in `production_runtime.py`; importing them across
modules would create an unreviewed coupling neither module's own docstring
anticipates) -- so that one real deployment configuring both runtimes
points both at the same physical owner identity and the same physical
witness daemon, exactly as it should.

## Infrastructure this module cannot itself provision

As of 2026-09-04, this development/review environment has none of the
thirteen required environment variables set, and in particular no TPM
witness daemon is reachable from it. `build_write_batch1_production_
runtime()` therefore returns `None` here -- the safe, default,
unconfigured state -- exactly like `production_runtime.build_production_
runtime()` would if invoked in this same environment for the alias
capability. Provisioning a reachable witness daemon and real pinned
Ed25519 authority key files is infrastructure/ops work outside this
module's scope; no private signing key is loaded or accepted anywhere in
this module, matching `production_runtime.py`'s own "the private signing
key never appears anywhere in this module or this package" discipline
exactly -- an off-host, human-controlled signer remains required to
produce the actual `PlanAuthorizationV2`/`ConfirmationEvidence` artifacts
any real acceptance-path exercise of this wiring would need.

Fail-closed anti-rollback requirement (ADR-011/ADR-021, identical to
`production_runtime.py`): a runtime here is never constructed with
`anti_rollback_anchor=None`. If the dedicated store's own persisted
anchor-provisioning record is not both seeded and complete, or the
witness client cannot be configured, `build_write_batch1_production_
runtime()` raises rather than returning a runtime with no anchor
enforcement.

Restart/reconciliation: identical discipline to `production_runtime.py`
-- every call performs a full, fresh construction (nothing cached across
calls); constructing each capability's `MutationExecutor` triggers the
existing, unchanged `SqliteRecoveryContractStore.reconcile_interrupted()`
call on the shared dedicated store.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import httpx

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.config import PfSenseConfig, load_api_key, load_config
from pfsense_mcp.factory import build_pfsense_client, build_write_client
from pfsense_mcp.tls import TLSMode

from ..secure_file import open_nofollow, validate_descriptor
from .alias_description import ConfiguredApplianceTargetV1
from .anti_rollback_tpm_witness import TpmHostWitnessAnchor
from .authorization_consumption_store import SqliteAuthorizationConsumptionStore
from .canonical import CanonicalValue
from .confirmation_providers import Ed25519ConfirmationVerifier
from .ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from .errors import PreparedExecutionIntentError, Tier1ConfigurationError, Tier1Error
from .executor import MutationExecutor
from .key_lifecycle import KeyPurpose, NonceCounter, load_key_material
from .log_display_preferences import (
    ENDPOINT_SYMBOL as LOG_DISPLAY_ENDPOINT_SYMBOL,
)
from .log_display_preferences import (
    HTTP_METHOD as LOG_DISPLAY_HTTP_METHOD,
)
from .log_display_preferences import (
    LogDisplayPreferencesChangeV1,
    LogDisplayPreferencesPreparerV1,
    LogSettingsStateV1,
    PreparedLogDisplayPreferencesExecutionV1,
)
from .log_retention_settings import (
    ENDPOINT_SYMBOL as LOG_RETENTION_ENDPOINT_SYMBOL,
)
from .log_retention_settings import (
    HTTP_METHOD as LOG_RETENTION_HTTP_METHOD,
)
from .log_retention_settings import (
    LogRetentionSettingsChangeV1,
    LogRetentionSettingsPreparerV1,
    PreparedLogRetentionSettingsExecutionV1,
)
from .ntp_settings_observability import (
    ENDPOINT_SYMBOL as NTP_OBSERVABILITY_ENDPOINT_SYMBOL,
)
from .ntp_settings_observability import (
    HTTP_METHOD as NTP_OBSERVABILITY_HTTP_METHOD,
)
from .ntp_settings_observability import (
    NtpSettingsObservabilityChangeV1,
    NtpSettingsObservabilityPreparerV1,
    NtpSettingsStateV1,
    PreparedNtpSettingsObservabilityExecutionV1,
)
from .ntp_time_server_prefer import (
    ENDPOINT_SYMBOL as NTP_PREFER_ENDPOINT_SYMBOL,
)
from .ntp_time_server_prefer import (
    HTTP_METHOD as NTP_PREFER_HTTP_METHOD,
)
from .ntp_time_server_prefer import (
    NtpTimeServerPreferChangeV1,
    NtpTimeServerPreferPreparerV1,
    NtpTimeServerStateV1,
    PreparedNtpTimeServerPreferExecutionV1,
)
from .policy import MutationPolicy, MutationRule
from .production_store import (
    ProductionStoreConfig,
    open_production_store,
    read_only_anchor_provisioning_status,
)
from .reconciliation_providers import Ed25519ReconciliationVerifier
from .system_timezone_write import (
    ENDPOINT_SYMBOL as SYSTEM_TIMEZONE_ENDPOINT_SYMBOL,
)
from .system_timezone_write import (
    HTTP_METHOD as SYSTEM_TIMEZONE_HTTP_METHOD,
)
from .system_timezone_write import (
    PreparedSystemTimezoneExecutionV1,
    SystemTimezoneChangeV1,
    SystemTimezonePreparerV1,
    SystemTimezoneStateV1,
)
from .write_execution_core import WriteExecutionCoreV1

# Shared with production_runtime.py -- same physical owner identity and
# witness daemon; see module docstring "Why the pinned authorities and
# witness anchor ARE shared". Literal duplicates of that module's private
# constants, not imports (see docstring for why).
_AUTHORIZATION_AUTHORITY_FILE_VAR = "PFSENSE_TIER1_AUTHORIZATION_AUTHORITY_FILE"
_CONFIRMATION_AUTHORITY_FILE_VAR = "PFSENSE_TIER1_CONFIRMATION_AUTHORITY_FILE"
_RECONCILIATION_AUTHORITY_FILE_VAR = "PFSENSE_TIER1_RECONCILIATION_AUTHORITY_FILE"
_WITNESS_BASE_URL_VAR = "PFSENSE_TIER1_WITNESS_BASE_URL"
_WITNESS_CLIENT_CERT_VAR = "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE"
_WITNESS_CLIENT_KEY_VAR = "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE"
_WITNESS_SERVER_CA_VAR = "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE"

# Dedicated to this module -- see docstring "Why a dedicated contract
# store and consumption store". Never shared with production_runtime.py's
# own PFSENSE_TIER1_STORE_PATH/STORE_KEY_FILE/etc.
_STORE_PATH_VAR = "PFSENSE_TIER1_WRITE_BATCH1_STORE_PATH"
_STORE_KEY_FILE_VAR = "PFSENSE_TIER1_WRITE_BATCH1_STORE_KEY_FILE"
_CONSUMPTION_STORE_PATH_VAR = "PFSENSE_TIER1_WRITE_BATCH1_CONSUMPTION_STORE_PATH"
_CONSUMPTION_STORE_KEY_FILE_VAR = "PFSENSE_TIER1_WRITE_BATCH1_CONSUMPTION_STORE_KEY_FILE"
_ENCRYPTION_KEY_FILE_VAR = "PFSENSE_TIER1_WRITE_BATCH1_ENCRYPTION_KEY_FILE"
_NONCE_COUNTER_FILE_VAR = "PFSENSE_TIER1_WRITE_BATCH1_NONCE_COUNTER_FILE"

#: Fixed, non-configurable identifiers -- mirrors
#: `production_runtime.CONSUMPTION_STORE_ID`'s own discipline exactly.
CONTRACT_STORE_ID = "tier1-production-write-batch1-store"
CONSUMPTION_STORE_ID = "tier1-production-write-batch1-consumption"

_AUTHORITY_FILE_MAX_BYTES = 4096
_PUBLIC_KEY_HEX = re.compile(r"[0-9a-f]{64}")

_REQUIRED_VARS = (
    _STORE_PATH_VAR,
    _STORE_KEY_FILE_VAR,
    _CONSUMPTION_STORE_PATH_VAR,
    _CONSUMPTION_STORE_KEY_FILE_VAR,
    _ENCRYPTION_KEY_FILE_VAR,
    _NONCE_COUNTER_FILE_VAR,
    _AUTHORIZATION_AUTHORITY_FILE_VAR,
    _CONFIRMATION_AUTHORITY_FILE_VAR,
    _RECONCILIATION_AUTHORITY_FILE_VAR,
    _WITNESS_BASE_URL_VAR,
    _WITNESS_CLIENT_CERT_VAR,
    _WITNESS_CLIENT_KEY_VAR,
    _WITNESS_SERVER_CA_VAR,
)


def _missing_required_vars(source: dict[str, str] | os._Environ[str]) -> list[str]:
    return [name for name in _REQUIRED_VARS if not source.get(name)]


def _load_pinned_authority(path: Path) -> PinnedAuthority:
    """Verbatim duplicate of `production_runtime._load_pinned_authority()`
    -- see that function's own docstring for the full file-shape/validation
    contract. Duplicated, not imported, for the same reason the other
    shared-authority constants above are duplicated."""

    descriptor = open_nofollow(path, on_error=Tier1ConfigurationError)
    try:
        validate_descriptor(path, descriptor, max_bytes=_AUTHORITY_FILE_MAX_BYTES, on_error=Tier1ConfigurationError)
        try:
            raw = os.read(descriptor, _AUTHORITY_FILE_MAX_BYTES + 1)
        except OSError:
            raise Tier1ConfigurationError(f"Pinned authority file could not be read: {path}") from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise Tier1ConfigurationError(f"Pinned authority descriptor could not be closed: {path}") from None

    if len(raw) > _AUTHORITY_FILE_MAX_BYTES:
        raise Tier1ConfigurationError(f"Pinned authority file is too large: {path}")
    try:
        value = json.loads(raw.decode("utf-8").strip())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Tier1ConfigurationError(f"Pinned authority file is not valid JSON: {path}") from exc
    if not isinstance(value, dict) or set(value) != {"authority_id", "public_key_hex"}:
        raise Tier1ConfigurationError(f"Pinned authority file has an unexpected shape: {path}")
    authority_id, public_key_hex = value["authority_id"], value["public_key_hex"]
    if (
        not isinstance(authority_id, str)
        or not isinstance(public_key_hex, str)
        or not _PUBLIC_KEY_HEX.fullmatch(public_key_hex)
    ):
        raise Tier1ConfigurationError(f"Pinned authority file has invalid encoding: {path}")
    try:
        return PinnedAuthority(authority_id=authority_id, public_key=bytes.fromhex(public_key_hex))
    except Tier1Error as exc:
        raise Tier1ConfigurationError(f"Pinned authority file failed domain validation: {path}") from exc


def _require_absolute_path(raw: str, var_name: str) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise Tier1ConfigurationError(f"{var_name} must be an absolute path (got {raw!r}).")
    return path


@dataclass(frozen=True)
class _WitnessClientConfig:
    base_url: str
    client_cert_file: Path
    client_key_file: Path
    server_ca_file: Path


def _load_witness_client_config(source: dict[str, str] | os._Environ[str]) -> _WitnessClientConfig:
    base_url = source[_WITNESS_BASE_URL_VAR]
    client_cert = source[_WITNESS_CLIENT_CERT_VAR]
    client_key = source[_WITNESS_CLIENT_KEY_VAR]
    server_ca = source[_WITNESS_SERVER_CA_VAR]

    if not base_url.startswith("https://"):
        raise Tier1ConfigurationError(f"{_WITNESS_BASE_URL_VAR} must use https (got {base_url!r}).")

    return _WitnessClientConfig(
        base_url=base_url,
        client_cert_file=_require_absolute_path(client_cert, _WITNESS_CLIENT_CERT_VAR),
        client_key_file=_require_absolute_path(client_key, _WITNESS_CLIENT_KEY_VAR),
        server_ca_file=_require_absolute_path(server_ca, _WITNESS_SERVER_CA_VAR),
    )


def _build_witness_anchor(config: _WitnessClientConfig) -> TpmHostWitnessAnchor:
    """Verbatim duplicate of `production_runtime._build_witness_anchor()`
    -- the confirmed-working mTLS recipe, an explicit `ssl.SSLContext`,
    never the `cert=`/`verify=<path>` shorthand."""

    try:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations(cafile=str(config.server_ca_file))
        ssl_context.load_cert_chain(certfile=str(config.client_cert_file), keyfile=str(config.client_key_file))
    except (OSError, ssl.SSLError) as exc:
        raise Tier1ConfigurationError("Witness client TLS configuration failed.") from exc
    client = httpx.Client(verify=ssl_context, trust_env=False, timeout=10.0)
    return TpmHostWitnessAnchor(client=client, base_url=config.base_url)


def _configured_appliance_target(pf_config: PfSenseConfig) -> ConfiguredApplianceTargetV1:
    ca_digest: str | None = None
    if pf_config.tls_mode is TLSMode.AUTO:
        if pf_config.tls_ca_file is None:
            raise Tier1ConfigurationError("Configured appliance TLS target is missing its CA file.")
        descriptor = open_nofollow(pf_config.tls_ca_file, on_error=Tier1ConfigurationError)
        try:
            validate_descriptor(pf_config.tls_ca_file, descriptor, max_bytes=1 << 20, on_error=Tier1ConfigurationError)
            ca_bytes = os.read(descriptor, (1 << 20) + 1)
        finally:
            os.close(descriptor)
        ca_digest = hashlib.sha256(ca_bytes).hexdigest()
    try:
        return ConfiguredApplianceTargetV1(
            base_url=pf_config.base_url, tls_mode=pf_config.tls_mode, ca_certificate_digest=ca_digest
        )
    except PreparedExecutionIntentError as exc:
        raise Tier1ConfigurationError("Configured appliance TLS target is not eligible for production WRITE.") from exc


def _ntp_prefer_raw_target(state: object) -> dict[str, CanonicalValue]:
    if not isinstance(state, NtpTimeServerStateV1):
        raise PreparedExecutionIntentError("NTP time server state is malformed.")
    return state.raw_target_hint()


def _ntp_observability_raw_target(state: object) -> dict[str, CanonicalValue]:
    if not isinstance(state, NtpSettingsStateV1):
        raise PreparedExecutionIntentError("NTP settings state is malformed.")
    return state.raw_target_hint()


def _log_settings_raw_target(state: object) -> dict[str, CanonicalValue]:
    if not isinstance(state, LogSettingsStateV1):
        raise PreparedExecutionIntentError("Log settings state is malformed.")
    return state.raw_target_hint()


def _system_timezone_raw_target(state: object) -> dict[str, CanonicalValue]:
    if not isinstance(state, SystemTimezoneStateV1):
        raise PreparedExecutionIntentError("System timezone state is malformed.")
    return state.raw_target_hint()


#: Every concrete preparer type `_core()` (below) is ever constructed
#: with -- structurally satisfies `WriteExecutionCoreV1`'s own
#: `preparer: _PreparerProtocol` parameter, checked once here rather than
#: importing that private, module-internal Protocol name across modules.
_AnyBatch1Preparer = (
    NtpTimeServerPreferPreparerV1
    | NtpSettingsObservabilityPreparerV1
    | LogDisplayPreferencesPreparerV1
    | LogRetentionSettingsPreparerV1
    | SystemTimezonePreparerV1
)


@dataclass(frozen=True, slots=True)
class ProductionWriteBatch1Runtime:
    """The complete, fixed, environment-derived runtime for all five
    ADR-037 Batch 1 capabilities. Exposes exactly five named
    `WriteExecutionCoreV1` attributes -- each capability's own
    `authorize_and_create`/`confirm_and_handoff`/`resume_prepared` gate --
    and nothing else. Every other composed component (store, executors,
    write client, authorities, anchor) is a private implementation detail
    of construction, never a public attribute a caller could substitute
    or bypass through -- mirrors `ProductionAliasDescriptionRuntime`'s
    own discipline exactly."""

    ntp_time_server_prefer: WriteExecutionCoreV1
    ntp_settings_observability: WriteExecutionCoreV1
    log_display_preferences: WriteExecutionCoreV1
    log_retention_settings: WriteExecutionCoreV1
    system_timezone: WriteExecutionCoreV1


def build_write_batch1_production_runtime(
    env: dict[str, str] | None = None,
) -> ProductionWriteBatch1Runtime | None:
    """The sole public entry point. Returns `None` if none of this
    module's required environment variables are set (the safe, default,
    disabled state). Raises `Tier1ConfigurationError`/`Tier1Error` for any
    partial configuration or any failure to construct a fully valid, fully
    anchored runtime -- never returns a partially-constructed or
    anchor-less runtime. Every call performs a full, fresh construction;
    nothing is cached across calls."""

    source = env if env is not None else os.environ
    missing = _missing_required_vars(source)
    if len(missing) == len(_REQUIRED_VARS):
        return None
    if missing:
        raise Tier1ConfigurationError(
            f"Write Batch 1 production runtime configuration is partial; missing: {', '.join(sorted(missing))}"
        )

    store_config = ProductionStoreConfig(
        store_path=_require_absolute_path(source[_STORE_PATH_VAR], _STORE_PATH_VAR),
        key_file=_require_absolute_path(source[_STORE_KEY_FILE_VAR], _STORE_KEY_FILE_VAR),
        store_id=CONTRACT_STORE_ID,
    )

    pf_config = load_config(env)
    api_key = load_api_key(pf_config)
    appliance_target = _configured_appliance_target(pf_config)

    encryption_key_record = load_key_material(Path(source[_ENCRYPTION_KEY_FILE_VAR]), purpose=KeyPurpose.ENCRYPTION)
    nonce_counter = NonceCounter(Path(source[_NONCE_COUNTER_FILE_VAR]), key_id=encryption_key_record.key_id)

    authorization_authorities = PinnedAuthoritySet(
        (_load_pinned_authority(Path(source[_AUTHORIZATION_AUTHORITY_FILE_VAR])),)
    )
    confirmation_authority = _load_pinned_authority(Path(source[_CONFIRMATION_AUTHORITY_FILE_VAR]))
    confirmation_verifier = Ed25519ConfirmationVerifier((confirmation_authority,))
    reconciliation_verifier = Ed25519ReconciliationVerifier(
        (_load_pinned_authority(Path(source[_RECONCILIATION_AUTHORITY_FILE_VAR])),)
    )

    provisioning_status = read_only_anchor_provisioning_status(store_config)
    if not provisioning_status.seeded or not provisioning_status.complete:
        raise Tier1ConfigurationError(
            "Anti-rollback anchor is not fully provisioned for the Write Batch 1 store; runtime refused."
        )
    witness_config = _load_witness_client_config(source)
    anchor = _build_witness_anchor(witness_config)

    store = open_production_store(
        store_config,
        confirmation_verifier=confirmation_verifier,
        reconciliation_verifier=reconciliation_verifier,
        anti_rollback_anchor=anchor,
    )
    consumption_integrity_key = load_key_material(
        Path(source[_CONSUMPTION_STORE_KEY_FILE_VAR]), purpose=KeyPurpose.INTEGRITY
    ).material
    consumption_store = SqliteAuthorizationConsumptionStore(
        Path(source[_CONSUMPTION_STORE_PATH_VAR]),
        integrity_key=consumption_integrity_key,
        store_id=CONSUMPTION_STORE_ID,
    )

    transport, read_client = build_pfsense_client(pf_config, api_key)
    write_client = build_write_client(pf_config, transport)

    def _core(
        *,
        capability: Capability,
        endpoint_symbol: str,
        http_method: str,
        preparer: _AnyBatch1Preparer,
        request_type: type,
        prepared_type: type,
        contract_id_prefix: str,
        raw_target_fn: Callable[[object], dict[str, CanonicalValue]],
    ) -> WriteExecutionCoreV1:
        policy = MutationPolicy(frozenset({MutationRule(capability, endpoint_symbol, http_method)}))
        executor = MutationExecutor(
            store=store,
            write_client=write_client,
            read_client=read_client,
            policy=policy,
            anti_rollback_anchor=anchor,
            encryption_key=encryption_key_record.material,
        )
        return WriteExecutionCoreV1(
            request_type=request_type,
            prepared_type=prepared_type,
            contract_id_prefix=contract_id_prefix,
            raw_target_fn=raw_target_fn,
            # WriteExecutionCoreV1's own `_PreparerProtocol` requires
            # `prepare(self, request: Any) -> PreparedWriteExecutionV1`;
            # every concrete preparer here correctly narrows `request` to
            # its own capability-specific type (e.g.
            # `SystemTimezonePreparerV1.prepare(self, request:
            # SystemTimezoneChangeV1)`), which mypy's Protocol method
            # matching flags under strict parameter contravariance even
            # though the narrower parameter is exactly the intended,
            # correct design -- `_validate_inputs()` inside
            # `WriteExecutionCoreV1` is what actually enforces
            # `isinstance(request, self._request_type)` at runtime, not
            # this Protocol. `cast(Any, ...)` here is a static-typing-only
            # escape at the one call boundary where this structural
            # limitation is unavoidable; every preparer/request/prepared
            # triple is still paired correctly by construction, immediately
            # above, per capability.
            preparer=cast(Any, preparer),
            authorities=authorization_authorities,
            consumption_store=consumption_store,
            contract_store=store,
            executor=executor,
            encryption_key=encryption_key_record,
            nonce_counter=nonce_counter,
        )

    return ProductionWriteBatch1Runtime(
        ntp_time_server_prefer=_core(
            capability=Capability.NTP_TIME_SERVER_PREFER_WRITE,
            endpoint_symbol=NTP_PREFER_ENDPOINT_SYMBOL,
            http_method=NTP_PREFER_HTTP_METHOD,
            preparer=NtpTimeServerPreferPreparerV1(read_client=read_client, configured_target=appliance_target),
            request_type=NtpTimeServerPreferChangeV1,
            prepared_type=PreparedNtpTimeServerPreferExecutionV1,
            contract_id_prefix="ntppref",
            raw_target_fn=_ntp_prefer_raw_target,
        ),
        ntp_settings_observability=_core(
            capability=Capability.NTP_SETTINGS_OBSERVABILITY_WRITE,
            endpoint_symbol=NTP_OBSERVABILITY_ENDPOINT_SYMBOL,
            http_method=NTP_OBSERVABILITY_HTTP_METHOD,
            preparer=NtpSettingsObservabilityPreparerV1(read_client=read_client, configured_target=appliance_target),
            request_type=NtpSettingsObservabilityChangeV1,
            prepared_type=PreparedNtpSettingsObservabilityExecutionV1,
            contract_id_prefix="ntpobs",
            raw_target_fn=_ntp_observability_raw_target,
        ),
        log_display_preferences=_core(
            capability=Capability.LOG_DISPLAY_PREFERENCES_WRITE,
            endpoint_symbol=LOG_DISPLAY_ENDPOINT_SYMBOL,
            http_method=LOG_DISPLAY_HTTP_METHOD,
            preparer=LogDisplayPreferencesPreparerV1(read_client=read_client, configured_target=appliance_target),
            request_type=LogDisplayPreferencesChangeV1,
            prepared_type=PreparedLogDisplayPreferencesExecutionV1,
            raw_target_fn=_log_settings_raw_target,
            contract_id_prefix="logdisp",
        ),
        log_retention_settings=_core(
            capability=Capability.LOG_RETENTION_SETTINGS_WRITE,
            endpoint_symbol=LOG_RETENTION_ENDPOINT_SYMBOL,
            http_method=LOG_RETENTION_HTTP_METHOD,
            preparer=LogRetentionSettingsPreparerV1(read_client=read_client, configured_target=appliance_target),
            request_type=LogRetentionSettingsChangeV1,
            prepared_type=PreparedLogRetentionSettingsExecutionV1,
            contract_id_prefix="logret",
            raw_target_fn=_log_settings_raw_target,
        ),
        system_timezone=_core(
            capability=Capability.SYSTEM_TIMEZONE_WRITE,
            endpoint_symbol=SYSTEM_TIMEZONE_ENDPOINT_SYMBOL,
            http_method=SYSTEM_TIMEZONE_HTTP_METHOD,
            preparer=SystemTimezonePreparerV1(read_client=read_client, configured_target=appliance_target),
            request_type=SystemTimezoneChangeV1,
            prepared_type=PreparedSystemTimezoneExecutionV1,
            contract_id_prefix="systz",
            raw_target_fn=_system_timezone_raw_target,
        ),
    )


__all__ = [
    "CONSUMPTION_STORE_ID",
    "CONTRACT_STORE_ID",
    "ProductionStoreConfig",
    "ProductionWriteBatch1Runtime",
    "build_write_batch1_production_runtime",
]
