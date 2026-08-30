"""Fixed, offline composition for the dedicated `read_only` managed
service-account stack -- the READ-only counterpart of
`security_admin_composition.py`.

**Why a separate module rather than a parametrized one** (POST-v1.0
MANAGED READ-ONLY DEFENSE IN DEPTH mission, 2026-08-29): `security_
admin_composition.py`'s `_ACCOUNT_NAME`/`_PROFILE` module constants
flow into `_namespace()` (which fixes the journal/lock file identity),
`AdminTargetBinding`, and `bootstrap_call()`'s `target_profile=`
argument. Threading a second discriminant through those already-
reviewed, live-LAB-verified call sites risks the exact write_protected
regression this mission explicitly warns against ("do not assume that
an architecture designed for another posture can simply be wired into
read_only without re-auditing it"). A full duplicate with its own
fixed `_ACCOUNT_NAME = "pfsense-mcp-readonly"` keeps every byte of
`security_admin_composition.py` unchanged and makes it structurally
impossible for the two ceremonies' journals, locks, or custody
artifacts to ever collide -- mirroring this codebase's own established
precedent for isolated security subsystems (`pfsense_mcp.tier1.
authorization_consumption_store`'s own docstring: "Duplicated rather
than shared").

**What genuinely is reused, not duplicated**: every pure, profile-
agnostic primitive `security_admin_composition.py` already exports for
this purpose -- secure-file reading/validation, schema loading,
package-version parsing, the `AdminCompositionConfig`/`AdminTargetBinding`/
`AdministrativeServiceAvailability`/`AdministrativeStatusService`/
`AdministrativeContext`/`_FixedMutationComponents` types (all already
generic over `account_identity`/`approved_profile`, imposed by the
*caller* here, not baked into the type), and `AdminCompositionError`
itself (so `security_bootstrap_orchestration.py`'s existing exception
handling needs no new except-clause to also cover this module). This
module reimplements only what must differ: the fixed account identity,
which derived privilege profile is targeted, which environment
variable names the newly-provisioned key is written to, and which
recovery module (`security_readonly_bootstrap_recovery.py`) its
mutation closures call.

**Env vars**: reuses every `PFSENSE_ADMIN_*`/`PFSENSE_API_*` variable
`security_admin_composition.py` already requires unchanged -- the
operator's own administrator credential and pfSense target are the
same concept regardless of which service-account profile is being
provisioned in a given `bootstrap --target-profile read_only`
invocation. The one deliberate difference is the custody path for the
*newly provisioned* key: `PFSENSE_READONLY_SERVICE_API_KEY_FILE`
(never `PFSENSE_SERVICE_API_KEY_FILE`) -- reusing the write_protected
name here would let a read_only bootstrap run silently overwrite a
write_protected account's own key custody file, or vice versa, if an
operator forgot to change an exported value between two ceremonies.

Only the read-only `AdministrativeStatusService` is exposed. Mutating
call bindings remain private until a separately reviewed journal-aware
orchestration and CLI slice exists -- identical discipline to
`security_admin_composition.py` itself.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from .api_version import ApiVersion
from .config import load_config
from .errors import ConfigurationError
from .security_admin_composition import (
    _MAX_IDENTITY_LENGTH,
    AdminCompositionConfig,
    AdminCompositionError,
    AdministrativeContext,
    AdministrativeStatusService,
    AdminTargetBinding,
    _FixedMutationComponents,
    _load_admin_api_key,
    _load_schema,
    _parse_package_version,
    _read_secret_text,
    _read_secure_file,
    _required,
    _validate_custody_path,
    _validate_owner_controlled_material,
    _validate_owner_directory,
)
from .security_auth_transition import AuthMethodTransitionCoordinator, ReconnectPolicy
from .security_bootstrap_client import BootstrapProvisioningClient, ObservedApiKey, ObservedUser
from .security_bootstrap_engine import (
    AccountProvisioningObservation,
    ProvisioningResult,
    TargetProfile,
    observe_account_provisioning_state,
    provision_service_account,
)
from .security_operation_journal import (
    AdministrativeOperationType,
    ExclusiveOperationLock,
    LockState,
    OperationJournal,
)
from .security_privileges import (
    EvidenceClass,
    distinct_ok_privileges,
    read_profile_requirements,
    resolve_profile_privileges,
)
from .security_readonly_bootstrap_recovery import (
    READONLY_RECOVERY_KEY_DESCRIPTION,
    READONLY_RECOVERY_USER_DESCRIPTION,
    ReadonlyRecoveryDeletionEvidence,
    delete_dedicated_readonly_recovery_user,
    identify_dedicated_readonly_recovery_user_candidate,
    identify_orphan_readonly_api_key_candidate,
    revoke_failed_readonly_bootstrap_api_key,
)
from .tls import TLSMode, resolve_verify
from .transport.base import Transport
from .transport.http import BasicAuthHttpTransport, HttpTransport

_ACCOUNT_NAME = "pfsense-mcp-readonly"
_PROFILE = "read_only"
_MAX_SECRET_BYTES = 16 * 1024
_MAX_SCHEMA_BYTES = 8 * 1024 * 1024
_REQUIRED_ADMIN_VARS = frozenset(
    {
        "PFSENSE_API_URL",
        "PFSENSE_IDENTITY",
        "PFSENSE_API_KEY_FILE",
        "PFSENSE_API_VERSION",
        "PFSENSE_TLS_MODE",
        "PFSENSE_ADMIN_USERNAME",
        "PFSENSE_ADMIN_PASSWORD_FILE",
        "PFSENSE_READONLY_SERVICE_API_KEY_FILE",
        "PFSENSE_ADMIN_STATE_DIR",
        "PFSENSE_ADMIN_JOURNAL_KEY_FILE",
        "PFSENSE_ADMIN_SCHEMA_FILE",
        "PFSENSE_ADMIN_SCHEMA_VERSION",
        "PFSENSE_RESTAPI_PACKAGE_VERSION",
    }
)


def load_readonly_admin_composition_config(source: Mapping[str, str]) -> AdminCompositionConfig:
    """Load explicit references only; never searches for credentials or
    state. Structurally identical to `load_admin_composition_config()`
    except the newly-provisioned key's custody path is read from
    `PFSENSE_READONLY_SERVICE_API_KEY_FILE`."""

    for name in _REQUIRED_ADMIN_VARS:
        _required(source, name)
    forbidden_overrides = {
        "PFSENSE_SERVICE_ACCOUNT_USERNAME",
        "PFSENSE_SERVICE_ACCOUNT_DESCRIPTION",
        "PFSENSE_SERVICE_ACCOUNT_PROFILE",
    }
    if forbidden_overrides.intersection(source):
        raise AdminCompositionError("Fixed service-account identity/profile must not be overridden")
    try:
        target = load_config(dict(source))
    except ConfigurationError as exc:
        raise AdminCompositionError(f"Administrative target configuration is invalid: {exc}") from None
    if target.api_version is not ApiVersion.V2:
        raise AdminCompositionError("ADR-033 administration requires API version v2")
    if target.tls_mode is TLSMode.INSECURE:
        raise AdminCompositionError("ADR-033 administration forbids insecure TLS")

    username = _required(source, "PFSENSE_ADMIN_USERNAME")
    if (
        username != username.strip()
        or len(username) > _MAX_IDENTITY_LENGTH
        or ":" in username
        or any(ord(character) < 32 or ord(character) == 127 for character in username)
    ):
        raise AdminCompositionError("PFSENSE_ADMIN_USERNAME is invalid")

    config = AdminCompositionConfig(
        target=target,
        administrator_username=username,
        administrator_password_file=Path(_required(source, "PFSENSE_ADMIN_PASSWORD_FILE")).expanduser(),
        service_api_key_file=Path(_required(source, "PFSENSE_READONLY_SERVICE_API_KEY_FILE")).expanduser(),
        state_directory=Path(_required(source, "PFSENSE_ADMIN_STATE_DIR")).expanduser(),
        journal_integrity_key_file=Path(_required(source, "PFSENSE_ADMIN_JOURNAL_KEY_FILE")).expanduser(),
        schema_file=Path(_required(source, "PFSENSE_ADMIN_SCHEMA_FILE")).expanduser(),
        schema_version=_required(source, "PFSENSE_ADMIN_SCHEMA_VERSION"),
        restapi_package_version=_parse_package_version(_required(source, "PFSENSE_RESTAPI_PACKAGE_VERSION")),
    )
    file_paths = (
        config.target.key_file,
        config.administrator_password_file,
        config.service_api_key_file,
        config.journal_integrity_key_file,
        config.schema_file,
    )
    if any(not path.is_absolute() for path in file_paths):
        raise AdminCompositionError("Administrative file references must use absolute paths")
    if len(set(file_paths)) != len(file_paths):
        raise AdminCompositionError("Administrative file references must be distinct")
    _validate_owner_directory(config.state_directory, label="Administrative state directory")
    _validate_custody_path(config.service_api_key_file)
    if config.target.tls_ca_file is not None:
        _validate_owner_controlled_material(config.target.tls_ca_file, label="TLS CA file", maximum=_MAX_SCHEMA_BYTES)
    return config


def _namespace(
    config: AdminCompositionConfig,
    *,
    operation_type: AdministrativeOperationType = AdministrativeOperationType.BOOTSTRAP,
) -> str:
    payload: dict[str, str] = {
        "target_origin": config.target.base_url,
        "target_identity": config.target.identity,
        "account_identity": _ACCOUNT_NAME,
        "approved_profile": _PROFILE,
    }
    # Mirrors security_admin_composition.py::_namespace() exactly (added for the POST-v1.0 MANAGED
    # READ-ONLY WIZARD INTEGRATION mission, 2026-08-29, to let a managed read_only apply's inline
    # RECOVERY_REQUIRED delegation use its own fresh recovery-typed journal, distinct from bootstrap's):
    # `operation_type` is deliberately omitted from the payload for the BOOTSTRAP default, so every
    # existing bootstrap namespace/journal/lock path for this account is byte-for-byte unchanged.
    if operation_type is not AdministrativeOperationType.BOOTSTRAP:
        payload["operation_type"] = operation_type.value
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"pfsense-mcp-adr033-admin-namespace-v1\x00" + canonical).hexdigest()


def build_readonly_admin_context(
    source: Mapping[str, str],
    *,
    operation_type: AdministrativeOperationType = AdministrativeOperationType.BOOTSTRAP,
) -> AdministrativeContext:
    """Construct one target-bound admin stack for the dedicated
    `read_only` managed service account, without network or mutation.
    Structurally identical to `build_admin_context()` except: the
    freshness gate is against `read_profile_requirements()` (the 95
    READ-only privileges, never the write_protected combined set), the
    fixed account is `pfsense-mcp-readonly`, and every mutation closure
    calls `TargetProfile.READ_ONLY`/`security_readonly_bootstrap_
    recovery.py`'s functions instead of the write_protected
    equivalents.

    `operation_type` mirrors `build_admin_context()`'s own parameter of
    the same name -- added so `security_recovery_orchestration.py` can
    build this account's own recovery-typed context (a fresh journal
    distinct from its bootstrap journal) instead of only ever being able
    to build the bootstrap one."""

    config = load_readonly_admin_composition_config(source)
    schema, schema_digest = _load_schema(config.schema_file)
    resolved = resolve_profile_privileges(schema, read_profile_requirements())
    if (
        not resolved
        or any(not item.ok or item.evidence_class is not EvidenceClass.SOURCE_CROSS_CHECKED for item in resolved)
        or not distinct_ok_privileges(resolved)
    ):
        raise AdminCompositionError("Approved profile is not fully source-cross-checked by the configured schema")
    integrity_key = _read_secure_file(
        config.journal_integrity_key_file,
        maximum=_MAX_SECRET_BYTES,
        label="Operation journal integrity key",
    )
    _load_admin_api_key(config.target)
    _read_secret_text(config.administrator_password_file, label="Administrator password file")

    namespace = _namespace(config, operation_type=operation_type)
    binding = AdminTargetBinding(
        target_origin=config.target.base_url,
        target_identity=config.target.identity,
        account_identity=_ACCOUNT_NAME,
        approved_profile=_PROFILE,
        schema_version=config.schema_version,
        schema_evidence_digest=schema_digest,
        namespace=namespace,
    )
    journal_path = config.state_directory / f"adr033-{namespace}.journal"
    lock_path = config.state_directory / f"adr033-{namespace}.lock"
    journal = OperationJournal(journal_path, integrity_key)
    lock = ExclusiveOperationLock(lock_path, integrity_key)
    status = AdministrativeStatusService(
        journal=journal,
        journal_path=journal_path,
        lock=lock,
        expected_binding=binding,
        service_api_key_file=config.service_api_key_file,
    )
    snapshot, trusted = status._load_bound_journal()
    if not trusted:
        raise AdminCompositionError("Existing operation journal is corrupt or bound to another target")
    lock_observation = lock.inspect()
    if lock_observation.state is LockState.CORRUPT:
        raise AdminCompositionError("Existing operation lock is corrupt or unsafe")
    if snapshot is None and lock_observation.state not in {LockState.ABSENT, LockState.RELEASED}:
        raise AdminCompositionError("Operation lock exists without a matching operation journal")
    if (
        snapshot is not None
        and lock_observation.operation_id is not None
        and lock_observation.operation_id != snapshot.latest.binding.operation_id
    ):
        raise AdminCompositionError("Operation lock belongs to a different operation")

    verify = resolve_verify(config.target.tls_mode, config.target.tls_ca_file)

    def keyauth_factory() -> HttpTransport:
        return HttpTransport(config.target.base_url, _load_admin_api_key(config.target), verify)

    def basicauth_factory() -> BasicAuthHttpTransport:
        password = _read_secret_text(config.administrator_password_file, label="Administrator password file")
        return BasicAuthHttpTransport(config.target.base_url, config.administrator_username, password, verify)

    def self_service_factory(username: str, password: str) -> Transport:
        if username != _ACCOUNT_NAME:
            raise AdminCompositionError("Self-service transport requested for an unexpected account")
        return BasicAuthHttpTransport(config.target.base_url, username, password, verify)

    def bootstrap_call() -> ProvisioningResult:
        transport = keyauth_factory()
        try:
            return provision_service_account(
                admin_transport=transport,
                self_service_transport_factory=self_service_factory,
                api_version=ApiVersion.V2,
                username=_ACCOUNT_NAME,
                target_profile=TargetProfile.READ_ONLY,
                schema=schema,
                installed_package_version=config.restapi_package_version,
                user_descr=READONLY_RECOVERY_USER_DESCRIPTION,
                key_descr=READONLY_RECOVERY_KEY_DESCRIPTION,
            )
        finally:
            transport.close()

    def revoke_call() -> ReadonlyRecoveryDeletionEvidence:
        admin_transport = keyauth_factory()
        revocation_transport = basicauth_factory()
        try:
            return revoke_failed_readonly_bootstrap_api_key(
                admin_transport=admin_transport,
                key_revocation_transport=revocation_transport,
                api_version=ApiVersion.V2,
            )
        finally:
            admin_transport.close()
            revocation_transport.close()

    def delete_call() -> ReadonlyRecoveryDeletionEvidence:
        transport = keyauth_factory()
        try:
            return delete_dedicated_readonly_recovery_user(
                admin_transport=transport, schema=schema, api_version=ApiVersion.V2
            )
        finally:
            transport.close()

    def identify_orphan_key() -> ObservedApiKey:
        transport = keyauth_factory()
        try:
            return identify_orphan_readonly_api_key_candidate(admin_transport=transport, api_version=ApiVersion.V2)
        finally:
            transport.close()

    def identify_dedicated_user() -> ObservedUser:
        transport = keyauth_factory()
        try:
            return identify_dedicated_readonly_recovery_user_candidate(
                admin_transport=transport, schema=schema, api_version=ApiVersion.V2
            )
        finally:
            transport.close()

    def auth_transition_factory() -> AuthMethodTransitionCoordinator:
        return AuthMethodTransitionCoordinator(
            keyauth_transport_factory=keyauth_factory,
            basicauth_transport_factory=basicauth_factory,
            api_version=ApiVersion.V2,
            reconnect_policy=ReconnectPolicy(),
        )

    def observe_restart_state() -> tuple[AccountProvisioningObservation, frozenset[str]]:
        transport = keyauth_factory()
        try:
            account = observe_account_provisioning_state(
                admin_transport=transport,
                api_version=ApiVersion.V2,
                username=_ACCOUNT_NAME,
                target_profile=TargetProfile.READ_ONLY,
                schema=schema,
                installed_package_version=config.restapi_package_version,
                user_descr=READONLY_RECOVERY_USER_DESCRIPTION,
            )
            client = BootstrapProvisioningClient(transport, api_version=ApiVersion.V2)
            auth_settings = client._observe_auth_settings_for_transition()
            return account, auth_settings.auth_methods
        finally:
            transport.close()

    mutation_components = _FixedMutationComponents(
        keyauth_transport_factory=keyauth_factory,
        basicauth_transport_factory=basicauth_factory,
        bootstrap_call=bootstrap_call,
        revoke_orphan_key_call=revoke_call,
        delete_dedicated_user_call=delete_call,
        identify_orphan_key_candidate=identify_orphan_key,
        identify_dedicated_user_candidate=identify_dedicated_user,
        auth_transition_factory=auth_transition_factory,
        observe_restart_state_call=observe_restart_state,
        journal_integrity_key=integrity_key,
    )
    return AdministrativeContext(
        config=config,
        binding=binding,
        status=status,
        journal_path=journal_path,
        lock_path=lock_path,
        _journal=journal,
        _lock=lock,
        _mutation_components=mutation_components,
    )


__all__ = [
    "build_readonly_admin_context",
    "load_readonly_admin_composition_config",
]
