"""Fixed, offline composition for ADR-033 administrative components.

This module is an internal construction boundary, not a command surface.  It
loads explicit secure references, binds them to one pfSense target and the one
approved service-account profile, and assembles closed bootstrap, recovery,
authentication-transition, journal, lock, and restart-classification
dependencies.  Construction performs no network call or mutation.

Only the read-only :class:`AdministrativeStatusService` is exposed.  Mutating
call bindings remain private until a separately reviewed journal-aware
orchestration and CLI slice exists.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .api_version import ApiVersion
from .config import PfSenseConfig, load_api_key, load_config
from .errors import ConfigurationError
from .secure_file import open_nofollow, validate_descriptor
from .security_auth_transition import AuthMethodTransitionCoordinator, ReconnectPolicy
from .security_bootstrap_client import BootstrapProvisioningClient, ObservedApiKey, ObservedUser
from .security_bootstrap_engine import (
    AccountProvisioningObservation,
    ProvisioningResult,
    TargetProfile,
    observe_account_provisioning_state,
    provision_service_account,
)
from .security_bootstrap_recovery import (
    RECOVERY_KEY_DESCRIPTION,
    RECOVERY_USER_DESCRIPTION,
    RecoveryDeletionEvidence,
    UnprovisionedIncidentEvidence,
    delete_dedicated_recovery_user,
    identify_dedicated_recovery_user_candidate,
    identify_orphan_api_key_candidate,
    identify_unprovisioned_incident_evidence,
    revoke_failed_bootstrap_api_key,
)
from .security_operation_journal import (
    AdministrativeOperationType,
    AuthoritativeRestartObservation,
    ExclusiveOperationLock,
    JournalSnapshot,
    LocalArtifactObservation,
    LockState,
    OperationBinding,
    OperationJournal,
    OperationJournalError,
    RecoveryAction,
    RestartClassification,
    RestartDecision,
    classify_restart,
)
from .security_privileges import (
    EvidenceClass,
    distinct_ok_privileges,
    resolve_profile_privileges,
    write_protected_profile_requirements,
)
from .tls import TLSMode, resolve_verify
from .transport.base import Transport
from .transport.http import BasicAuthHttpTransport, HttpTransport

_ACCOUNT_NAME = "pfsense-mcp"
_PROFILE = "write_protected"
_MAX_SECRET_BYTES = 16 * 1024
_MAX_SCHEMA_BYTES = 8 * 1024 * 1024
_MAX_IDENTITY_LENGTH = 128
_REQUIRED_ADMIN_VARS = frozenset(
    {
        "PFSENSE_API_URL",
        "PFSENSE_IDENTITY",
        "PFSENSE_API_KEY_FILE",
        "PFSENSE_API_VERSION",
        "PFSENSE_TLS_MODE",
        "PFSENSE_ADMIN_USERNAME",
        "PFSENSE_ADMIN_PASSWORD_FILE",
        "PFSENSE_SERVICE_API_KEY_FILE",
        "PFSENSE_ADMIN_STATE_DIR",
        "PFSENSE_ADMIN_JOURNAL_KEY_FILE",
        "PFSENSE_ADMIN_SCHEMA_FILE",
        "PFSENSE_ADMIN_SCHEMA_VERSION",
        "PFSENSE_RESTAPI_PACKAGE_VERSION",
    }
)


class AdminCompositionError(Exception):
    """Secure administrative composition failed closed."""


@dataclass(frozen=True)
class AdminCompositionConfig:
    """Secret-free, explicit configuration for one fixed admin stack."""

    target: PfSenseConfig
    administrator_username: str
    administrator_password_file: Path
    service_api_key_file: Path
    state_directory: Path
    journal_integrity_key_file: Path
    schema_file: Path
    schema_version: str
    restapi_package_version: tuple[int, int, int]

    def __repr__(self) -> str:
        return (
            "AdminCompositionConfig("
            f"target_origin={self.target.base_url!r}, target_identity={self.target.identity!r}, "
            f"administrator_username={self.administrator_username!r}, "
            f"service_account={_ACCOUNT_NAME!r}, profile={_PROFILE!r})"
        )


@dataclass(frozen=True)
class AdminTargetBinding:
    target_origin: str
    target_identity: str
    account_identity: str
    approved_profile: str
    schema_version: str
    schema_evidence_digest: str
    namespace: str


@dataclass(frozen=True)
class AdministrativeServiceAvailability:
    bootstrap_available: bool
    recovery_action: RecoveryAction | None
    restart_decision: RestartDecision


@dataclass(frozen=True)
class _FixedMutationComponents:
    """Private fixed call graph; deliberately absent from public context API."""

    keyauth_transport_factory: Callable[[], HttpTransport] = field(repr=False)
    basicauth_transport_factory: Callable[[], BasicAuthHttpTransport] = field(repr=False)
    bootstrap_call: Callable[[], ProvisioningResult] = field(repr=False)
    revoke_orphan_key_call: Callable[[], RecoveryDeletionEvidence] = field(repr=False)
    delete_dedicated_user_call: Callable[[], RecoveryDeletionEvidence] = field(repr=False)
    #: Read-only identification, never a mutation -- shares the exact
    #: same selection logic `revoke_orphan_key_call`/`delete_dedicated_user_call`
    #: apply on their own first read (see `identify_orphan_api_key_candidate()`/
    #: `identify_dedicated_recovery_user_candidate()`'s own docstrings). A
    #: recovery orchestration layer uses these to resolve the current
    #: candidate object for confirmation-token binding, without needing its
    #: own transport-construction access.
    identify_orphan_key_candidate: Callable[[], ObservedApiKey] = field(repr=False)
    identify_dedicated_user_candidate: Callable[[], ObservedUser] = field(repr=False)
    #: Read-only, two-independent-reads proof of absence for
    #: RECOVER_UNPROVISIONED_INCIDENT -- see
    #: `identify_unprovisioned_incident_evidence()`'s own docstring.
    #: Never a mutation; shares the same role as the two candidate-
    #: identification callables above, just proving an absence rather
    #: than resolving a candidate object to act on.
    identify_unprovisioned_incident_evidence_call: Callable[[], UnprovisionedIncidentEvidence] = field(repr=False)
    auth_transition_factory: Callable[[], AuthMethodTransitionCoordinator] = field(repr=False)
    #: Read-only, fresh-live-evidence restart-observation primitive.
    #: Never a mutation -- calls only `list_users()` and the existing
    #: auth-settings GET. Used exclusively to build an
    #: `AuthoritativeRestartObservation` for `classify_restart()`;
    #: never consulted when deciding whether to start a *new*
    #: operation. See `security_bootstrap_orchestration.py`'s
    #: `build_authoritative_restart_observation()`.
    observe_restart_state_call: Callable[[], tuple[AccountProvisioningObservation, frozenset[str]]] = field(repr=False)
    #: The already-validated journal integrity key, exposed so a recovery
    #: orchestration layer can derive/verify a confirmation token bound to
    #: the same key that already authenticates every journal/lock record
    #: -- avoids re-reading the secret file a second time and avoids a new
    #: secret/credential of its own.
    journal_integrity_key: bytes = field(repr=False)


class AdministrativeStatusService:
    """Read-only local restart/status facade with no transport dependency."""

    def __init__(
        self,
        *,
        journal: OperationJournal,
        journal_path: Path,
        lock: ExclusiveOperationLock,
        expected_binding: AdminTargetBinding,
        service_api_key_file: Path,
    ) -> None:
        self._journal = journal
        self._journal_path = journal_path
        self._lock = lock
        self._expected = expected_binding
        self._service_api_key_file = service_api_key_file

    def classify(
        self,
        *,
        authoritative: AuthoritativeRestartObservation | None,
    ) -> RestartDecision:
        snapshot, trusted = self._load_bound_journal()
        return classify_restart(
            journal=snapshot,
            journal_trusted=trusted,
            lock=self._lock.inspect(),
            artifacts=self._observe_local_artifacts(),
            authoritative=authoritative,
        )

    def availability(
        self,
        *,
        authoritative: AuthoritativeRestartObservation | None,
    ) -> AdministrativeServiceAvailability:
        decision = self.classify(authoritative=authoritative)
        return AdministrativeServiceAvailability(
            bootstrap_available=decision.classification is RestartClassification.CLEAN_NO_OPERATION,
            recovery_action=(
                decision.recovery_action
                if decision.classification
                in {RestartClassification.PARTIAL_SERVER_STATE, RestartClassification.RECOVERY_REQUIRED}
                else None
            ),
            restart_decision=decision,
        )

    def _load_bound_journal(self) -> tuple[JournalSnapshot | None, bool]:
        if not self._journal_path.exists() and not self._journal_path.is_symlink():
            return None, True
        try:
            snapshot = self._journal.load()
        except OperationJournalError:
            return None, False
        binding = snapshot.latest.binding
        expected = self._expected
        trusted = (
            binding.target_origin == expected.target_origin
            and binding.target_identity == expected.target_identity
            and binding.account_identity == expected.account_identity
            and binding.approved_profile == expected.approved_profile
            and binding.schema_version == expected.schema_version
            and binding.schema_evidence_digest == expected.schema_evidence_digest
            and binding.starting_auth_methods == ("KeyAuth",)
        )
        return snapshot, trusted

    def _observe_local_artifacts(self) -> LocalArtifactObservation:
        path = self._service_api_key_file
        if not path.exists() and not path.is_symlink():
            return LocalArtifactObservation(trusted=True, key_custody_present=False)
        try:
            descriptor = open_nofollow(path, on_error=_composition_error)
            try:
                validate_descriptor(path, descriptor, max_bytes=_MAX_SECRET_BYTES, on_error=_composition_error)
            finally:
                os.close(descriptor)
        except AdminCompositionError:
            return LocalArtifactObservation(trusted=False)
        return LocalArtifactObservation(trusted=True, key_custody_present=True)


@dataclass(frozen=True)
class AdministrativeContext:
    """Constructed fixed stack; public surface is intentionally read-only."""

    config: AdminCompositionConfig
    binding: AdminTargetBinding
    status: AdministrativeStatusService
    journal_path: Path
    lock_path: Path
    _journal: OperationJournal = field(repr=False)
    _lock: ExclusiveOperationLock = field(repr=False)
    _mutation_components: _FixedMutationComponents = field(repr=False)

    def __repr__(self) -> str:
        return (
            "AdministrativeContext("
            f"target_origin={self.binding.target_origin!r}, "
            f"target_identity={self.binding.target_identity!r}, "
            f"account_identity={self.binding.account_identity!r}, "
            f"approved_profile={self.binding.approved_profile!r})"
        )

    def new_operation_binding(
        self, *, operation_id: str, operation_type: AdministrativeOperationType
    ) -> OperationBinding:
        """Create secret-free immutable metadata; does not create a journal."""

        return OperationBinding(
            operation_id=operation_id,
            operation_type=operation_type,
            target_identity=self.binding.target_identity,
            target_origin=self.binding.target_origin,
            account_identity=self.binding.account_identity,
            approved_profile=self.binding.approved_profile,
            schema_version=self.binding.schema_version,
            schema_evidence_digest=self.binding.schema_evidence_digest,
            starting_auth_methods=("KeyAuth",),
        )


def _composition_error(message: str) -> AdminCompositionError:
    return AdminCompositionError(message)


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None or not value.strip():
        raise AdminCompositionError(f"Missing required administrative configuration: {name}")
    return value


def _read_secure_file(path: Path, *, maximum: int, label: str) -> bytes:
    descriptor = open_nofollow(path, on_error=_composition_error)
    try:
        validate_descriptor(path, descriptor, max_bytes=maximum, on_error=_composition_error)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
        value = b"".join(chunks)
    except OSError:
        raise AdminCompositionError(f"{label} could not be read securely") from None
    finally:
        os.close(descriptor)
    if not value:
        raise AdminCompositionError(f"{label} is empty")
    return value


def _read_secret_text(path: Path, *, label: str) -> str:
    raw = _read_secure_file(path, maximum=_MAX_SECRET_BYTES, label=label)
    first_line = raw.split(b"\n", maxsplit=1)[0]
    try:
        value = first_line.decode("utf-8")
    except UnicodeDecodeError:
        raise AdminCompositionError(f"{label} is not valid UTF-8") from None
    if not value or value != value.strip() or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise AdminCompositionError(f"{label} is malformed")
    return value


def _load_admin_api_key(config: PfSenseConfig) -> str:
    try:
        return load_api_key(config)
    except ConfigurationError as exc:
        raise AdminCompositionError(f"Administrator API-key reference is unsafe: {exc}") from None


def _validate_owner_directory(path: Path, *, label: str) -> None:
    if not path.is_absolute():
        raise AdminCompositionError(f"{label} path must be absolute")
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        raise AdminCompositionError(f"{label} is unavailable") from None
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AdminCompositionError(f"{label} must be an owner-only directory")


def _validate_custody_path(path: Path) -> None:
    if not path.is_absolute():
        raise AdminCompositionError("Service API-key custody path must be absolute")
    _validate_owner_directory(path.parent, label="Service API-key custody directory")
    if path.is_symlink():
        raise AdminCompositionError("Service API-key custody path must not be a symbolic link")
    if path.exists():
        descriptor = open_nofollow(path, on_error=_composition_error)
        try:
            validate_descriptor(path, descriptor, max_bytes=_MAX_SECRET_BYTES, on_error=_composition_error)
        finally:
            os.close(descriptor)


def _validate_owner_controlled_material(path: Path, *, label: str, maximum: int) -> None:
    """Permit read-only sharing, but never a symlink or non-owner-writable file."""

    if not path.is_absolute():
        raise AdminCompositionError(f"{label} path must be absolute")
    descriptor = open_nofollow(path, on_error=_composition_error)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size > maximum
        ):
            raise AdminCompositionError(f"{label} is not owner-controlled regular material")
    except OSError:
        raise AdminCompositionError(f"{label} metadata could not be validated") from None
    finally:
        os.close(descriptor)


def _parse_package_version(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isascii() or not part.isdigit() for part in parts):
        raise AdminCompositionError("PFSENSE_RESTAPI_PACKAGE_VERSION must be an exact three-part version")
    version = tuple(int(part) for part in parts)
    return version[0], version[1], version[2]


def _load_schema(path: Path) -> tuple[dict[str, Any], str]:
    raw = _read_secure_file(path, maximum=_MAX_SCHEMA_BYTES, label="Administrative OpenAPI schema")
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeError):
        raise AdminCompositionError("Administrative OpenAPI schema is malformed") from None
    if not isinstance(parsed, dict) or not parsed:
        raise AdminCompositionError("Administrative OpenAPI schema must be a non-empty object")
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    digest = hashlib.sha256(b"pfsense-mcp-adr033-schema-v1\x00" + canonical).hexdigest()
    return parsed, digest


def load_admin_composition_config(source: Mapping[str, str]) -> AdminCompositionConfig:
    """Load explicit references only; never searches for credentials or state."""

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
        service_api_key_file=Path(_required(source, "PFSENSE_SERVICE_API_KEY_FILE")).expanduser(),
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
    resolution_operation_id: str | None = None,
) -> str:
    payload: dict[str, str] = {
        "target_origin": config.target.base_url,
        "target_identity": config.target.identity,
        "account_identity": _ACCOUNT_NAME,
        "approved_profile": _PROFILE,
    }
    # `operation_type` is deliberately omitted from the payload for the
    # BOOTSTRAP default, so every existing bootstrap namespace/journal/lock
    # path is byte-for-byte unchanged by this parameter's existence. Only a
    # non-default operation_type (the two ADR-033 recovery actions) adds a
    # new key, giving each its own fresh journal/lock file distinct from
    # bootstrap's -- see RECOVER_ORPHAN_KEY/RECOVER_DEDICATED_USER's own
    # docstring in security_operation_journal.py for why recovery must
    # never continue the original operation's journal (RECOVERY_REQUIRED
    # is a deliberately terminal DurableOperationState).
    if operation_type is not AdministrativeOperationType.BOOTSTRAP:
        payload["operation_type"] = operation_type.value
    # `resolution_operation_id`, when given, is likewise omitted unless
    # present -- every ordinary (non-retry) bootstrap/recovery namespace
    # is completely unaffected by this parameter's existence. When a
    # caller supplies it (only `security_recovery_orchestration.py`, after
    # independently proving a COMPLETED, MAC-bound RECOVER_UNPROVISIONED_
    # INCIDENT record exists for the incident occupying the plain BOOTSTRAP
    # namespace -- this function performs no such proof itself, it is a
    # pure path-derivation primitive), the *retry* attempt gets its own
    # fresh journal/lock, distinct from the original incident's, so
    # `OperationJournal.create()`'s `O_CREAT | O_EXCL` semantics can
    # succeed without ever touching, truncating, or overwriting the
    # original incident journal (see `derive_resolution_operation_id()`'s
    # own docstring in security_operation_journal.py for why a
    # classification-only fix cannot work here).
    if resolution_operation_id is not None:
        payload["resolution_operation_id"] = resolution_operation_id
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"pfsense-mcp-adr033-admin-namespace-v1\x00" + canonical).hexdigest()


def build_admin_context(
    source: Mapping[str, str],
    *,
    operation_type: AdministrativeOperationType = AdministrativeOperationType.BOOTSTRAP,
    resolution_operation_id: str | None = None,
) -> AdministrativeContext:
    """Construct one target-bound admin stack without network or mutation.

    `resolution_operation_id` (default `None`, fully backward compatible):
    see `_namespace()`'s own docstring. This function performs no
    verification of what it's given -- it is a pure construction
    boundary, exactly like every other parameter here. Only
    `security_recovery_orchestration.py` may pass a non-`None` value, and
    only after it has itself independently loaded and verified a
    COMPLETED, correctly-bound RECOVER_UNPROVISIONED_INCIDENT journal
    record whose own `operation_id` equals the value passed here -- the
    same "verify before you build" discipline that module's existing
    `recovery_context = build_context(source, operation_type=...)` call
    already follows for the two pre-existing recovery actions. Only
    meaningful when `operation_type` is `BOOTSTRAP`; raises otherwise
    (a resolution cannot apply to a recovery-typed namespace)."""

    if resolution_operation_id is not None and operation_type is not AdministrativeOperationType.BOOTSTRAP:
        raise AdminCompositionError("resolution_operation_id is only meaningful for a BOOTSTRAP operation_type")
    config = load_admin_composition_config(source)
    schema, schema_digest = _load_schema(config.schema_file)
    resolved = resolve_profile_privileges(schema, write_protected_profile_requirements())
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
    # Validate both credentials during construction without retaining their values
    # in public configuration or error text.
    _load_admin_api_key(config.target)
    _read_secret_text(config.administrator_password_file, label="Administrator password file")

    namespace = _namespace(config, operation_type=operation_type, resolution_operation_id=resolution_operation_id)
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
                target_profile=TargetProfile.WRITE_PROTECTED,
                schema=schema,
                installed_package_version=config.restapi_package_version,
                user_descr=RECOVERY_USER_DESCRIPTION,
                key_descr=RECOVERY_KEY_DESCRIPTION,
            )
        finally:
            transport.close()

    def revoke_call() -> RecoveryDeletionEvidence:
        admin_transport = keyauth_factory()
        revocation_transport = basicauth_factory()
        try:
            return revoke_failed_bootstrap_api_key(
                admin_transport=admin_transport,
                key_revocation_transport=revocation_transport,
                api_version=ApiVersion.V2,
            )
        finally:
            admin_transport.close()
            revocation_transport.close()

    def delete_call() -> RecoveryDeletionEvidence:
        transport = keyauth_factory()
        try:
            return delete_dedicated_recovery_user(admin_transport=transport, schema=schema, api_version=ApiVersion.V2)
        finally:
            transport.close()

    def identify_orphan_key() -> ObservedApiKey:
        transport = keyauth_factory()
        try:
            return identify_orphan_api_key_candidate(admin_transport=transport, api_version=ApiVersion.V2)
        finally:
            transport.close()

    def identify_dedicated_user() -> ObservedUser:
        transport = keyauth_factory()
        try:
            return identify_dedicated_recovery_user_candidate(
                admin_transport=transport, schema=schema, api_version=ApiVersion.V2
            )
        finally:
            transport.close()

    def identify_unprovisioned_incident() -> UnprovisionedIncidentEvidence:
        transport = keyauth_factory()
        try:
            return identify_unprovisioned_incident_evidence(admin_transport=transport, api_version=ApiVersion.V2)
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
                target_profile=TargetProfile.WRITE_PROTECTED,
                schema=schema,
                installed_package_version=config.restapi_package_version,
                user_descr=RECOVERY_USER_DESCRIPTION,
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
        identify_unprovisioned_incident_evidence_call=identify_unprovisioned_incident,
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
    "AdminCompositionConfig",
    "AdminCompositionError",
    "AdminTargetBinding",
    "AdministrativeContext",
    "AdministrativeServiceAvailability",
    "AdministrativeStatusService",
    "build_admin_context",
    "load_admin_composition_config",
]
