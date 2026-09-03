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
from enum import Enum
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
    DurableOperationState,
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
    derive_resolution_operation_id,
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


class PfRestReadOnlyStatus(str, Enum):
    """Result of the bootstrap read-only pre-flight check (Mission II
    Mission B) -- never raises; every ambiguity collapses to a blocked
    value, matching this codebase's established "return a value, never
    propagate an ambiguous failure" discipline (see e.g.
    `build_authoritative_restart_observation()`'s own docstring)."""

    #: `GET /system/restapi/settings` was read successfully and reports
    #: `read_only: false` -- bootstrap may proceed to mutate.
    WRITABLE = "writable"
    #: Confirmed `read_only: true` -- pfSense will reject every non-GET
    #: request with HTTP 405 at the server. A harmless, environmental,
    #: always-retryable pre-flight rejection (see
    #: `security_bootstrap_orchestration.py`'s own docstring on the
    #: journal boundary this status is checked against).
    BLOCKED_READ_ONLY = "blocked_read_only"
    #: The GET failed (network/TLS/auth/HTTP error) or the response was
    #: malformed/ambiguous -- treated identically to a confirmed
    #: `read_only: true` by every caller: fail closed on any ambiguity,
    #: never assume the appliance is writable without proof.
    BLOCKED_UNVERIFIABLE = "blocked_unverifiable"


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
    #: Read-only pre-flight observation of pfSense's own global REST API
    #: "Read Only" mode (Mission II Mission B). Never raises -- see
    #: `PfRestReadOnlyStatus`'s own docstring. `security_bootstrap_
    #: orchestration.py` calls this *before* creating any journal record
    #: for a new bootstrap attempt, so a confirmed- or unverifiable-
    #: read-only rejection never advances local state at all.
    check_pfrest_read_only_call: Callable[[], PfRestReadOnlyStatus] = field(repr=False)
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
    `security_recovery_orchestration.py`/`security_bootstrap_
    orchestration.py` (via `locate_bootstrap_chain_frontier()`) may pass
    a non-`None` value, and only after independently loading and
    verifying a COMPLETED, correctly-bound RECOVER_UNPROVISIONED_INCIDENT
    journal record whose own `operation_id` equals the value passed here
    -- the same "verify before you build" discipline those callers'
    existing `build_context(source, operation_type=...)` calls already
    follow for the two pre-existing recovery actions.

    Meaningful when `operation_type` is `BOOTSTRAP` (selects a retry
    generation's own bootstrap namespace) *or* `RECOVER_UNPROVISIONED_
    INCIDENT` (selects that same generation's *own* resolution namespace,
    distinct from generation 0's fixed one -- see `locate_bootstrap_
    chain_frontier()`'s own docstring for why both operation types share
    this one parameter); raises for the other two recovery-action types,
    which never participate in the unprovisioned-incident chain."""

    if resolution_operation_id is not None and operation_type not in {
        AdministrativeOperationType.BOOTSTRAP,
        AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT,
    }:
        raise AdminCompositionError(
            "resolution_operation_id is only meaningful for a BOOTSTRAP or "
            "RECOVER_UNPROVISIONED_INCIDENT operation_type"
        )
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

    def check_read_only() -> PfRestReadOnlyStatus:
        transport = keyauth_factory()
        try:
            mode = BootstrapProvisioningClient(transport, api_version=ApiVersion.V2).observe_restapi_mode()
        except Exception:  # deliberately broad: any GET/parse failure fails closed, never assumes writable
            return PfRestReadOnlyStatus.BLOCKED_UNVERIFIABLE
        finally:
            transport.close()
        return PfRestReadOnlyStatus.BLOCKED_READ_ONLY if mode.read_only else PfRestReadOnlyStatus.WRITABLE

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
        check_pfrest_read_only_call=check_read_only,
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


#: Hard cap on how many RESOLVE_UNPROVISIONED_INCIDENT generations
#: `locate_bootstrap_chain_frontier()` will ever walk forward through in
#: one call. Not a defense against a genuine cycle -- each generation's
#: namespace is a SHA256 hash deterministically derived from its parent
#: resolution's own HMAC-authenticated `operation_id`
#: (`derive_resolution_operation_id()`), so an honest chain cannot loop;
#: forging one would require the owner-controlled journal integrity key,
#: outside this codebase's threat model (the same trust assumption every
#: other journal/lock integrity check here already makes). This cap
#: exists purely so a walk always terminates in bounded time even under
#: an unanticipated or corrupted on-disk state, and so it is directly
#: testable without constructing dozens of real generations.
_MAX_CHAIN_GENERATIONS = 64


@dataclass(frozen=True)
class ChainGenerationSummary:
    """One inspectable step of a `locate_bootstrap_chain_frontier()`
    walk -- never used to make a decision itself, only to let a human
    (via `recover`'s own output) or a test see exactly which generations
    were visited and why the walk stopped where it did."""

    generation: int
    operation_id: str | None
    classification: RestartClassification
    recovery_action: RecoveryAction | None
    resolved: bool


@dataclass(frozen=True)
class ChainFrontier:
    """The result of walking the deterministic incident -> resolution ->
    retry-namespace chain forward from generation 0 (see
    `locate_bootstrap_chain_frontier()`)."""

    generation: int
    #: The `resolution_operation_id` that reached `context`'s own
    #: namespace -- `None` for generation 0 (the fixed, original
    #: bootstrap namespace), otherwise the prior generation's completed
    #: resolution's own `operation_id`. Callers needing to build this
    #: same generation's *resolution*-typed context (`operation_type=
    #: RECOVER_UNPROVISIONED_INCIDENT`) pass this exact value as
    #: `resolution_operation_id` -- see `_namespace()`'s own docstring.
    resolution_operation_id: str | None
    context: AdministrativeContext
    decision: RestartDecision
    chain: tuple[ChainGenerationSummary, ...]


def locate_bootstrap_chain_frontier(
    context0: AdministrativeContext,
    *,
    source: Mapping[str, str],
    build_context: Callable[..., AdministrativeContext],
) -> ChainFrontier:
    """Deterministically, offline, walk forward from generation 0 (the
    fixed bootstrap namespace `context0` is already built against)
    through however many RESOLVE_UNPROVISIONED_INCIDENT generations are
    already resolved, and return the *frontier*: the first generation
    that is not a completely-resolved link in the chain -- either a
    fresh, never-attempted namespace, or an incident that still needs
    attention (of any kind, including the two pre-existing recovery
    actions, which never chain past their own generation).

    ## Why generation N's resolution shares a namespace parameter with
    ## generation N's own bootstrap namespace

    Generation N's bootstrap namespace is `_namespace(BOOTSTRAP,
    resolution_operation_id=R)`, where `R` is generation N-1's own
    completed resolution's `operation_id` (`None` for generation 0 --
    today's existing, unchanged fixed namespace). Generation N's own
    *resolution* -- the RESOLVE_UNPROVISIONED_INCIDENT journal that
    would close generation N's incident -- reuses that exact same `R` as
    its `_namespace(RECOVER_UNPROVISIONED_INCIDENT, resolution_
    operation_id=R)` salt. This keeps generation 0's resolution at
    today's fixed, singleton namespace (`R=None`, byte-for-byte
    unchanged -- required so the real, already-completed production
    incident-0 resolution remains reachable at its existing path), while
    giving every later generation's resolution a distinct namespace of
    its own, so a second, third, ... resolution never collides with an
    earlier one's already-`COMPLETED` journal file.

    ## Hop condition

    A generation is treated as "resolved, keep walking" only when *all*
    of the following hold, each independently re-verified from the
    on-disk journal (never cached, never assumed):
      - this generation's own classification (`authoritative=None`,
        matching every other offline `recover`/`bootstrap` classify()
        call) is exactly `RECOVERY_REQUIRED` with `recovery_action is
        None` -- the one shape RESOLVE_UNPROVISIONED_INCIDENT ever
        applies to (see `RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT`'s
        own docstring). Any other classification -- `CLEAN_NO_OPERATION`
        (fresh, nothing attempted yet), `CLEAN_COMPLETED`/anything else
        while a real `authoritative` observation is later supplied
        (checked by this function's own callers, not here),
        `CORRUPT_OR_UNTRUSTED_LOCAL_STATE`, or `RECOVERY_REQUIRED` with a
        real `recovery_action` (REVOKE_ORPHAN_KEY/DELETE_DEDICATED_USER,
        which never chain past their own generation) -- stops the walk
        immediately, handing that generation back as the frontier.
      - a resolution journal exists at the namespace this exact
        generation's incident would derive
        (`derive_resolution_operation_id(incident_operation_id,
        incident_record_mac)`, using this generation's own freshly
        re-loaded `operation_id`/latest-record `mac` -- never a value
        computed for any other generation), is `trusted` (binding
        matches the current configuration), and is `COMPLETED`, and its
        own `operation_id` equals that freshly re-derived value exactly.
        A resolution computed for a different incident (including an
        adjacent generation, or a stale/tampered file placed at the
        wrong path) can never satisfy this -- an attacker or corrupted
        state cannot forge a match without the trusted integrity key.

    Only once every one of those checks passes does the walk advance:
    `context` becomes `build_context(source, resolution_operation_id=
    expected_resolution_id)` (operation_type defaults to `BOOTSTRAP`),
    `generation` increments, and the loop repeats against the new
    context. Any failure to independently re-verify a hop (missing
    resolution, untrusted binding, wrong operation_id, journal load
    error, `AdminCompositionError` rebuilding a later generation's
    context, or the `_MAX_CHAIN_GENERATIONS` cap) always just **stops
    the walk and returns the last safely-confirmed generation** -- never
    raises past generation 0 and never guesses forward. Under-hopping
    (stopping too early) is always safe: the caller's existing,
    unchanged classify()-driven reporting takes over from there. This
    function never mutates anything, never acquires a lock, and never
    itself performs a RESOLVE_UNPROVISIONED_INCIDENT resolution -- it
    only decides which single context/decision downstream callers act
    on, exactly mirroring the narrower single-hop helper it replaces.
    """

    context = context0
    resolution_operation_id: str | None = None
    generation = 0
    chain: list[ChainGenerationSummary] = []

    while generation < _MAX_CHAIN_GENERATIONS:
        decision = context.status.classify(authoritative=None)
        hoppable = (
            decision.classification is RestartClassification.RECOVERY_REQUIRED
            and decision.recovery_action is None
            and decision.operation_id is not None
        )
        if not hoppable:
            chain.append(
                ChainGenerationSummary(
                    generation=generation,
                    operation_id=decision.operation_id,
                    classification=decision.classification,
                    recovery_action=decision.recovery_action,
                    resolved=False,
                )
            )
            break

        try:
            incident_snapshot = context._journal.load()
        except OperationJournalError:
            chain.append(
                ChainGenerationSummary(
                    generation=generation,
                    operation_id=decision.operation_id,
                    classification=decision.classification,
                    recovery_action=decision.recovery_action,
                    resolved=False,
                )
            )
            break

        incident_operation_id = decision.operation_id
        if incident_operation_id is None:
            # `hoppable` already proved this is unreachable -- defensive only,
            # mirroring security_recovery_orchestration.py's own identical
            # "classify_restart() never returns RECOVERY_REQUIRED without an
            # operation_id" guard.
            break
        expected_resolution_id = derive_resolution_operation_id(
            incident_operation_id=incident_operation_id, incident_record_mac=incident_snapshot.latest.mac
        )
        try:
            resolution_context = build_context(
                source,
                operation_type=AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT,
                resolution_operation_id=resolution_operation_id,
            )
        except AdminCompositionError:
            chain.append(
                ChainGenerationSummary(
                    generation=generation,
                    operation_id=decision.operation_id,
                    classification=decision.classification,
                    recovery_action=decision.recovery_action,
                    resolved=False,
                )
            )
            break

        resolution_snapshot, trusted = resolution_context.status._load_bound_journal()
        resolved = (
            trusted
            and resolution_snapshot is not None
            and resolution_snapshot.latest.state is DurableOperationState.COMPLETED
            and resolution_snapshot.latest.binding.operation_id == expected_resolution_id
        )
        chain.append(
            ChainGenerationSummary(
                generation=generation,
                operation_id=decision.operation_id,
                classification=decision.classification,
                recovery_action=decision.recovery_action,
                resolved=resolved,
            )
        )
        if not resolved:
            break

        try:
            next_context = build_context(source, resolution_operation_id=expected_resolution_id)
        except AdminCompositionError:
            break

        context = next_context
        resolution_operation_id = expected_resolution_id
        generation += 1
        decision = context.status.classify(authoritative=None)

    return ChainFrontier(
        generation=generation,
        resolution_operation_id=resolution_operation_id,
        context=context,
        decision=context.status.classify(authoritative=None),
        chain=tuple(chain),
    )


__all__ = [
    "AdminCompositionConfig",
    "AdminCompositionError",
    "AdminTargetBinding",
    "AdministrativeContext",
    "AdministrativeServiceAvailability",
    "AdministrativeStatusService",
    "ChainFrontier",
    "ChainGenerationSummary",
    "PfRestReadOnlyStatus",
    "build_admin_context",
    "load_admin_composition_config",
    "locate_bootstrap_chain_frontier",
]
