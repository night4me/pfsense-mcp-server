"""W2 -- the fixed production runtime for the alias-description first-WRITE
path (ADR-025/ADR-026, `docs/tier1/IMPLEMENTATION_ROADMAP.md`'s "W2 -- Fixed
production runtime").

Not imported by `application.py`/`factory.py`/`server.py`. Composes the
already-built, production-inert W1 path
(`alias_description.py`/`alias_description_execution.py`) against real,
environment-derived dependencies: the authenticated schema-v7
`RecoveryContract` store, a durable one-time `AuthorizationConsumptionStore`,
the artifact-encryption key/nonce, three pinned Ed25519 authorities
(`PlanAuthorizationV2`, confirmation, reconciliation), the real TPM-witness
anti-rollback anchor, the fixed `AliasDescriptionAdapterV1`/preparer, exactly
one `MutationPolicy` rule, and the same configured pfSense HTTPS/TLS
appliance target already used by the READ path
(`pfsense_mcp.config.load_config()`, unchanged, reused).

Fixed, not configurable: every component is derived deterministically from
environment variables; nothing here accepts a caller-selected endpoint,
method, adapter, capability, transport, policy, authority, store, target,
TLS setting, reconciliation implementation, or executor. No private signing
key is loaded or accepted anywhere in this module -- only Ed25519 *public*
key material (verification only), matching `ed25519_authority.py`'s own
"the private signing key never appears anywhere in this module or this
package" discipline.

Disabled by default: `build_production_runtime()` returns `None` when none
of this module's required environment variables are set -- unconfigured is
the safe, default state, matching `production_store.py`'s own convention
exactly. Partial configuration -- any required piece set without every
other one -- fails closed with `Tier1ConfigurationError`, never guessed.

Fail-closed anti-rollback requirement (ADR-011/ADR-021: `write_protected`
requires anchor assurance != none): a production WRITE runtime is never
constructed with `anti_rollback_anchor=None`. If the witness client cannot
be configured, or the store's own persisted anchor-provisioning record is
not both seeded and complete (`production_store.read_only_anchor_provisioning_status()`,
reused unchanged), `build_production_runtime()` raises rather than
returning a runtime with no anchor enforcement. The mTLS witness-client
construction recipe is the exact one already confirmed working against
real hardware in `pfsense_mcp.tier1_anchor_check`'s
`_build_witness_anchor()` (an explicit `ssl.SSLContext`, never the
`cert=`/`verify=<path>` shorthand) -- reimplemented here, not imported,
because that module lives outside `pfsense_mcp.tier1` and importing it from
inside `tier1/` would be a new, backwards layering direction this module
does not need and does not introduce.

Restart/reconciliation: every call to `build_production_runtime()`
constructs entirely fresh process-local objects (transport, clients,
stores, executor) -- nothing here is cached, memoized, or reused across
calls. Constructing a fresh `MutationExecutor` already triggers the
existing, already-tested `SqliteRecoveryContractStore.reconcile_interrupted()`
call (`executor.py.__init__`, unchanged), which moves any contract left in
`EXECUTING`/`ROLLING_BACK` into `RECONCILIATION` -- the existing, unchanged
manual-only exit per `state_machine.py`. This module adds no new
uncertainty classification: `DEFINITELY_APPLIED`/`DEFINITELY_NOT_APPLIED`/
`AMBIGUOUS` remain exactly `executor.py`'s/`faults.py`'s existing
`EffectKnowledge`/`classify_fault()` machinery, and manual resolution
remains exactly `store.resolve_reconciliation()`, gated by the same pinned
reconciliation authority configured here -- `ProductionAliasDescriptionRuntime.resolve_reconciliation()`
below is a one-line forwarding call, not a second implementation.

W3 Slice 3 (ADR-028 product composition): `request_alias_description_change()`
is the single composed operation tying Slice 2's artifact-exchange
primitives (`artifact_exchange.py`), Slice 3A's `resume_prepared()` seam
(`alias_description_execution.py`), and this existing, completely
unmodified W1/W2 authorization/confirmation/execution chain into ADR-028's
five-state asynchronous product model (`ProductOutcome`). Three additional
fixed, environment-derived, all-or-nothing file paths (never
caller-selectable) are required alongside the existing set: the signed
authorization inbox, the unsigned pending-confirmation outbox, and the
signed confirmation inbox -- exactly three fixed single files, matching
`lab/reconciliation_authority.py`'s own accepted pattern; no directory
scanning, no wildcard discovery. **Not yet MCP-exposed** -- no tool,
endpoint, or product registration imports this method; it remains
reachable only from this module and its own tests, exactly like every
other W1/W2/W3 slice before product activation (Slice 4).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import ssl
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

import httpx

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.config import PfSenseConfig, load_api_key, load_config
from pfsense_mcp.factory import build_pfsense_client, build_write_client
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.tls import TLSMode

from ..secure_file import open_nofollow, validate_descriptor
from .alias_description import (
    ADAPTER_VERSION,
    ENDPOINT_SYMBOL,
    HTTP_METHOD,
    AliasDescriptionChangeV1,
    AliasDescriptionPreparerV1,
    ConfiguredApplianceTargetV1,
)
from .alias_description_execution import AliasDescriptionExecutionCoreV1
from .anti_rollback_tpm_witness import TpmHostWitnessAnchor
from .artifact_exchange import (
    load_signed_confirmation_evidence,
    load_signed_plan_authorization_v2,
    pending_confirmation_request_from_contract,
    pending_confirmation_request_to_bytes,
    write_secure_new,
)
from .authorization_consumption_store import SqliteAuthorizationConsumptionStore
from .confirmation_providers import Ed25519ConfirmationVerifier
from .contract import RecoveryContract
from .ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from .errors import (
    ArtifactExchangeError,
    BoundExecutionError,
    PreparedExecutionIntentError,
    Tier1ConfigurationError,
    Tier1Error,
)
from .executor import MutationExecutor
from .key_lifecycle import KeyPurpose, NonceCounter, load_key_material
from .policy import MutationPolicy, MutationRule
from .production_store import (
    ProductionStoreConfig,
    load_production_store_config,
    open_production_store,
    read_only_anchor_provisioning_status,
)
from .reconciliation import ReconciliationEvidence
from .reconciliation_providers import Ed25519ReconciliationVerifier
from .state_machine import RecoveryState
from .store import SqliteRecoveryContractStore

_CONSUMPTION_STORE_PATH_VAR = "PFSENSE_TIER1_CONSUMPTION_STORE_PATH"
_CONSUMPTION_STORE_KEY_FILE_VAR = "PFSENSE_TIER1_CONSUMPTION_STORE_KEY_FILE"
_ENCRYPTION_KEY_FILE_VAR = "PFSENSE_TIER1_ENCRYPTION_KEY_FILE"
_NONCE_COUNTER_FILE_VAR = "PFSENSE_TIER1_NONCE_COUNTER_FILE"
_AUTHORIZATION_AUTHORITY_FILE_VAR = "PFSENSE_TIER1_AUTHORIZATION_AUTHORITY_FILE"
_CONFIRMATION_AUTHORITY_FILE_VAR = "PFSENSE_TIER1_CONFIRMATION_AUTHORITY_FILE"
_RECONCILIATION_AUTHORITY_FILE_VAR = "PFSENSE_TIER1_RECONCILIATION_AUTHORITY_FILE"

# Identical env-var contract to pfsense_mcp.tier1_anchor_check -- one
# witness daemon connection, shared by the read-only startup check and
# this module's enabled write runtime. Not imported from there (see
# module docstring); the values must still match exactly for a deployment
# that configures both.
_WITNESS_BASE_URL_VAR = "PFSENSE_TIER1_WITNESS_BASE_URL"
_WITNESS_CLIENT_CERT_VAR = "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE"
_WITNESS_CLIENT_KEY_VAR = "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE"
_WITNESS_SERVER_CA_VAR = "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE"

# W3 Slice 3 (ADR-028 W3-D1): exactly three fixed, non-caller-selectable
# single files -- matching lab/reconciliation_authority.py's own accepted
# pattern exactly, never a directory to scan.
_AUTHORIZATION_INBOX_FILE_VAR = "PFSENSE_TIER1_AUTHORIZATION_INBOX_FILE"
_CONFIRMATION_PENDING_FILE_VAR = "PFSENSE_TIER1_CONFIRMATION_PENDING_FILE"
_CONFIRMATION_SIGNED_FILE_VAR = "PFSENSE_TIER1_CONFIRMATION_SIGNED_FILE"

# A fixed, non-configurable identifier -- mirrors production_store.py's own
# PRODUCTION_STORE_ID exactly. Not sourced from env: there is exactly one
# consumption store for exactly one production deployment of this one
# semantic unit.
CONSUMPTION_STORE_ID = "tier1-production-alias-description-consumption"

_AUTHORITY_FILE_MAX_BYTES = 4096
_PUBLIC_KEY_HEX = re.compile(r"[0-9a-f]{64}")

_REQUIRED_VARS = (
    "PFSENSE_TIER1_STORE_PATH",
    "PFSENSE_TIER1_STORE_KEY_FILE",
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
    _AUTHORIZATION_INBOX_FILE_VAR,
    _CONFIRMATION_PENDING_FILE_VAR,
    _CONFIRMATION_SIGNED_FILE_VAR,
)


class ProductOutcomeState(str, Enum):
    """ADR-028's five product-facing states -- an intentionally coarse
    projection of the richer internal `RecoveryContract`/`MutationExecutor`
    state machine, never a 1:1 rename of every internal state (owner
    decision, 2026-08-15). Mapping principle, applied uniformly by
    `_project_recovery_state()` below: `VERIFIED` and `RECONCILIATION`
    project to their own like-named states; every other internal outcome
    (`FAILED`, `ROLLING_BACK`, `ROLLED_BACK`, `ROLLBACK_FAILED`, and any
    fail-closed denial before a contract exists) projects to the uniform
    `REFUSED` -- it never reveals which specific internal state or gate
    produced it. No `RecoveryState` is added, removed, or reinterpreted to
    make this mapping neater; the durable internal record is never hidden,
    only additionally projected."""

    REQUESTED = "requested"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    VERIFIED = "verified"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    REFUSED = "refused"


@dataclass(frozen=True)
class ProductOutcome:
    """The W3 Slice 3 composed operation's return value. `contract_id` is
    populated whenever a durable `RecoveryContract` exists for this
    request (including on `REFUSED`, if refusal happened after the
    contract was created) -- exposing an opaque identifier is not itself
    "which gate refused" detail; it is `None` only for `REQUESTED` and for
    a `REFUSED` that occurred before any contract could exist."""

    state: ProductOutcomeState
    contract_id: str | None = None


def _project_recovery_state(state: RecoveryState) -> ProductOutcomeState:
    if state is RecoveryState.VERIFIED:
        return ProductOutcomeState.VERIFIED
    if state is RecoveryState.RECONCILIATION:
        return ProductOutcomeState.RECONCILIATION_REQUIRED
    return ProductOutcomeState.REFUSED


def _artifact_present(path: Path) -> bool:
    """`lexists`-equivalent presence check: a broken symlink (target
    missing) still counts as "something is here" -- it must be refused by
    the existing secure-file discipline when read, never silently treated
    as REQUESTED/AWAITING_CONFIRMATION's "nothing here yet" case (ADR-028:
    "never silently treated as absent")."""

    return path.is_symlink() or path.exists()


class ProductionAliasDescriptionRuntime:
    """The complete, fixed, environment-derived W2/W3 runtime. Exposes
    the W1 execution core (`authorize_and_create`/`confirm_and_handoff`/
    `resume_prepared`), manual signed reconciliation resolution, and the
    single composed W3 Slice 3 product operation
    (`request_alias_description_change`) -- nothing else. Holding this
    object gives no direct access to the underlying store, executor,
    write client, artifact-exchange paths, or any other lower-level
    primitive; every other composed component is a private implementation
    detail of construction, never a public attribute a caller could
    substitute or bypass through."""

    __slots__ = (
        "_artifact_integrity_key",
        "_authorization_inbox_file",
        "_confirmation_authority_id",
        "_confirmation_pending_file",
        "_confirmation_signed_file",
        "_preparer",
        "_store",
        "execution_core",
    )

    def __init__(
        self,
        *,
        execution_core: AliasDescriptionExecutionCoreV1,
        store: SqliteRecoveryContractStore,
        preparer: AliasDescriptionPreparerV1,
        authorization_inbox_file: Path,
        confirmation_pending_file: Path,
        confirmation_signed_file: Path,
        confirmation_authority_id: str,
        artifact_integrity_key: bytes,
    ) -> None:
        self.execution_core = execution_core
        self._store = store
        self._preparer = preparer
        self._authorization_inbox_file = authorization_inbox_file
        self._confirmation_pending_file = confirmation_pending_file
        self._confirmation_signed_file = confirmation_signed_file
        self._confirmation_authority_id = confirmation_authority_id
        self._artifact_integrity_key = artifact_integrity_key

    def resolve_reconciliation(self, contract_id: str, *, evidence: ReconciliationEvidence) -> RecoveryContract:
        """Forwards to the store's own, already-hardened
        `resolve_reconciliation()` -- unchanged, not reimplemented. Fails
        closed exactly as that method already does: wrong/unsigned
        evidence, an evidence/contract-state mismatch, or a missing
        reconciliation verifier all raise before any state changes."""

        return self._store.resolve_reconciliation(contract_id, evidence=evidence)

    def request_alias_description_change(
        self,
        request: AliasDescriptionChangeV1,
        *,
        requested_plan_digest: str,
        requested_step_id: str,
        target_capability_posture: CapabilityPosture,
        target_anchor_assurance: AnchorAssurance,
        now: datetime,
        freshness_env: dict[str, str] | None = None,
    ) -> ProductOutcome:
        """The single W3 Slice 3 composed operation (ADR-028). Not yet
        MCP-exposed -- no tool, endpoint, or product registration calls
        this method anywhere in this repository.

        Re-invocation/deduplication (ADR-028): a fresh, authoritative
        preparation of `request` is always performed first (needed to
        derive the exact idempotency key either way), then the store's own
        durable `PREPARED` state -- never a new persistent store or
        identity concept -- decides the path: an existing contract not
        already `PREPARED` (already completed or in flight through the
        existing, unmodified executor/reconciliation machinery) is
        projected via `_project_recovery_state()` and never re-authorized
        or re-confirmed by this method; an existing `PREPARED` contract is
        resumed via Slice 3A's `resume_prepared()`; only when no contract
        exists at all is a fresh `authorize_and_create()` attempted, and
        only after finding a signed authorization artifact -- no artifact
        present is `REQUESTED`, with zero consumption and zero contract
        creation, never an error.

        Confirmation delivery: the fixed, non-caller-selectable
        confirmation-pending outbox is populated (idempotently -- never
        overwriting an existing artifact) once a `PREPARED` contract
        exists either way, then the fixed confirmation-signed inbox is
        checked; absent is `AWAITING_CONFIRMATION` (including the
        pre-positioned case, where a signed confirmation was already
        waiting before the contract even existed -- ADR-028's accepted
        special case of the same mechanism); present-and-invalid is
        `REFUSED`; present-and-valid proceeds through the existing,
        unmodified `confirm_and_handoff()` exactly once, and its resulting
        `RecoveryState` is projected via `_project_recovery_state()`.

        Every fail-closed denial along the way -- preparer failure,
        malformed/unsafe/stale/mismatched/wrong-authority authorization or
        confirmation artifact, any `BoundExecutionError` from the
        unmodified W1 core -- returns the uniform `ProductOutcome(REFUSED,
        ...)`, never leaking which specific check failed."""

        try:
            authorized_preparation = self._preparer.prepare(request)
            idempotency_key = self.execution_core.compute_idempotency_key(authorized_preparation)
            existing = self._store.find_by_idempotency_key(idempotency_key)
        except Exception:
            return ProductOutcome(ProductOutcomeState.REFUSED)

        if existing is not None and existing.state is not RecoveryState.PREPARED:
            return ProductOutcome(_project_recovery_state(existing.state), contract_id=existing.contract_id)

        if existing is not None:
            try:
                handle = self.execution_core.resume_prepared(existing.contract_id, request=request, now=now)
            except BoundExecutionError:
                return ProductOutcome(ProductOutcomeState.REFUSED, contract_id=existing.contract_id)
            contract = existing
        else:
            if not _artifact_present(self._authorization_inbox_file):
                return ProductOutcome(ProductOutcomeState.REQUESTED)
            try:
                authorization = load_signed_plan_authorization_v2(self._authorization_inbox_file)
            except ArtifactExchangeError:
                return ProductOutcome(ProductOutcomeState.REFUSED)
            try:
                handle = self.execution_core.authorize_and_create(
                    request,
                    authorized_preparation=authorized_preparation,
                    authorization=authorization,
                    requested_plan_digest=requested_plan_digest,
                    requested_step_id=requested_step_id,
                    target_capability_posture=target_capability_posture,
                    target_anchor_assurance=target_anchor_assurance,
                    now=now,
                    freshness_env=freshness_env,
                )
            except BoundExecutionError:
                return ProductOutcome(ProductOutcomeState.REFUSED)
            try:
                contract = self._store.load(handle.contract_id)
            except Exception:
                # The contract was already durably created by
                # authorize_and_create() above; a failure reading it back
                # here only prevents emitting the pending-confirmation
                # artifact this round -- it must never be reported as a
                # refusal of an operation that already succeeded up to
                # this point. A later re-invocation finds it via the
                # dedup path above and retries emission.
                return ProductOutcome(ProductOutcomeState.AWAITING_CONFIRMATION, contract_id=handle.contract_id)

        self._ensure_pending_confirmation_request(contract)

        if not _artifact_present(self._confirmation_signed_file):
            return ProductOutcome(ProductOutcomeState.AWAITING_CONFIRMATION, contract_id=handle.contract_id)
        try:
            confirmation = load_signed_confirmation_evidence(self._confirmation_signed_file)
        except ArtifactExchangeError:
            return ProductOutcome(ProductOutcomeState.REFUSED, contract_id=handle.contract_id)
        try:
            outcome = self.execution_core.confirm_and_handoff(handle, confirmation=confirmation, now=now)
        except BoundExecutionError:
            return ProductOutcome(ProductOutcomeState.REFUSED, contract_id=handle.contract_id)
        return ProductOutcome(_project_recovery_state(outcome.state), contract_id=handle.contract_id)

    def _ensure_pending_confirmation_request(self, contract: RecoveryContract) -> None:
        """Idempotent, fail-closed emission: never overwrites an existing
        pending-confirmation artifact (ADR-028: leftover/conflicting
        artifacts are never auto-deleted or overwritten -- cleanup is an
        explicit operator action). A write failure (a stale, unrelated
        artifact already occupying the fixed path) never affects the
        already-durable `PREPARED` contract; it only means this round
        does not (re-)emit a fresh pending request."""

        if _artifact_present(self._confirmation_pending_file):
            return
        pending = pending_confirmation_request_from_contract(
            contract, expected_authority_id=self._confirmation_authority_id
        )
        with contextlib.suppress(ArtifactExchangeError):
            write_secure_new(
                self._confirmation_pending_file,
                pending_confirmation_request_to_bytes(pending, integrity_key=self._artifact_integrity_key),
            )


def _missing_required_vars(source: dict[str, str] | os._Environ[str]) -> list[str]:
    return [name for name in _REQUIRED_VARS if not source.get(name)]


def _load_pinned_authority(path: Path) -> PinnedAuthority:
    """Loads exactly one Ed25519 *public* key, never a private one -- the
    file shape mirrors `key_lifecycle.load_key_material()`'s own
    self-describing JSON convention
    (`{"authority_id": "...", "public_key_hex": "<64 lowercase hex>"}`),
    read through the same O_NOFOLLOW-validated descriptor discipline.
    `PinnedAuthority.__post_init__` performs the actual domain validation
    (authority-id shape, exact 32-byte key length); this function only
    validates file shape/encoding before construction and wraps any
    failure -- including a domain-validation failure -- uniformly as
    `Tier1ConfigurationError`, never leaking the original message."""

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
    """The confirmed-working mTLS recipe from `witness_daemon/README.md`'s
    "Connecting from the guest" section, applied verbatim -- identical to
    `pfsense_mcp.tier1_anchor_check._build_witness_anchor()`, an explicit
    `ssl.SSLContext`, never the `cert=`/`verify=<path>` shorthand found
    unreliable on `httpx>=0.28` during real-hardware verification."""

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


def build_production_runtime(env: dict[str, str] | None = None) -> ProductionAliasDescriptionRuntime | None:
    """The sole public entry point. Returns `None` if none of this
    module's required environment variables are set (the safe, default,
    disabled state). Raises `Tier1ConfigurationError`/`Tier1Error` for
    any partial configuration or any failure to construct a fully valid,
    fully anchored runtime -- never returns a partially-constructed or
    anchor-less runtime. Every call performs a full, fresh construction;
    nothing is cached across calls, matching the "no persisted
    process-local transport/client/request state" restart requirement."""

    source = env if env is not None else os.environ
    missing = _missing_required_vars(source)
    if len(missing) == len(_REQUIRED_VARS):
        return None
    if missing:
        raise Tier1ConfigurationError(
            f"Production WRITE runtime configuration is partial; missing: {', '.join(sorted(missing))}"
        )

    store_config = load_production_store_config(env)
    if store_config is None:  # pragma: no cover - guarded by the all-or-nothing check above
        raise Tier1ConfigurationError("Production WRITE runtime requires the Tier 1 store to be configured.")

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
            "Anti-rollback anchor is not fully provisioned for this store; production WRITE runtime refused."
        )
    witness_config = _load_witness_client_config(source)
    anchor = _build_witness_anchor(witness_config)

    # W3 Slice 3 (ADR-028 W3-D1): three fixed, non-caller-selectable
    # single artifact-exchange files, all-or-nothing with every other
    # required var above (see _REQUIRED_VARS).
    authorization_inbox_file = _require_absolute_path(
        source[_AUTHORIZATION_INBOX_FILE_VAR], _AUTHORIZATION_INBOX_FILE_VAR
    )
    confirmation_pending_file = _require_absolute_path(
        source[_CONFIRMATION_PENDING_FILE_VAR], _CONFIRMATION_PENDING_FILE_VAR
    )
    confirmation_signed_file = _require_absolute_path(
        source[_CONFIRMATION_SIGNED_FILE_VAR], _CONFIRMATION_SIGNED_FILE_VAR
    )

    store = open_production_store(
        store_config,
        confirmation_verifier=confirmation_verifier,
        reconciliation_verifier=reconciliation_verifier,
        anti_rollback_anchor=anchor,
    )
    # The same integrity-only key material protects both the consumption
    # store's own rows and the pending-confirmation-request artifact's
    # MAC: both are local-tamper-detection-only, same trust boundary
    # (this production process/host), never an authorization or
    # confirmation authority in themselves -- a second, dedicated key
    # would add required-configuration surface without a corresponding
    # security separation need.
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
    preparer = AliasDescriptionPreparerV1(read_client=read_client, configured_target=appliance_target)
    policy = MutationPolicy(frozenset({MutationRule(Capability.ALIAS_WRITE, ENDPOINT_SYMBOL, HTTP_METHOD)}))
    executor = MutationExecutor(
        store=store,
        write_client=write_client,
        read_client=read_client,
        policy=policy,
        anti_rollback_anchor=anchor,
        encryption_key=encryption_key_record.material,
    )
    execution_core = AliasDescriptionExecutionCoreV1(
        preparer=preparer,
        authorities=authorization_authorities,
        consumption_store=consumption_store,
        contract_store=store,
        executor=executor,
        encryption_key=encryption_key_record,
        nonce_counter=nonce_counter,
    )
    return ProductionAliasDescriptionRuntime(
        execution_core=execution_core,
        store=store,
        preparer=preparer,
        authorization_inbox_file=authorization_inbox_file,
        confirmation_pending_file=confirmation_pending_file,
        confirmation_signed_file=confirmation_signed_file,
        confirmation_authority_id=confirmation_authority.authority_id,
        artifact_integrity_key=consumption_integrity_key,
    )


__all__ = [
    "ADAPTER_VERSION",
    "CONSUMPTION_STORE_ID",
    "ProductOutcome",
    "ProductOutcomeState",
    "ProductionAliasDescriptionRuntime",
    "ProductionStoreConfig",
    "build_production_runtime",
]
