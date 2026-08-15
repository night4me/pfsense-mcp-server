"""ADR-021 Phase B: read-only security-posture discovery.

This is the SECOND, narrow, explicit exception to `pfsense_mcp.tier1`
never being imported from outside its own package -- exempted by name,
alongside `tier1_anchor_check.py`, in `tests/tier1/test_isolation.py::
test_tier1_is_not_imported_outside_its_inert_package`. `security_cli.py`
itself does not import `pfsense_mcp.tier1` at all; it only ever calls
the public functions in this file, keeping this exemption's surface to
exactly this one additional file, matching the discipline
`docs/SECURITY_POSTURE_PROVISIONING.md`'s "Affected code areas" table
already anticipated.

Implements exactly `ADR-021`'s Phase B (`docs/SECURITY_POSTURE_PROVISIONING.md`,
"Phased implementation plan"): `DISCOVERED` and, where evidence allows,
`PREREQUISITES_VERIFIED`-level detail for both accepted axes,
independently:

  - capability posture (`read_only` / `write_protected`) --
    `ADR-004`'s capability-profile mechanism plus the WRITE
    allow-list/capability state. Resolves the actually-configured profile
    via `profiles.get_profile()` and reads *its own* `.capabilities` for
    `*_WRITE` membership (W3 Slice 4: a static union across
    `AuditorProfile`/`EngineerProfile` alone stopped being an accurate
    proxy once a real, selectable profile started granting a `*_WRITE`
    capability), combined with `WriteEndpoints.active_entries()` --
    neither `Capability`/`profiles.get_profile()`/`WriteEndpoints` are
    `pfsense_mcp.tier1` imports.
  - anchor assurance (`none` / `software` / `hardware_witness`) --
    reuses `load_production_store_config()` (the same config loader
    `tier1_anchor_check.py` uses) and
    `read_only_anchor_provisioning_status()`
    (`pfsense_mcp.tier1.production_store`) for the store side, and
    `TpmHostWitnessAnchor.read()` for the live side -- never their
    mutating counterparts.

This module never calls `provision_anchor_baseline()`,
`TpmHostWitnessAnchor.advance()`, any `RecoveryContract`/
`MutationExecutor`/`WriteApiClient` construction, or anything that
writes to the production store, the TPM, or pfSense. Every function
here returns a value; nothing here logs, prints, or has any other
side effect -- `security_cli.py` owns all output formatting.

**Store access is genuinely read-only, not merely disciplined.** This
module never constructs `SqliteRecoveryContractStore` (whose
`__init__` always runs `_initialize_schema()` --
`CREATE TABLE IF NOT EXISTS ...` -- even against an existing,
untouched file; harmless for a healthy store, but a real
repair-as-a-side-effect against a legacy/partial/foreign SQLite file
missing one or more expected tables). It calls
`read_only_anchor_provisioning_status()` instead, which opens the
store via SQLite's own `mode=ro` URI -- the database engine itself
refuses any DDL/DML attempt, a structural guarantee independent of
this module's own code. It also never calls that function (or
anything else) against a store path that has not already been created
on disk -- mirroring `scripts/tier1_store_bootstrap.py`'s own
existence check exactly, so discovery can never provision or create
anything by the mere act of looking, on top of the read-only
connection guarantee.
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass, field
from enum import Enum

import httpx

from .capabilities import Capability
from .errors import ConfigurationError
from .profiles import get_profile
from .tier1.anti_rollback import AnchorProvisioningStatus
from .tier1.anti_rollback_tpm_witness import TpmHostWitnessAnchor
from .tier1.errors import AnchorUnavailableError, Tier1ConfigurationError, Tier1Error
from .tier1.production_store import load_production_store_config, read_only_anchor_provisioning_status
from .write_endpoints import WriteEndpoints

_WRITE_CAPABILITIES = tuple(member for member in Capability if member.name.endswith("_WRITE"))

_WITNESS_BASE_URL_VAR = "PFSENSE_TIER1_WITNESS_BASE_URL"
_WITNESS_CLIENT_CERT_VAR = "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE"
_WITNESS_CLIENT_KEY_VAR = "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE"
_WITNESS_SERVER_CA_VAR = "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE"


class CapabilityPosture(str, Enum):
    """The accepted `ADR-021` capability-posture axis. Deliberately only
    these two values -- never collapsed with anchor assurance into a
    three-level ladder (`ADR-021`'s own rejected Model A)."""

    READ_ONLY = "read_only"
    WRITE_PROTECTED = "write_protected"


class AnchorAssurance(str, Enum):
    """The accepted `ADR-021` anchor-assurance axis. `SOFTWARE` is a
    real value in the model but is never resolved by this module today --
    `docs/SECURITY_POSTURE_PROVISIONING.md` records that no
    remote-witness backend exists anywhere in this repository yet
    (Phase G, unimplemented); reporting it here would assert a
    capability that cannot currently be verified."""

    NONE = "none"
    SOFTWARE = "software"
    HARDWARE_WITNESS = "hardware_witness"
    UNKNOWN = "unknown"


class AnchorEvidenceState(str, Enum):
    """Finer-grained evidence trail behind `AnchorAssurance`'s coarse
    value -- required so discovery can distinguish "nothing configured"
    from "configured but not provisioned" from "provisioned but the
    live witness could not be verified", per `ADR-021` Phase B's own
    "do not infer ACTIVE merely because files or configuration exist"
    requirement."""

    UNCONFIGURED = "unconfigured"
    CONFIGURATION_INVALID = "configuration_invalid"
    CONFIGURED_NOT_CREATED = "configured_not_created"
    STORE_ERROR = "store_error"
    CONFIGURED_UNPROVISIONED = "configured_unprovisioned"
    PROVISIONED_UNVERIFIED = "provisioned_unverified"
    PROVISIONED_UNREACHABLE = "provisioned_unreachable"
    PROVISIONED_VERIFIED = "provisioned_verified"
    PROVISIONED_MISMATCH = "provisioned_mismatch"


@dataclass(frozen=True)
class CapabilityPostureDiscovery:
    value: CapabilityPosture
    configured_profile_name: str
    configured_profile_valid: bool
    write_capabilities_active: int
    write_capabilities_total: int
    allow_list_entries: tuple[str, ...]
    evidence: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class AnchorAssuranceDiscovery:
    value: AnchorAssurance
    evidence_state: AnchorEvidenceState
    store_configured: bool
    store_exists: bool | None
    seeded: bool | None
    complete: bool | None
    handle: str | None
    baseline: int | None
    provisioned_at: str | None
    witness_configured: bool
    witness_reachable: bool | None
    witness_value: int | None
    witness_matches_baseline: bool | None
    evidence: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SecurityPostureDiscovery:
    capability_posture: CapabilityPostureDiscovery
    anchor_assurance: AnchorAssuranceDiscovery


def discover_capability_posture(env: dict[str, str] | None = None) -> CapabilityPostureDiscovery:
    """Read-only. Never constructs a `WriteApiClient`, never touches
    pfSense, never imports `pfsense_mcp.tier1` (this axis has nothing to
    do with the anchor)."""

    source = env if env is not None else os.environ
    configured_profile_name = source.get("PFSENSE_PROFILE", "auditor").strip().lower()

    evidence: list[str] = []
    configured_profile_valid = True
    try:
        get_profile(configured_profile_name)
    except ConfigurationError:
        configured_profile_valid = False
        evidence.append(
            f"PFSENSE_PROFILE={configured_profile_name!r} is not a recognized profile name; "
            "the server itself would fail closed at startup with this configuration."
        )

    # Evidence source: the ACTUALLY CONFIGURED profile's own granted
    # capabilities -- not a static union across every known profile.
    # Before W3 Slice 4, AuditorProfile/EngineerProfile alone (neither of
    # which ever grants a *_WRITE capability) made a static OR-across-
    # fixed-profiles check an accurate-enough proxy in practice; that
    # stopped being true the moment a real, selectable profile
    # (WriteProtectedProfile, W3 Slice 1) started granting one, and
    # `WriteEndpoints.active_entries()` stopped being an always-empty
    # signal (W3 Slice 4) -- a static, profile-independent OR-check would
    # now report write_protected for every deployment, including the
    # unconfigured default. Resolving `configured_profile_name` through
    # `get_profile()` and reading *its own* `.capabilities` answers the
    # actually meaningful question: does the profile this deployment has
    # actually selected grant a *_WRITE capability right now.
    if configured_profile_valid:
        resolved_profile_capabilities = get_profile(configured_profile_name).capabilities
    else:
        resolved_profile_capabilities = frozenset()
    active_write_capabilities = [member for member in _WRITE_CAPABILITIES if member in resolved_profile_capabilities]
    allow_list_entries = tuple(WriteEndpoints.active_entries())

    # Both must hold for WRITE to be evidence-backed: a granting profile
    # with no allow-listed endpoint, or an allow-listed endpoint under a
    # non-granting profile, each leave WRITE structurally unreachable
    # (mirrors two of ADR-028's own three activation-gate conditions;
    # this read-only discovery function does not attempt the third --
    # constructing the full production runtime -- itself).
    if active_write_capabilities and allow_list_entries:
        value = CapabilityPosture.WRITE_PROTECTED
        evidence.append(
            f"{len(active_write_capabilities)} of {len(_WRITE_CAPABILITIES)} *_WRITE capabilities granted by the "
            f"configured profile ({configured_profile_name!r}) and {len(allow_list_entries)} WriteEndpoints "
            "entrie(s) found -- resolved write_protected from evidence."
        )
    else:
        value = CapabilityPosture.READ_ONLY
        if configured_profile_valid and configured_profile_name == "engineer":
            evidence.append(
                "PFSENSE_PROFILE is configured as 'engineer', but the configured profile grants 0 WRITE "
                "capabilities -- resolved posture is still read_only from evidence, not the configured profile "
                "name alone."
            )
        elif allow_list_entries and not active_write_capabilities:
            evidence.append(
                f"PFSENSE_PROFILE={configured_profile_name!r} grants 0 WRITE capabilities even though "
                f"{len(allow_list_entries)} WriteEndpoints entrie(s) exist -- resolved posture is read_only "
                "from evidence; the allow-list alone never grants anything."
            )
        elif active_write_capabilities and not allow_list_entries:
            evidence.append(
                f"PFSENSE_PROFILE={configured_profile_name!r} grants {len(active_write_capabilities)} *_WRITE "
                "capabilities, but the WriteEndpoints allow-list is empty -- resolved posture is read_only from "
                "evidence; a granting profile alone never reaches an endpoint that is not allow-listed."
            )
        else:
            evidence.append(f"PFSENSE_PROFILE={configured_profile_name!r}, 0 WRITE capabilities active. ")

    return CapabilityPostureDiscovery(
        value=value,
        configured_profile_name=configured_profile_name,
        configured_profile_valid=configured_profile_valid,
        write_capabilities_active=len(active_write_capabilities),
        write_capabilities_total=len(_WRITE_CAPABILITIES),
        allow_list_entries=allow_list_entries,
        evidence=tuple(evidence),
    )


@dataclass(frozen=True)
class _WitnessClientConfig:
    base_url: str
    client_cert_file: str
    client_key_file: str
    server_ca_file: str


def _load_witness_client_config(env: dict[str, str] | None = None) -> _WitnessClientConfig | None:
    """Deliberately mirrors `tier1_anchor_check.py`'s own private
    `_load_witness_client_config`/`WitnessClientConfig` exactly (same
    four env vars, same all-or-nothing validation, same distinction
    between "not configured" (`None`, silent) and "partially configured"
    (raises -- a likely operator typo, worth surfacing as its own
    evidence, not silently collapsed into "not configured") rather than
    importing a private name across module boundaries. Kept
    intentionally small (env-var reads plus one https:// scheme check)
    -- the actual security-relevant logic (mTLS `SSLContext`
    construction, the wire protocol) is not duplicated; it is reused
    directly from
    `pfsense_mcp.tier1.anti_rollback_tpm_witness.TpmHostWitnessAnchor`
    below."""

    source = env if env is not None else os.environ
    base_url = source.get(_WITNESS_BASE_URL_VAR)
    client_cert = source.get(_WITNESS_CLIENT_CERT_VAR)
    client_key = source.get(_WITNESS_CLIENT_KEY_VAR)
    server_ca = source.get(_WITNESS_SERVER_CA_VAR)

    if not base_url and not client_cert and not client_key and not server_ca:
        return None
    if not base_url or not client_cert or not client_key or not server_ca:
        missing = [
            name
            for name, value in (
                (_WITNESS_BASE_URL_VAR, base_url),
                (_WITNESS_CLIENT_CERT_VAR, client_cert),
                (_WITNESS_CLIENT_KEY_VAR, client_key),
                (_WITNESS_SERVER_CA_VAR, server_ca),
            )
            if not value
        ]
        raise Tier1Error(f"Witness client configuration is partial; missing: {', '.join(missing)}")
    if not base_url.startswith("https://"):
        raise Tier1Error(f"{_WITNESS_BASE_URL_VAR} must use https.")

    return _WitnessClientConfig(
        base_url=base_url, client_cert_file=client_cert, client_key_file=client_key, server_ca_file=server_ca
    )


def _build_read_only_witness_client(config: _WitnessClientConfig) -> TpmHostWitnessAnchor:
    """The confirmed-working mTLS recipe (`witness_daemon/README.md`'s
    "Connecting from the guest" section) -- an explicit `ssl.SSLContext`,
    matching `tier1_anchor_check.py`'s own `_build_witness_anchor`. The
    returned `TpmHostWitnessAnchor` exposes both `read()` and
    `advance()`; this module's own discipline (never call `.advance()`)
    is enforced by never calling it anywhere in this file, verified
    structurally by `tests/test_security_discovery_isolation.py`."""

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(cafile=config.server_ca_file)
    ssl_context.load_cert_chain(certfile=config.client_cert_file, keyfile=config.client_key_file)
    client = httpx.Client(verify=ssl_context, trust_env=False, timeout=10.0)
    return TpmHostWitnessAnchor(client=client, base_url=config.base_url)


def _anchor_result(
    *,
    value: AnchorAssurance,
    evidence_state: AnchorEvidenceState,
    evidence: tuple[str, ...],
    store_configured: bool = True,
    store_exists: bool | None = None,
    status: AnchorProvisioningStatus | None = None,
    witness_configured: bool = False,
    witness_reachable: bool | None = None,
    witness_value: int | None = None,
    witness_matches_baseline: bool | None = None,
) -> AnchorAssuranceDiscovery:
    """The single place every `AnchorAssuranceDiscovery` is built.
    Collapses what were eight near-identical ~13-field dataclass
    constructions in `discover_anchor_assurance()` into one call each,
    differing only in what actually differs -- both a readability win
    and a correctness one (a future new branch cannot forget to set a
    field the others already set correctly). `status` is `None` exactly
    when the store has not been successfully opened and read yet
    (unconfigured/invalid/not-created/error); once known (`status` set),
    `store_exists` is always `True` and every downstream branch shares
    the same five status-derived fields. `store_exists` may also be set
    explicitly and independently of `status` -- the one case that needs
    this is `CONFIGURED_NOT_CREATED`, where the store is known *not* to
    exist (`False`), not merely unknown (`None`)."""

    return AnchorAssuranceDiscovery(
        value=value,
        evidence_state=evidence_state,
        store_configured=store_configured,
        store_exists=True if status is not None else store_exists,
        seeded=None if status is None else status.seeded,
        complete=None if status is None else status.complete,
        handle=None if status is None else status.handle,
        baseline=None if status is None else status.baseline,
        provisioned_at=None if status is None else status.provisioned_at,
        witness_configured=witness_configured,
        witness_reachable=witness_reachable,
        witness_value=witness_value,
        witness_matches_baseline=witness_matches_baseline,
        evidence=evidence,
    )


def discover_anchor_assurance(env: dict[str, str] | None = None) -> AnchorAssuranceDiscovery:
    """Read-only. Never calls `provision_anchor_baseline()` or
    `TpmHostWitnessAnchor.advance()`. Never calls
    `read_only_anchor_provisioning_status()` against a path that does
    not yet exist -- mirrors `scripts/tier1_store_bootstrap.py`'s own
    existence check exactly. `read_only_anchor_provisioning_status()`
    itself opens the store via SQLite's `mode=ro` URI, so even a
    legacy/partial/foreign store file missing expected tables cannot
    have its schema created or repaired as a side effect of being
    read -- the database engine refuses any write attempt structurally
    (see that function's own docstring in
    `pfsense_mcp.tier1.production_store`).

    Evidence strings deliberately never embed a raw configured path,
    URL, or third-party exception message verbatim -- only exception
    *class names* and values this module itself already treats as
    non-sensitive (the TPM handle, the counter values, timestamps).
    Some `Tier1Error`/`OSError`/`ssl.SSLError` messages from lower
    layers do embed absolute filesystem paths (e.g.
    `ContractValidationError`'s own text, or a failed
    `ssl.SSLContext.load_cert_chain()`); reusing those `str(exc)`
    verbatim here would leak configured paths into discovery evidence
    (and therefore into `--json` output meant for logging/automation),
    which is more disclosure than a "what state is this in" report
    needs."""

    try:
        store_config = load_production_store_config(env)
    except Tier1ConfigurationError:
        return _anchor_result(
            value=AnchorAssurance.UNKNOWN,
            evidence_state=AnchorEvidenceState.CONFIGURATION_INVALID,
            evidence=("Tier 1 store configuration is invalid (see PFSENSE_TIER1_STORE_PATH/_KEY_FILE).",),
        )

    if store_config is None:
        return _anchor_result(
            value=AnchorAssurance.NONE,
            evidence_state=AnchorEvidenceState.UNCONFIGURED,
            store_configured=False,
            evidence=("PFSENSE_TIER1_STORE_PATH/PFSENSE_TIER1_STORE_KEY_FILE unset -- Tier 1 is inert.",),
        )

    # Never open a store that has never been created -- even the
    # read-only mode=ro connection below requires an existing file
    # (SQLite's own mode=ro refuses to create one), but checking here
    # keeps the "not provisioned" evidence accurate and avoids a
    # sqlite3 error path for the common, expected case.
    if not store_config.store_path.exists():
        return _anchor_result(
            value=AnchorAssurance.NONE,
            evidence_state=AnchorEvidenceState.CONFIGURED_NOT_CREATED,
            store_exists=False,
            evidence=(
                "Store is configured but the file does not exist yet -- not provisioned. Not opened "
                "(opening a nonexistent store would create it).",
            ),
        )

    try:
        status = read_only_anchor_provisioning_status(store_config)
    except Tier1Error as exc:
        return _anchor_result(
            value=AnchorAssurance.UNKNOWN,
            evidence_state=AnchorEvidenceState.STORE_ERROR,
            evidence=(
                f"Store exists but could not be opened or read read-only ({type(exc).__name__}) -- "
                "possible integrity/authentication failure, or a missing/incomplete schema. "
                "Never repaired or created as a side effect of this check.",
            ),
        )

    if not status.seeded or not status.complete:
        return _anchor_result(
            value=AnchorAssurance.NONE,
            evidence_state=AnchorEvidenceState.CONFIGURED_UNPROVISIONED,
            status=status,
            evidence=(
                f"Store exists but is not fully provisioned (seeded={status.seeded}, complete={status.complete}).",
            ),
        )

    # Store-side evidence proves *something* was provisioned. Only the
    # TPM-backed backend has ever been implemented in this repository
    # (docs/SECURITY_POSTURE_PROVISIONING.md's own "software... not yet
    # designed" note) -- so store evidence alone already justifies
    # HARDWARE_WITNESS, independent of whether live verification below
    # succeeds.
    provisioning_evidence = (
        f"Store provisioning record: handle={status.handle} baseline={status.baseline} "
        f"provisioned_at={status.provisioned_at}."
    )

    try:
        witness_config = _load_witness_client_config(env)
    except Tier1Error as exc:
        # Partial/invalid config is distinct evidence from "not
        # configured at all" -- likely an operator typo, worth
        # surfacing, not silently collapsed into the clean case. Only
        # the exception's class name is reported -- its own message
        # would otherwise be the one place a misconfigured witness
        # base_url could leak verbatim into evidence.
        return _anchor_result(
            value=AnchorAssurance.HARDWARE_WITNESS,
            evidence_state=AnchorEvidenceState.PROVISIONED_UNVERIFIED,
            status=status,
            evidence=(
                provisioning_evidence,
                f"Witness client configuration is invalid ({type(exc).__name__}) -- live verification skipped.",
            ),
        )

    if witness_config is None:
        return _anchor_result(
            value=AnchorAssurance.HARDWARE_WITNESS,
            evidence_state=AnchorEvidenceState.PROVISIONED_UNVERIFIED,
            status=status,
            evidence=(provisioning_evidence, "Witness client not configured -- live verification skipped."),
        )

    try:
        anchor = _build_read_only_witness_client(witness_config)
        current_value = anchor.read()
    except (OSError, ssl.SSLError, AnchorUnavailableError, Tier1Error) as exc:
        return _anchor_result(
            value=AnchorAssurance.HARDWARE_WITNESS,
            evidence_state=AnchorEvidenceState.PROVISIONED_UNREACHABLE,
            status=status,
            witness_configured=True,
            witness_reachable=False,
            evidence=(
                provisioning_evidence,
                f"Witness client configured but the live witness could not be read ({type(exc).__name__}). "
                "Store-side evidence still indicates hardware_witness was provisioned.",
            ),
        )

    matches = current_value == status.baseline
    verified_state = AnchorEvidenceState.PROVISIONED_VERIFIED if matches else AnchorEvidenceState.PROVISIONED_MISMATCH
    match_evidence = (
        f"Witness value ({current_value}) matches persisted high-water mark ({status.baseline})."
        if matches
        else (
            f"Witness value ({current_value}) does NOT match persisted high-water mark "
            f"({status.baseline}) -- security-relevant anomaly, reported not resolved. Discovery "
            "never performs reconciliation."
        )
    )
    return _anchor_result(
        value=AnchorAssurance.HARDWARE_WITNESS,
        evidence_state=verified_state,
        status=status,
        witness_configured=True,
        witness_reachable=True,
        witness_value=current_value,
        witness_matches_baseline=matches,
        evidence=(provisioning_evidence, match_evidence),
    )


def discover_security_posture(env: dict[str, str] | None = None) -> SecurityPostureDiscovery:
    """The one function `security_cli.py` calls. Composes both
    independent axis-discovery functions above; performs no additional
    logic and no I/O of its own."""

    return SecurityPostureDiscovery(
        capability_posture=discover_capability_posture(env),
        anchor_assurance=discover_anchor_assurance(env),
    )
