"""ADR-021/022 amendment (2026-09-05): off-runtime anchor-assurance
discovery from a signed `AnchorEvidenceExport`, for an isolated verifier
(a signer) that must never open, import, or hold keys for the runtime
`RecoveryContract` SQLite store.

This is the THIRD, narrow, explicit exception to `pfsense_mcp.tier1`
never being imported from outside its own package -- alongside
`tier1_anchor_check.py` and `security_discovery.py`
(`tests/tier1/test_isolation.py::test_tier1_is_not_imported_outside_its_inert_package`).
Deliberately a SEPARATE module from `security_discovery.py`, not an
added function inside it: `security_discovery.py` imports
`pfsense_mcp.tier1.production_store` (and therefore `sqlite3`)
unconditionally, for its own, unrelated, store-backed
`discover_anchor_assurance()`. Adding this function there would mean
anything that only ever needs THIS function -- in particular, the
isolated signer -- transitively imports `sqlite3`/`production_store.py`
merely by importing the file, exactly the class of coupling
`docs/adr/ADR-028...` already rejected once for
`ResolvedTransportTarget` (moved to `tier1/transport_target.py` for the
identical reason). See `security_posture_types.py`'s own docstring for
the matching extraction this module depends on to share
`AnchorAssuranceDiscovery` with the store-backed path without paying
for `production_store.py`'s own import graph.

## What this module produces and how it differs from the store path

`discover_anchor_assurance()` derives `baseline`/`provisioned_at`/
`handle` from a live, read-only SQLite read of the store's own
`anchor_state` table. This module derives the exact same three values
from an already-signed, already-delivered `AnchorEvidenceExport`
instead -- verified with a **public** Ed25519 key only (never a
symmetric HMAC key that could also forge future exports), checked for
a bounded validity window, and cross-checked against a live witness
read exactly as the store path already does. Given equivalent
evidence (the export's `baseline`/`provisioned_at` match what the
store would have reported, and the witness read returns the same
value), the resulting `AnchorAssuranceDiscovery` has identical
digest-relevant fields (`value`, `evidence_state`, `baseline`,
`witness_value`, `provisioned_at`) to what the store path would
produce -- so `compute_plan_digest()` is unaffected; only the
*evidence source* differs, never the digest schema or the plan-
construction logic (`security_plan.generate_security_posture_plan_
from_discovery()`, which both paths feed into identically).

## What this module never does

Never imports `pfsense_mcp.tier1.production_store`, `sqlite3`, or
anything that could open, create, or hold a key for the runtime
`RecoveryContract` store. Never calls `TpmHostWitnessAnchor.advance()`
-- only `.read()`, exactly like `security_discovery.py`'s own
discipline. Never provisions, signs, or holds a private key of any
kind -- `sign_anchor_evidence_export()` (the only function that could)
lives in `tier1/anchor_evidence_export.py`, not here, and is never
imported here either.
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from datetime import datetime

import httpx

from .security_posture_types import AnchorAssurance, AnchorAssuranceDiscovery, AnchorEvidenceState
from .tier1.anchor_evidence_export import AnchorEvidenceExport, verify_anchor_evidence_export_signature
from .tier1.anti_rollback_tpm_witness import TpmHostWitnessAnchor
from .tier1.ed25519_authority import PinnedAuthoritySet
from .tier1.errors import AnchorUnavailableError, Tier1Error

#: Deliberately identical to `security_discovery.py`'s own four witness
#: env vars -- the exact same live TPM witness daemon, the exact same
#: mTLS recipe, reused verbatim, not reinvented for this second caller.
_WITNESS_BASE_URL_VAR = "PFSENSE_TIER1_WITNESS_BASE_URL"
_WITNESS_CLIENT_CERT_VAR = "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE"
_WITNESS_CLIENT_KEY_VAR = "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE"
_WITNESS_SERVER_CA_VAR = "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE"


@dataclass(frozen=True)
class _WitnessClientConfig:
    base_url: str
    client_cert_file: str
    client_key_file: str
    server_ca_file: str


def _load_witness_client_config(env: dict[str, str] | None = None) -> _WitnessClientConfig | None:
    """Deliberately duplicates `security_discovery.py`'s own private
    `_load_witness_client_config` (which itself already duplicates
    `tier1_anchor_check.py`'s) rather than importing a private name
    across a module boundary -- the established, reviewed pattern in
    this exact codebase for this exact ~20-line, side-effect-free
    helper. Importing it from `security_discovery.py` instead would
    reintroduce the very `production_store.py`/`sqlite3` coupling this
    module exists to avoid."""

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
    """Identical mTLS recipe to `security_discovery.py`'s own private
    helper of the same name. This module's own discipline (never call
    `.advance()`) is enforced by never calling it anywhere below,
    verified structurally by this module's own isolation test."""

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(cafile=config.server_ca_file)
    ssl_context.load_cert_chain(certfile=config.client_cert_file, keyfile=config.client_key_file)
    client = httpx.Client(verify=ssl_context, trust_env=False, timeout=10.0)
    return TpmHostWitnessAnchor(client=client, base_url=config.base_url)


def _result(
    *,
    value: AnchorAssurance,
    evidence_state: AnchorEvidenceState,
    evidence: tuple[str, ...],
    export: AnchorEvidenceExport | None = None,
    witness_configured: bool = False,
    witness_reachable: bool | None = None,
    witness_value: int | None = None,
    witness_matches_baseline: bool | None = None,
) -> AnchorAssuranceDiscovery:
    """The single place every `AnchorAssuranceDiscovery` produced by
    this module is built -- mirrors `security_discovery.py`'s own
    `_anchor_result()` role for its path. `store_configured`/
    `store_exists` are always `True` here: an export, once verified,
    IS the configured/existing evidence source for this path (there is
    no separate "is a store configured" question the way the SQLite
    path has one)."""

    return AnchorAssuranceDiscovery(
        value=value,
        evidence_state=evidence_state,
        store_configured=True,
        store_exists=True,
        seeded=True if export is not None else None,
        complete=True if export is not None else None,
        handle=None if export is None else export.handle,
        baseline=None if export is None else export.baseline,
        provisioned_at=None if export is None else export.provisioned_at,
        witness_configured=witness_configured,
        witness_reachable=witness_reachable,
        witness_value=witness_value,
        witness_matches_baseline=witness_matches_baseline,
        evidence=evidence,
    )


def discover_anchor_assurance_from_export(
    export: AnchorEvidenceExport,
    *,
    authorities: PinnedAuthoritySet,
    expected_store_id: str,
    now: datetime,
    env: dict[str, str] | None = None,
) -> AnchorAssuranceDiscovery:
    """Read-only. Never calls `TpmHostWitnessAnchor.advance()`, never
    imports `production_store.py`/`sqlite3`, never requires the
    runtime store's encryption or integrity key. Fails closed
    (`AnchorAssurance.UNKNOWN`, `AnchorEvidenceState.CONFIGURATION_
    INVALID` or `STORE_ERROR`) on a bad signature, wrong `store_id`,
    or an expired/future-dated export -- exactly the same "unavailable
    evidence must never be treated as a success/no-op condition"
    discipline `discover_anchor_assurance()` itself already follows for
    its own failure branches, and which `generate_security_posture_
    plan_from_discovery()` already blocks the whole plan on
    (`AnchorAssurance.UNKNOWN` at `current.anchor_assurance.value`)."""

    if not verify_anchor_evidence_export_signature(export, authorities):
        return _result(
            value=AnchorAssurance.UNKNOWN,
            evidence_state=AnchorEvidenceState.STORE_ERROR,
            evidence=(
                "AnchorEvidenceExport signature verification failed against the pinned posture-evidence "
                "authority/authorities -- refusing to trust unverified anchor evidence.",
            ),
        )

    if export.store_id != expected_store_id:
        return _result(
            value=AnchorAssurance.UNKNOWN,
            evidence_state=AnchorEvidenceState.CONFIGURATION_INVALID,
            evidence=(
                f"AnchorEvidenceExport store_id {export.store_id!r} does not match the expected store "
                f"identity {expected_store_id!r}.",
            ),
        )

    if now < export.issued_at:
        return _result(
            value=AnchorAssurance.UNKNOWN,
            evidence_state=AnchorEvidenceState.CONFIGURATION_INVALID,
            evidence=("AnchorEvidenceExport is issued in the future relative to the current time.",),
        )
    if now >= export.expires_at:
        return _result(
            value=AnchorAssurance.UNKNOWN,
            evidence_state=AnchorEvidenceState.CONFIGURATION_INVALID,
            evidence=("AnchorEvidenceExport has expired -- its bounded validity window has elapsed.",),
        )

    provisioning_evidence = (
        f"AnchorEvidenceExport: handle={export.handle} baseline={export.baseline} "
        f"provisioned_at={export.provisioned_at} issued_at={export.issued_at.isoformat()} "
        f"expires_at={export.expires_at.isoformat()}."
    )

    try:
        witness_config = _load_witness_client_config(env)
    except Tier1Error as exc:
        return _result(
            value=AnchorAssurance.HARDWARE_WITNESS,
            evidence_state=AnchorEvidenceState.PROVISIONED_UNVERIFIED,
            export=export,
            evidence=(
                provisioning_evidence,
                f"Witness client configuration is invalid ({type(exc).__name__}) -- live verification skipped.",
            ),
        )

    if witness_config is None:
        return _result(
            value=AnchorAssurance.HARDWARE_WITNESS,
            evidence_state=AnchorEvidenceState.PROVISIONED_UNVERIFIED,
            export=export,
            evidence=(provisioning_evidence, "Witness client not configured -- live verification skipped."),
        )

    try:
        anchor = _build_read_only_witness_client(witness_config)
        current_value = anchor.read()
    except (OSError, ssl.SSLError, AnchorUnavailableError, Tier1Error) as exc:
        return _result(
            value=AnchorAssurance.HARDWARE_WITNESS,
            evidence_state=AnchorEvidenceState.PROVISIONED_UNREACHABLE,
            export=export,
            witness_configured=True,
            witness_reachable=False,
            evidence=(
                provisioning_evidence,
                f"Witness client configured but the live witness could not be read ({type(exc).__name__}). "
                "Exported evidence still indicates hardware_witness was provisioned.",
            ),
        )

    matches = current_value == export.baseline
    verified_state = AnchorEvidenceState.PROVISIONED_VERIFIED if matches else AnchorEvidenceState.PROVISIONED_MISMATCH
    match_evidence = (
        f"Witness value ({current_value}) matches the authenticated exported baseline ({export.baseline})."
        if matches
        else (
            f"Witness value ({current_value}) does NOT match the authenticated exported baseline "
            f"({export.baseline}) -- security-relevant anomaly, reported not resolved. Discovery never "
            "performs reconciliation."
        )
    )
    return _result(
        value=AnchorAssurance.HARDWARE_WITNESS,
        evidence_state=verified_state,
        export=export,
        witness_configured=True,
        witness_reachable=True,
        witness_value=current_value,
        witness_matches_baseline=matches,
        evidence=(provisioning_evidence, match_evidence),
    )


__all__ = ["discover_anchor_assurance_from_export"]
