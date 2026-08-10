"""Read-only, opt-in, log-only Tier 1 anti-rollback anchor startup
verification.

This is the ONE, narrow, explicit exception to `pfsense_mcp.tier1`
never being imported from outside its own package -- exempted by name
in `tests/tier1/test_isolation.py::
test_tier1_is_not_imported_outside_its_inert_package`, nothing else.
`application.py` itself does not import `pfsense_mcp.tier1` at all; it
only ever calls `run_anchor_startup_check()` here, keeping the
isolation exemption's surface to exactly this one file.

What this module does, precisely, and nothing more:

  - If neither `PFSENSE_TIER1_STORE_PATH` nor `PFSENSE_TIER1_STORE_KEY_FILE`
    is set (the default, expected state today), this is a complete
    no-op -- server behavior is byte-identical to before this module
    existed.
  - If configured, opens the production store **read-only** (via the
    already-implemented, tested `production_store.open_production_store()`
    -- never `provision_anchor_baseline()`), reads its provisioning
    status, and -- if a witness connection is also configured -- calls
    `TpmHostWitnessAnchor.read()` (a GET request; the protocol has no
    mutating read operation) and compares the result against the
    persisted high-water mark.
  - Every outcome is a *log message only*. This function never raises
    (a single broad `except Exception` wraps everything so a Tier 1
    problem can never affect whether the READ-only MCP server starts or
    serves its 42 existing tools -- matching `whole_store_anti_rollback.md`'s
    own G4: anchor unavailability degrades to informational, never
    "server unusable"), never writes to the store, never calls
    `advance()`, never constructs `RecoveryContract`/`MutationExecutor`/
    `WriteApiClient`, never touches `WriteEndpoints`, and is not
    reachable from, or exposed through, any MCP tool, resource, or the
    `pfsense_mcp_info` introspection payload.

Mismatch handling (Invariant I2, `whole_store_anti_rollback.md`): the
accepted architecture's own recovery action for a detected mismatch --
in either direction -- is a store mutation (forcing affected contracts
into `RECONCILIATION`, or advancing the persisted mark to match) that
this read-only integration deliberately does not perform. A mismatch is
logged as a security-relevant finding for operator review, not silently
resolved and not treated as fatal -- inventing an unauthorized recovery
action here would be worse than reporting the gap plainly.
"""

from __future__ import annotations

import logging
import os
import ssl
from dataclasses import dataclass
from pathlib import Path

import httpx

from .tier1.anti_rollback_tpm_witness import TpmHostWitnessAnchor
from .tier1.errors import AnchorUnavailableError, Tier1Error
from .tier1.production_store import load_production_store_config, open_production_store

_WITNESS_BASE_URL_VAR = "PFSENSE_TIER1_WITNESS_BASE_URL"
_WITNESS_CLIENT_CERT_VAR = "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE"
_WITNESS_CLIENT_KEY_VAR = "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE"
_WITNESS_SERVER_CA_VAR = "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE"
_WITNESS_VARS = (_WITNESS_BASE_URL_VAR, _WITNESS_CLIENT_CERT_VAR, _WITNESS_CLIENT_KEY_VAR, _WITNESS_SERVER_CA_VAR)
_EXPECTED_HANDLE_VAR = "PFSENSE_TIER1_EXPECTED_HANDLE"


@dataclass(frozen=True)
class WitnessClientConfig:
    """A validated, deterministic pointer to the witness daemon
    connection -- mirrors `production_store.ProductionStoreConfig`'s own
    fail-closed, side-effect-free loading discipline. Independent of
    `ProductionStoreConfig`: an operator may configure the store without
    yet configuring witness connectivity (comparison is then skipped,
    not an error -- see `_run()`)."""

    base_url: str
    client_cert_file: Path
    client_key_file: Path
    server_ca_file: Path


def _load_witness_client_config(env: dict[str, str] | None = None) -> WitnessClientConfig | None:
    source = env if env is not None else os.environ
    base_url_raw = source.get(_WITNESS_BASE_URL_VAR)
    client_cert_raw = source.get(_WITNESS_CLIENT_CERT_VAR)
    client_key_raw = source.get(_WITNESS_CLIENT_KEY_VAR)
    server_ca_raw = source.get(_WITNESS_SERVER_CA_VAR)

    if not base_url_raw and not client_cert_raw and not client_key_raw and not server_ca_raw:
        return None
    if not base_url_raw or not client_cert_raw or not client_key_raw or not server_ca_raw:
        missing = [
            name
            for name, value in (
                (_WITNESS_BASE_URL_VAR, base_url_raw),
                (_WITNESS_CLIENT_CERT_VAR, client_cert_raw),
                (_WITNESS_CLIENT_KEY_VAR, client_key_raw),
                (_WITNESS_SERVER_CA_VAR, server_ca_raw),
            )
            if not value
        ]
        raise Tier1Error(f"Witness client configuration is partial; missing: {', '.join(missing)}")

    # Every value above is now narrowed to `str` (not `None`) by the
    # combined guard -- no runtime assert needed for type narrowing
    # (bandit B101 correctly flags asserts in production code, since
    # they are stripped under `-O`).
    if not base_url_raw.startswith("https://"):
        raise Tier1Error(f"{_WITNESS_BASE_URL_VAR} must use https (got {base_url_raw!r}).")

    def _require_absolute(raw: str, var_name: str) -> Path:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            raise Tier1Error(f"{var_name} must be an absolute path (got {raw!r}).")
        return path

    return WitnessClientConfig(
        base_url=base_url_raw,
        client_cert_file=_require_absolute(client_cert_raw, _WITNESS_CLIENT_CERT_VAR),
        client_key_file=_require_absolute(client_key_raw, _WITNESS_CLIENT_KEY_VAR),
        server_ca_file=_require_absolute(server_ca_raw, _WITNESS_SERVER_CA_VAR),
    )


def _build_witness_anchor(config: WitnessClientConfig) -> TpmHostWitnessAnchor:
    """The confirmed-working mTLS recipe from `witness_daemon/README.md`'s
    "Connecting from the guest" section, applied verbatim -- an explicit
    `ssl.SSLContext`, never the `cert=`/`verify=<path>` shorthand found
    unreliable on `httpx>=0.28` during real-hardware verification."""

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(cafile=str(config.server_ca_file))
    ssl_context.load_cert_chain(certfile=str(config.client_cert_file), keyfile=str(config.client_key_file))
    client = httpx.Client(verify=ssl_context, trust_env=False, timeout=10.0)
    return TpmHostWitnessAnchor(client=client, base_url=config.base_url)


def run_anchor_startup_check(logger: logging.Logger) -> None:
    """The sole production entrypoint. Never raises."""

    try:
        _run(logger)
    except Exception:
        logger.exception("tier1_anchor_check_failed: unexpected error during read-only anchor verification")


def _run(logger: logging.Logger) -> None:
    try:
        store_config = load_production_store_config()
    except Tier1Error as exc:
        logger.error(
            "tier1_anchor_check: store configuration is invalid (%s) -- verification skipped; "
            "server continuing normally.",
            exc,
        )
        return
    if store_config is None:
        return  # Not configured -- the default, safe, expected state. No log noise.

    try:
        store = open_production_store(store_config)
        status = store.anchor_provisioning_status()
    except Tier1Error as exc:
        logger.error(
            "tier1_anchor_check: production store could not be opened or failed integrity/authentication "
            "verification (%s) -- this may be security-relevant; verification skipped; server continuing normally.",
            exc,
        )
        return

    if not status.seeded or not status.complete:
        logger.warning(
            "tier1_anchor_check: production anchor is configured but not fully provisioned "
            "(seeded=%s, complete=%s) -- witness comparison skipped; server continuing normally.",
            status.seeded,
            status.complete,
        )
        return

    logger.info(
        "tier1_anchor_check: store provisioning record -- handle=%s baseline=%s provisioned_at=%s",
        status.handle,
        status.baseline,
        status.provisioned_at,
    )

    # The witness daemon's own wire protocol never exposes which NV
    # handle it is configured for (by design -- G3, minimal API
    # surface) -- there is no live cross-check possible against it. This
    # optional, operator-asserted expectation is the only legitimate way
    # to check "configured handle mismatch" without extending that
    # protocol: if set, it must exactly match the store's own recorded
    # provisioning handle. Unset (the default) skips this check entirely
    # -- it is defense-in-depth, not a requirement.
    expected_handle = os.environ.get(_EXPECTED_HANDLE_VAR)
    if expected_handle and expected_handle != status.handle:
        logger.error(
            "tier1_anchor_check: configured handle mismatch -- %s=%s does not match the store's recorded "
            "provisioning handle %s. This is security-relevant (it may indicate the wrong store, the wrong "
            "witness daemon, or a misconfiguration); comparison skipped; server continuing normally.",
            _EXPECTED_HANDLE_VAR,
            expected_handle,
            status.handle,
        )
        return

    try:
        witness_config = _load_witness_client_config()
    except Tier1Error as exc:
        logger.error(
            "tier1_anchor_check: witness client configuration is invalid (%s) -- comparison skipped; "
            "server continuing normally.",
            exc,
        )
        return
    if witness_config is None:
        logger.info("tier1_anchor_check: witness client not configured -- comparison skipped.")
        return

    try:
        anchor = _build_witness_anchor(witness_config)
    except (OSError, ssl.SSLError, Tier1Error) as exc:
        # Local cert/key loading failure (missing file, malformed PEM,
        # mismatched key) -- distinct from the witness being unreachable
        # over the network, which is handled separately below.
        logger.error(
            "tier1_anchor_check: witness client TLS configuration failed (%s) -- comparison skipped; "
            "server continuing normally.",
            exc,
        )
        return

    try:
        current = anchor.read()
    except AnchorUnavailableError as exc:
        logger.warning(
            "tier1_anchor_check: witness anchor unavailable (%s) -- comparison skipped. Per "
            "whole_store_anti_rollback.md G4, read-only server operation is unaffected regardless; "
            "no current functionality depends on this (PREPARE/EXECUTE are not wired into production).",
            exc,
        )
        return
    except Tier1Error as exc:
        logger.error("tier1_anchor_check: witness read failed (%s) -- comparison skipped.", exc)
        return

    persisted = status.baseline
    if current == persisted:
        logger.info(
            "tier1_anchor_check: witness value matches persisted high-water mark (%s == %s). "
            "Read-only, no action taken.",
            current,
            persisted,
        )
    else:
        logger.error(
            "tier1_anchor_check: witness value (%s) does not match persisted high-water mark (%s) -- "
            "per whole_store_anti_rollback.md Invariant I2 this is a security-relevant anomaly in "
            "either direction (a restored store file, or a tampered/reset anchor). The accepted "
            "architecture's own recovery action for this (forcing affected contracts into "
            "RECONCILIATION, or advancing the persisted mark to match) is a store mutation this "
            "read-only integration deliberately does not perform -- this finding requires operator "
            "review and a separately authorized future reconciliation phase. Read-only server "
            "operation is unaffected; no contracts exist in production today regardless "
            "(PREPARE/EXECUTE are not wired in).",
            current,
            persisted,
        )
