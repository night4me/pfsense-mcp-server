#!/usr/bin/env python3
"""tier1_store_bootstrap.py -- the operator entrypoint for the Tier 1
anti-rollback anchor's production SQLite store.

This is the answer to "how does an operator configure/inspect/provision
the production store" without needing to guess a database path, open an
ad-hoc Python shell to construct `SqliteRecoveryContractStore` directly,
manually edit SQLite, or reimplement any HMAC/insert-only logic. It is a
thin CLI over `pfsense_mcp.tier1.production_store`, which does all of the
actual work.

Configuration is two environment variables, both required together or
neither (see `pfsense_mcp.tier1.production_store` for the exact
validation and `docs/tier1/specs/production_store_bootstrap.md` for the
full model):

    PFSENSE_TIER1_STORE_PATH       absolute path to the SQLite store file
    PFSENSE_TIER1_STORE_KEY_FILE   absolute path to the HMAC integrity
                                    key file (key_lifecycle.py format),
                                    in a different directory than the
                                    store file itself

Default (no arguments): **read-only status check.** Reports whether
Tier 1 is configured at all, and if so, whether the store file already
exists. It deliberately does **not** construct `SqliteRecoveryContractStore`
against a path that does not yet exist, since doing so would create it
(`store.py::_prepare_path`'s own atomic-creation behavior) -- this
script's default mode must never have that side effect.

`--provision VALUE --handle HANDLE --yes-i-understand`: the one-time,
insert-only, explicit provisioning action -- calls
`provision_production_anchor_baseline()`, which itself calls the
already-implemented, tested Slice B primitive
`SqliteRecoveryContractStore.provision_anchor_baseline()`. Refuses
(`AnchorAlreadyProvisionedError`) if this store already has a baseline or
completion marker recorded. `--yes-i-understand` is required and does
nothing except make accidental invocation (e.g. a stray Enter on a
half-typed command) require one extra deliberate flag.

This script must never:
  - construct a store against a path that does not yet exist outside
    `--provision` mode,
  - read, print, or log key material bytes or the TPM NV index's own
    authorization secret (it never touches the TPM at all),
  - import anything that could reach pfSense (`pfsense_mcp.rest_api_client`/
    `transport`/`tools`/`write_api_client`/`pfsense_client`) -- verified
    structurally by `tests/test_tier1_store_bootstrap_isolation.py`,
  - be invoked by CI or any Makefile target.
"""

from __future__ import annotations

import argparse
import sys

from pfsense_mcp.tier1.errors import Tier1ConfigurationError, Tier1Error
from pfsense_mcp.tier1.production_store import (
    load_production_store_config,
    open_production_store,
    provision_production_anchor_baseline,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tier1_store_bootstrap.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--provision",
        type=int,
        default=None,
        metavar="VALUE",
        help="Seed the anchor baseline with VALUE and mark provisioning complete. Requires --handle and "
        "--yes-i-understand. Refuses if already provisioned.",
    )
    parser.add_argument(
        "--handle",
        type=str,
        default=None,
        help="Opaque identifier for the physical anchor (e.g. the TPM NV index handle) being recorded. "
        "Required with --provision.",
    )
    parser.add_argument(
        "--yes-i-understand",
        action="store_true",
        help="Required alongside --provision. Confirms this call is intentional.",
    )
    return parser


def _status(argv_out) -> int:
    try:
        config = load_production_store_config()
    except Tier1ConfigurationError as exc:
        print(f"Error: {exc}", file=argv_out)
        return 1

    if config is None:
        print(
            "tier1_store_bootstrap: Tier 1 is not configured "
            "(PFSENSE_TIER1_STORE_PATH / PFSENSE_TIER1_STORE_KEY_FILE unset). Inert."
        )
        return 0

    print(f"tier1_store_bootstrap: configured store path:  {config.store_path}")
    print(f"tier1_store_bootstrap: configured key file:    {config.key_file}")
    print(f"tier1_store_bootstrap: store identifier:       {config.store_id}")

    if not config.store_path.exists():
        print("tier1_store_bootstrap: store file does not exist yet -- not yet provisioned.")
        print("tier1_store_bootstrap: it will be created only when --provision is explicitly run.")
        return 0

    try:
        store = open_production_store(config)
        state = store.anchor_provisioning_status()
    except Tier1Error as exc:
        print(f"Error opening the configured store: {exc}", file=argv_out)
        return 1

    print(f"tier1_store_bootstrap: seeded:          {state.seeded}")
    print(f"tier1_store_bootstrap: baseline:        {state.baseline}")
    print(f"tier1_store_bootstrap: complete:        {state.complete}")
    print(f"tier1_store_bootstrap: handle:          {state.handle}")
    print(f"tier1_store_bootstrap: provisioned_at:  {state.provisioned_at}")
    return 0


def _provision(value: int, handle: str | None, *, confirmed: bool, err_out) -> int:
    if not handle:
        print("Error: --provision requires --handle.", file=err_out)
        return 2
    if not confirmed:
        print("Error: --provision requires --yes-i-understand.", file=err_out)
        return 2

    try:
        config = load_production_store_config()
    except Tier1ConfigurationError as exc:
        print(f"Error: {exc}", file=err_out)
        return 1
    if config is None:
        print(
            "Error: Tier 1 is not configured "
            "(PFSENSE_TIER1_STORE_PATH / PFSENSE_TIER1_STORE_KEY_FILE unset). Nothing to provision.",
            file=err_out,
        )
        return 1

    try:
        provision_production_anchor_baseline(config, value=value, handle=handle)
    except Tier1Error as exc:
        print(f"Error: provisioning refused: {exc}", file=err_out)
        return 1

    print(f"tier1_store_bootstrap: provisioned baseline={value} handle={handle} at {config.store_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.provision is not None:
        return _provision(args.provision, args.handle, confirmed=args.yes_i_understand, err_out=sys.stderr)
    return _status(sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
