"""Production bootstrap for the Tier 1 anti-rollback anchor store.

Not imported by production. Deliberately: this module gives a future
operator a real, deterministic, non-ad-hoc way to configure and
provision `SqliteRecoveryContractStore` on the host that actually runs
`pfsense-mcp-server`, but nothing in `application.py`/`factory.py`/
`server.py` calls it -- doing so would be the first-ever import of
`pfsense_mcp.tier1` from outside its own package, which
`tests/tier1/test_isolation.py::test_tier1_is_not_imported_outside_its_inert_package`
currently enforces has never happened across every phase of this
project's roadmap (see `docs/tier1/specs/production_store_bootstrap.md`
for the full status of that separate, not-yet-authorized decision). The
intended entrypoint for now is a standalone operator tool
(`scripts/tier1_store_bootstrap.py`), which lives outside
`src/pfsense_mcp/` and is therefore free to import this module without
touching that invariant.

Two-phase, matching the config/key-file split already established by
`pfsense_mcp.config` (`load_config()` validates paths; `load_api_key()`
separately reads the key, only when actually needed):

  1. `load_production_store_config()` -- pure path validation, zero
     filesystem I/O beyond `Path` string operations. Fails closed on
     partial configuration. Returns `None`, not an error, when Tier 1 is
     simply unconfigured -- that is the expected, safe, default state.
  2. `open_production_store()` -- the one function that touches the
     filesystem: loads the integrity key
     (`key_lifecycle.load_key_material()`, never reimplemented here) and
     constructs `SqliteRecoveryContractStore`, which performs its own
     already-implemented-and-tested O_NOFOLLOW/permission/malformed-file/
     atomic-creation safety (`store.py::_prepare_path`/`_connect`/
     `_initialize_schema`). This is the "defer actual creation" half of
     the Option A/B split in `production_store_bootstrap.md` -- calling
     `load_production_store_config()` alone creates nothing.

`provision_production_anchor_baseline()` composes both, calling the
already-implemented, tested Slice B primitive
(`SqliteRecoveryContractStore.provision_anchor_baseline()`) rather than
duplicating any HMAC/insert-only logic.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .errors import Tier1ConfigurationError
from .key_lifecycle import KeyPurpose, load_key_material
from .store import SqliteRecoveryContractStore

_STORE_PATH_VAR = "PFSENSE_TIER1_STORE_PATH"
_KEY_FILE_VAR = "PFSENSE_TIER1_STORE_KEY_FILE"

# There is exactly one production anchor store per deployment (no
# multi-tenancy) -- a fixed, documented, non-guessable identifier, not
# another path an operator could get wrong. Must match store.py's own
# _STORE_ID pattern (checked by SqliteRecoveryContractStore.__init__).
PRODUCTION_STORE_ID = "tier1-production-anchor"


@dataclass(frozen=True)
class ProductionStoreConfig:
    """A validated, deterministic pointer to the production anchor
    store's location -- not proof the store exists yet, and not itself
    an open connection or loaded key."""

    store_path: Path
    key_file: Path
    store_id: str = PRODUCTION_STORE_ID


def load_production_store_config(env: dict[str, str] | None = None) -> ProductionStoreConfig | None:
    """Fail-closed, environment-driven, side-effect-free.

    - Neither `PFSENSE_TIER1_STORE_PATH` nor `PFSENSE_TIER1_STORE_KEY_FILE`
      set: returns `None`. This is the default, expected, safe state --
      Tier 1 stays completely inert, exactly as it has throughout this
      project. Not an error.
    - Exactly one of the two set: raises `Tier1ConfigurationError`.
      Partial configuration is ambiguous and refused, never guessed.
    - Both set: validates both are absolute paths (a relative path would
      make the configured location depend on the current working
      directory of whatever process reads it -- not deterministic), that
      they do not name the same file, and that they do not share a
      parent directory (`docs/tier1/specs/key_lifecycle.md` Invariant I1
      -- a directory listing of the store's parent must not also reveal
      the key material's location). Touches no filesystem state: does
      not check existence, permissions, or symlink-ness of either path --
      that is `SqliteRecoveryContractStore.__init__`'s and
      `key_lifecycle.load_key_material()`'s own job respectively, each
      already implemented and tested; this function does not duplicate
      either.
    """

    source = env if env is not None else os.environ
    store_path_raw = source.get(_STORE_PATH_VAR)
    key_file_raw = source.get(_KEY_FILE_VAR)

    if not store_path_raw and not key_file_raw:
        return None
    if not store_path_raw or not key_file_raw:
        raise Tier1ConfigurationError(f"Both {_STORE_PATH_VAR} and {_KEY_FILE_VAR} must be set together, or neither.")

    store_path = Path(store_path_raw).expanduser()
    key_file = Path(key_file_raw).expanduser()

    if not store_path.is_absolute():
        raise Tier1ConfigurationError(f"{_STORE_PATH_VAR} must be an absolute path (got {store_path_raw!r}).")
    if not key_file.is_absolute():
        raise Tier1ConfigurationError(f"{_KEY_FILE_VAR} must be an absolute path (got {key_file_raw!r}).")
    if store_path == key_file:
        raise Tier1ConfigurationError(f"{_STORE_PATH_VAR} and {_KEY_FILE_VAR} must not name the same file.")
    if store_path.parent == key_file.parent:
        raise Tier1ConfigurationError(
            f"{_STORE_PATH_VAR} and {_KEY_FILE_VAR} must not share a parent directory (key_lifecycle.md Invariant I1)."
        )

    return ProductionStoreConfig(store_path=store_path, key_file=key_file)


def open_production_store(config: ProductionStoreConfig) -> SqliteRecoveryContractStore:
    """Loads the real integrity key and constructs the real store against
    `config`'s validated location. The first filesystem-touching step --
    calling this against a path that has never held a store creates one,
    atomically, with the same safety `SqliteRecoveryContractStore`
    already guarantees for every other caller (production or test)."""

    key_record = load_key_material(config.key_file, purpose=KeyPurpose.INTEGRITY)
    return SqliteRecoveryContractStore(
        config.store_path,
        integrity_key=key_record.material,
        store_id=config.store_id,
    )


def provision_production_anchor_baseline(config: ProductionStoreConfig, *, value: int, handle: str) -> None:
    """The narrow, explicit, one-call provisioning entrypoint targeting
    exactly the configured production store -- composes
    `open_production_store()` with the already-implemented, tested Slice
    B primitive `SqliteRecoveryContractStore.provision_anchor_baseline()`
    rather than reimplementing any insert-only/HMAC/ordering logic here.
    Raises `AnchorAlreadyProvisionedError` if this store already has a
    baseline or completion marker recorded -- never silently
    overwritten, exactly as `provision_anchor_baseline()` already
    guarantees."""

    store = open_production_store(config)
    store.provision_anchor_baseline(value=value, handle=handle)
