# Tier 1 — Production store bootstrap

Status: implemented (inert, unwired). No production application file
imports this mechanism.
Related: [key_lifecycle.md](key_lifecycle.md),
[whole_store_anti_rollback.md](whole_store_anti_rollback.md),
[anti_rollback_tpm_host_witness.md](anti_rollback_tpm_host_witness.md).

## Purpose

Give an operator a real, deterministic, non-ad-hoc way to configure,
inspect, and one-time-provision `SqliteRecoveryContractStore` on the host
that actually runs `pfsense-mcp-server`, without needing to guess a
database path, open a Python shell to construct the store class directly,
manually edit SQLite, or reimplement any HMAC/insert-only provisioning
logic already built in `anti_rollback.py`/`store.py`.

This spec deliberately does **not** decide whether/when the running MCP
server process itself should construct this store — see "Explicitly
deferred decision" below.

## Security goals

- G1: No production application code path (`application.py`/
  `factory.py`/`server.py`/`tools/`) can reach a mutation endpoint through
  this mechanism, regardless of whether it is ever wired in — verified
  structurally, not by convention (see Required tests).
- G2: The store's location is never guessed, never falls back to an
  undocumented default, and is not affected by the current working
  directory of whatever process reads it.
- G3: Configuring the store's location never itself creates state on
  disk. Only an explicit, later, separate call creates or opens the
  store.
- G4: The integrity key file and the store file are provably in
  different directories (`key_lifecycle.md` Invariant I1), enforced by
  code, not merely documented.
- G5: Every file-safety property `SqliteRecoveryContractStore` already
  enforces (symlink rejection, owner-only permissions, malformed-file
  rejection, atomic creation) continues to apply unchanged — this layer
  adds configuration validation *above* that, never a parallel or
  weaker check.
- G6: No secret material (key bytes, TPM auth secrets) is ever read,
  logged, or printed by the operator-facing status tool.

## Invariants

- I1: `load_production_store_config()` performs zero filesystem I/O.
  It validates only the shape of the two configured paths (absolute,
  distinct file, distinct parent directory). Existence, permissions, and
  symlink-ness of either path are validated later, by
  `open_production_store()`/`key_lifecycle.load_key_material()`, not
  duplicated here.
- I2: Tier 1 being unconfigured (`PFSENSE_TIER1_STORE_PATH` and
  `PFSENSE_TIER1_STORE_KEY_FILE` both unset) is the default, expected,
  safe state — `load_production_store_config()` returns `None`, not an
  error. Tier 1 remains exactly as inert as it has been throughout this
  project.
- I3: Partial configuration (exactly one of the two variables set) is
  always a `Tier1ConfigurationError`, never guessed or defaulted.
- I4: The store identifier is a fixed, documented constant
  (`PRODUCTION_STORE_ID = "tier1-production-anchor"`), not another path
  an operator could get wrong — there is exactly one production anchor
  store per deployment, no multi-tenancy.
- I5: `open_production_store()` is the only function in this mechanism
  that touches the filesystem. Calling it against a path that has never
  held a store creates one, through `SqliteRecoveryContractStore`'s own
  already-tested atomic-creation path (`store.py::_prepare_path`) —
  never through code duplicated here.
- I6: `provision_production_anchor_baseline()` performs no HMAC,
  insert-only, or ordering logic itself — it composes
  `open_production_store()` with the already-implemented, tested Slice B
  primitive `SqliteRecoveryContractStore.provision_anchor_baseline()`.

## Explicitly deferred decision — not resolved by this spec

**Whether the running `pfsense-mcp-server` process itself (via
`application.py`/`factory.py`) should ever construct this store is a
separate, not-yet-authorized decision, deliberately left open here.**

Every phase of this project's own roadmap
(`docs/tier1/IMPLEMENTATION_ROADMAP.md`) has treated "a non-`tier1`
production file imports `pfsense_mcp.tier1`" as the single largest
threshold in the whole project — bigger than implementing the sealed
executor itself, which remains "never constructed by production" even
after Phase 3's completion. `tests/tier1/test_isolation.py::
test_tier1_is_not_imported_outside_its_inert_package` currently enforces,
as a hard, 100%-passing structural test, that this has never happened.
The roadmap's own Phase 5 entry gate (the first phase that touches
`Application`/`factory.py`/`ToolRegistry`) requires both Milestone 0
naming (done — `ADR-020`) **and** Phase 4's live disposable-lab evidence
(not done).

This mechanism therefore ships as **importable only from outside
`src/pfsense_mcp/`** — specifically from
`scripts/tier1_store_bootstrap.py`, which lives outside the isolation
test's scan root and is free to import inert Tier 1 code, exactly the
same pattern already established for `scripts/build_endpoint_catalogue.py`
importing `pfsense_mcp.api_surface`. This fully satisfies every concrete
operator-facing requirement (deterministic path selection, safe
construction, a real provisioning entrypoint) without requiring the
Phase-5-scoped decision to be made first. If a future session wants the
running server itself to validate or expose this configuration (e.g. in
`pfsense_mcp_info`), that is its own explicit future authorization,
informed by this spec but not granted by it.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Configured path vs. guesswork | Two explicit, required-together env vars | Any undocumented fallback/default path | `load_production_store_config()` (I2/I3) |
| Store file vs. filesystem | Process holding a validated, non-symlink, owner-only descriptor | Any other process/user on the host | `SqliteRecoveryContractStore._prepare_path()` (unchanged, reused) |
| Key file vs. store file | Two distinct directories | An attacker who can read one directory learning the other's location | I1 same-parent-directory check (new) |
| Operator tool vs. pfSense | `scripts/tier1_store_bootstrap.py`, zero pfSense-capable imports | Any accidental mutation reachability | `tests/test_tier1_store_bootstrap_isolation.py` (AST-based, new) |

## State ownership

- `src/pfsense_mcp/tier1/production_store.py` (new) owns:
  `ProductionStoreConfig`, `load_production_store_config()`,
  `open_production_store()`, `provision_production_anchor_baseline()`,
  `PRODUCTION_STORE_ID`.
- `SqliteRecoveryContractStore.anchor_provisioning_status()` (new, in
  `store.py`) and `ProvisioningRecord.read()` (new, in `anti_rollback.py`)
  are read-only accessors for operator tooling — never called by
  provisioning or execution logic itself.
- `scripts/tier1_store_bootstrap.py` (new) owns the CLI surface only; it
  contains no independent logic beyond argument parsing and print
  formatting.

## Interfaces

```python
# src/pfsense_mcp/tier1/production_store.py

PRODUCTION_STORE_ID: str  # "tier1-production-anchor"


@dataclass(frozen=True)
class ProductionStoreConfig:
    store_path: Path
    key_file: Path
    store_id: str = PRODUCTION_STORE_ID


def load_production_store_config(env: dict[str, str] | None = None) -> ProductionStoreConfig | None: ...
def open_production_store(config: ProductionStoreConfig) -> SqliteRecoveryContractStore: ...
def provision_production_anchor_baseline(config: ProductionStoreConfig, *, value: int, handle: str) -> None: ...
```

```
# environment variables
PFSENSE_TIER1_STORE_PATH        absolute path to the SQLite store file
PFSENSE_TIER1_STORE_KEY_FILE    absolute path to the HMAC integrity key
                                 file (key_lifecycle.py format), in a
                                 different directory than the store file
```

```
# scripts/tier1_store_bootstrap.py
tier1_store_bootstrap.py                                    # read-only status
tier1_store_bootstrap.py --provision VALUE --handle H --yes-i-understand
```

## Failure modes

| Failure | Detection | Resulting state | Automatic retry |
|---|---|---|---|
| Neither env var set | `load_production_store_config()` | Returns `None`; Tier 1 stays inert | N/A — not a failure |
| Exactly one env var set | `load_production_store_config()` | `Tier1ConfigurationError`, nothing touched | No |
| Relative path | `load_production_store_config()` | `Tier1ConfigurationError`, nothing touched | No |
| Store path == key file, or same parent directory | `load_production_store_config()` | `Tier1ConfigurationError`, nothing touched | No |
| Store parent directory missing | `SqliteRecoveryContractStore._prepare_path()` | `ContractValidationError` (fixed this session — previously a raw unhandled `FileNotFoundError`), nothing created | No |
| Store parent directory unsafe (not 0700 / wrong owner) | `_prepare_path()` | `ContractValidationError`, nothing created | No |
| Store path is a symlink, or an existing file is unsafe | `_prepare_path()` | `ContractValidationError`, nothing created/opened | No |
| Existing store file is malformed/not SQLite | `_connect()` | `ContractIntegrityError`, nothing further happens | No |
| Key file missing/unsafe/malformed | `key_lifecycle.load_key_material()` | `KeyMaterialError`, store is never constructed | No |
| Store already provisioned | `provision_anchor_baseline()` (Slice B, unchanged) | `AnchorAlreadyProvisionedError`, nothing overwritten | No |

## Recovery behavior

- **Backup**: `_connect()` sets `PRAGMA journal_mode = DELETE` (no `-wal`/
  `-shm` sidecar files), so a filesystem-level copy of the single store
  file, taken while the `pfsense-mcp-server` process (or, currently, any
  ad-hoc script invocation) is not actively writing, is a complete,
  consistent backup. `sqlite3 <path> ".backup <dest>"` is an equivalent,
  safe-while-open alternative.
- **Restore**: stop any process holding the store open, replace the file,
  restart. `SqliteRecoveryContractStore.__init__`'s existing schema/
  integrity verification (`_verify_schema()`, HMAC checks on every read)
  detects a restored file that does not match the configured
  `integrity_key`/`store_id` and fails closed
  (`ContractIntegrityError`) rather than silently accepting it.
- **Restart/reopen**: constructing `SqliteRecoveryContractStore` against
  an existing, valid store file is idempotent and side-effect-free beyond
  opening a connection — already covered by `test_store.py`'s existing
  `test_create_load_and_restart_preserve_authoritative_contract`; this
  spec's own tests add the same coverage specifically through
  `open_production_store()`.
- **Directory creation**: deliberately **not** this mechanism's job. The
  parent directory of both the store path and the key file must already
  exist, owned by the effective user, mode `0700`, before either
  `open_production_store()` or `key_lifecycle.load_key_material()` is
  called — provisioned by deployment tooling (e.g. a systemd
  `StateDirectory=`/`ConfigurationDirectory=` directive, or a manual
  `install -d -m 0700`), not auto-created here. Auto-creating directories
  from inside a security-sensitive store-construction path would
  introduce exactly the kind of race/permission-guessing risk this
  mechanism exists to avoid.

## Non-goals

- Does not decide the deferred production-wiring question above.
- Does not implement key rotation, backup automation, or a systemd unit
  file — those are deployment/operational concerns, out of scope here
  (see `key_lifecycle.md`'s own equivalent non-goal for the encryption/
  integrity keys themselves).
- Does not touch the TPM, the host-witness daemon, or any Proxmox/VM
  configuration — `value`/`handle` passed to
  `provision_production_anchor_baseline()` must already have been
  obtained from the real anchor by the caller (see
  `anti_rollback_tpm_host_witness.md`).

## Required tests

- No configuration → `None`, zero filesystem access (`tests/tier1/
  test_production_store.py`).
- Partial configuration (either direction) → `Tier1ConfigurationError`.
- Relative store path / relative key file → `Tier1ConfigurationError`.
- Store path == key file → `Tier1ConfigurationError`.
- Store path and key file share a parent directory → `Tier1ConfigurationError`
  (Invariant I1/G4).
- Valid configuration → deterministic `ProductionStoreConfig`, confirmed
  to touch no filesystem state.
- `open_production_store()` creates a store on first open; reopens an
  existing one; rejects unsafe parent directory, symlinked store path,
  malformed existing file, and unsafe key file — reusing
  `SqliteRecoveryContractStore`'s and `key_lifecycle`'s own existing,
  tested checks, not duplicating them.
- Missing parent directory now fails closed with `ContractValidationError`,
  not a raw `FileNotFoundError` (`tests/tier1/test_store.py::
  test_store_rejects_nonexistent_parent_directory_cleanly`, new
  regression test).
- `provision_production_anchor_baseline()` seeds and marks complete;
  refuses a second call; two independently configured stores cannot
  cross-contaminate each other's provisioning state.
- `AnchorProvisioningStatus`/`anchor_provisioning_status()`/
  `ProvisioningRecord.read()`: before any provisioning, after full
  provisioning, and in the seeded-but-not-complete intermediate state;
  corrupted marker fails closed on read (`tests/tier1/
  test_anti_rollback.py`).
- `scripts/tier1_store_bootstrap.py`: status reporting for unconfigured/
  configured-but-unprovisioned/provisioned states, creating nothing in
  status mode; `--provision` requires both `--handle` and
  `--yes-i-understand`; a full provision-then-status-then-refused-second-
  call cycle (`tests/test_tier1_store_bootstrap.py`).
- Structural: the script cannot import anything capable of reaching
  pfSense and calls no forbidden attribute name; no production
  application file imports this mechanism
  (`tests/test_tier1_store_bootstrap_isolation.py`).

## Activation requirements

- [x] Implemented and tested per "Required tests" above.
- [ ] The deferred production-wiring decision (see above) — its own,
      separate, future authorization, informed by but not granted by
      this spec.
- [ ] An operational runbook for initial deployment (creating the parent
      directories with correct ownership/mode, generating the integrity
      key via `key_lifecycle.py`'s existing tooling) — documentation, not
      code, not yet written.

## Implementation checklist

- [x] `src/pfsense_mcp/tier1/production_store.py`: `ProductionStoreConfig`,
      `load_production_store_config()`, `open_production_store()`,
      `provision_production_anchor_baseline()`.
- [x] `Tier1ConfigurationError` added to `errors.py`.
- [x] `SqliteRecoveryContractStore.anchor_provisioning_status()` and
      `ProvisioningRecord.read()` (read-only status accessors).
- [x] `store.py::_prepare_path()`'s missing-parent-directory case fixed
      to fail closed with `ContractValidationError` instead of a raw
      `FileNotFoundError`.
- [x] `scripts/tier1_store_bootstrap.py` operator CLI.
- [x] `tests/tier1/test_production_store.py`,
      `tests/test_tier1_store_bootstrap.py`,
      `tests/test_tier1_store_bootstrap_isolation.py`, plus additions to
      `tests/tier1/test_anti_rollback.py`/`test_store.py`.

## Review checklist

- [ ] Confirm no committed test fixture or default value anywhere in this
      slice uses the real TPM baseline (`2`) or the real NV handle
      (`0x01500000`) as a literal — only synthetic values.
- [ ] Confirm `load_production_store_config()` truly performs zero
      filesystem I/O (grep for `os.`/`Path.exists`/`Path.stat` calls
      inside it — there should be none beyond `Path()` construction
      itself).

## Security checklist

- [ ] No key material or TPM secret is ever read, printed, or logged by
      `scripts/tier1_store_bootstrap.py` in either mode.
- [ ] `tests/test_tier1_store_bootstrap_isolation.py` passes: the script
      cannot import `rest_api_client`/`transport`/`tools`/
      `write_api_client`/`pfsense_client`, and calls no forbidden
      attribute name.
- [ ] `tests/tier1/test_isolation.py::
      test_tier1_is_not_imported_outside_its_inert_package` still passes
      unchanged — no production application file imports
      `pfsense_mcp.tier1`.

## Test checklist

- [ ] Every failure mode in the table above has a dedicated test.
- [ ] `make quick`/`make validate` both green.
- [ ] Full pytest suite green; 42-tool public MCP contract byte-identical;
      WRITE 0/3 active; WRITE allow-list empty.
