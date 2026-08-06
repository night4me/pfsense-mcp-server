# WRITE Tier 0 — Infrastructure-Only Implementation Specification

## Context

v0.1.0 (READ-only) is accepted and frozen (`docs/ACCEPTANCE_v0.1.0.md`, commit
`51e86a2`, tag `v0.1.0`). The user has authorized planning — but explicitly
**not yet implementing** — the first step toward mutating capability: "Tier
0," which must be infrastructure only. No real mutating pfSense capability
(no `create_firewall_alias`, no `set_dhcp_static_mapping`, nothing) is built
in Tier 0. The deliverable is the load-bearing machinery — allow-listing,
dry-run, snapshot/rollback, audit — fully built and tested, but provably
inert in the running server. Tier 1 (the first real capability) begins only
after a separate, explicit authorization naming that capability.

This spec was derived from direct reading of the current v0.1.0 codebase
(not summarized secondhand), specifically: `capabilities.py`, `profiles.py`,
`tools/registry.py`, `tools/write/__init__.py`, `errors.py`,
`rest_api_client.py`, `endpoints.py`, `application.py`, `factory.py`,
`config.py`, `transport/{base,mock}.py`, `logging_setup.py`, `tools/audit.py`,
`Makefile`, `pyproject.toml`, and the static checkers
`get_only_check.py`/`tools_write_check.py`/`bounded_params_check.py`/
`scaffold_capability.py`. Every design decision below extends an existing,
observed pattern rather than inventing a new one.

## Design principles (why the shape below, not another one)

1. **Inert by construction, not by convention.** The production bootstrap
   path (`application.py` → `factory.py` → `ToolRegistry`) is **not touched**
   in Tier 0. `WriteApiClient`/`PfSenseWriteClient` are never instantiated
   during real server startup — they exist only as tested library code. A
   bug in Tier 0 code cannot reach the live pfSense box because nothing in
   the running process ever constructs an object capable of a non-GET call.
2. **Two named chokepoints, not one relaxed one.** `RestApiClient` stays
   exactly as it is today — unconditionally GET-only, unmodified. A second,
   separate `WriteApiClient` is the *only other* place permitted to call
   `Transport.request()` with a non-GET method. `get_only_check.py`'s
   allow-list grows from one name to two, explicitly — the check's job
   shifts from "GET-only" to "only these two audited files touch the wire,"
   stated plainly in its own docstring.
3. **Allow-list before capability.** Mirroring `Endpoints`/
   `SUPPORTED_CAPABILITIES_THIS_BUILD`'s existing "explicit list, not
   inference" philosophy: a mutation is refused unless its endpoint is a
   `WriteEndpoints` entry. That registry ships **empty** in Tier 0 — so even
   if every other gate had a bug, every mutation attempt still refuses at
   the allow-list check. Static checker (`write_allow_list_check.py`) proves
   the registry is empty.
4. **Capability gate stays empty too, independently.** `Capability.
   FIREWALL_WRITE/ALIAS_WRITE/SERVICE_WRITE` already exist (unused
   placeholders) but are excluded from `SUPPORTED_CAPABILITIES_THIS_BUILD`
   and both `Profile`s today. Tier 0 changes **none** of `capabilities.py`
   or `profiles.py` — a second static checker
   (`write_capability_check.py`) proves this stays true, as an independent,
   redundant guard alongside principle 3.
5. **Snapshot-before-mutate, using the existing READ path.** A live mutation
   is refused without a fresh `RecoveryContract`, and a contract can only be
   created by capturing current state through the *existing*, already-
   verified `PfSenseClient` GET path — Tier 0 adds no new way to read
   pfSense, it reuses the one that's already accepted and frozen.
6. **Dry-run never touches the wire.** `WriteApiClient.dry_run()` performs
   zero non-GET network calls, by construction — it only reads current state
   (via the same GET path as principle 5) and computes a predicted diff
   in-process.

## 1. Final architecture

```
Transport (HttpTransport / MockTransport)          — UNCHANGED
    ↓                              ↓
RestApiClient (GET-only, unchanged)   WriteApiClient (NEW — 2nd chokepoint)
    ↓                              ↓
PfSenseClient (unchanged)          PfSenseWriteClient (NEW)
    ↓                              ↓            ↑ uses PfSenseClient for
ToolRegistry.register_all()  ToolRegistry.register_all_write()   snapshots
    (34 READ tools, unchanged)  (NEW extension point — registers
                                  nothing; no *_WRITE capability is
                                  ever active in this build)

Supporting, cross-cutting NEW modules (used only by the write path):
  write_endpoints.py   — WriteEndpoints allow-list (empty in Tier 0)
  write_types.py        — MutationPlan / DryRunResult / ExecutionResult /
                           RollbackResult / ContractStatus
  recovery.py            — RecoveryContract + RecoveryContractStore
  rollback.py             — RollbackPlan protocol + RollbackExecutor
  write_audit.py           — separate, structured write-audit log
```

`Application`/`factory.py`/`config.py` are **not modified** — see Design
Principle 1. `WriteApiClient` and `PfSenseWriteClient` are fully built and
unit-tested via `MockTransport`, but nothing in the real server process ever
constructs one in Tier 0.

## 2. Module responsibilities (summary — full per-module spec in §12)

| Layer | Module | Responsibility |
|---|---|---|
| Allow-list | `write_endpoints.py` | Single source of truth for which (path, HTTP method) pairs may ever be mutated. Empty in Tier 0. |
| Shared types | `write_types.py` | `MutationPlan`, `DryRunResult`, `ExecutionResult`, `RollbackResult`, `ContractStatus` — no behavior. |
| Chokepoint | `write_api_client.py` | The only module besides `rest_api_client.py` calling `Transport.request()`. Owns dry-run (zero network), execute (allow-list + contract checks, then the one real call), and its own request-level audit logging. |
| Recovery | `recovery.py` | `RecoveryContract` (immutable snapshot + rollback plan + TTL) and `RecoveryContractStore` (in-memory, expiring). |
| Rollback | `rollback.py` | `RollbackPlan` protocol; `RollbackExecutor` replays a contract's rollback plan and updates contract status. |
| Domain | `pfsense_write_client.py` | Semantic write layer mirroring `PfSenseClient`'s shape. Zero domain mutating methods in Tier 0 — only the generic `dry_run`/`prepare_recovery_contract`/`execute`/`rollback` plumbing. |
| Audit | `write_audit.py` | Separate structured (JSON-lines) audit log, distinct file from the existing plain-text server log, for every dry-run/execute/rollback event. |
| Registration | `tools/registry.py` (modified) | Adds `register_all_write()` — a documented, empty extension point called from `register_all()`. |
| Enforcement | `errors.py` (modified) | Adds `WriteNotAllowedError`. |
| Enforcement | `get_only_check.py` (modified) | Allow-list grows from `("rest_api_client.py",)` to `("rest_api_client.py", "write_api_client.py")`. |
| Enforcement | `write_allow_list_check.py` (new) | Proves `WriteEndpoints` has zero entries. |
| Enforcement | `write_capability_check.py` (new) | Proves no `*_WRITE` capability is in `SUPPORTED_CAPABILITIES_THIS_BUILD` or either `Profile`. |
| Refactor | `logging_setup.py` / `application.py` (modified) | `LOG_DIR` constant moves from `application.py` into `logging_setup.py` as `DEFAULT_LOG_DIR`, so `write_audit.py` can share it without a reverse import. Purely mechanical; no behavior change. |

## 3. Recovery Contract implementation

`recovery.py`:

```python
@dataclass(frozen=True)
class RecoveryContract:
    contract_id: str  # uuid4 hex
    capability: Capability
    endpoint_symbol: str  # a WriteEndpoints attribute name
    created_at_utc: datetime
    expires_at_utc: datetime  # short TTL, e.g. 5 minutes
    pre_state_snapshot: dict[str, Any]  # raw GET body, in-memory only
    rollback_plan: RollbackPlan
    status: ContractStatus  # OPEN / COMMITTED / ROLLED_BACK / EXPIRED
```

`RecoveryContractStore` (in-memory dict, no persistence — a snapshot is live
pfSense config data and must never be written to disk or logged in full,
consistent with `errors.py`'s existing "no raw response body" rule):
`create(capability, endpoint_symbol, snapshot, rollback_plan, ttl) ->
RecoveryContract`, `get(contract_id) -> RecoveryContract | None` (`None` if
missing/expired — expiry checked against `datetime.now(UTC)`, not a
background thread), `mark_committed(contract_id)`,
`mark_rolled_back(contract_id)`.

`PfSenseWriteClient.prepare_recovery_contract(plan)` is the only place a
contract is created: it calls straight into the existing `PfSenseClient` GET
method for the relevant resource to capture `pre_state_snapshot` — reusing
the already-accepted READ path rather than adding a second way to read
pfSense.

## 4. Write allow-list enforcement

`write_endpoints.py` mirrors `endpoints.py`'s `EndpointInfo`/`Endpoints`
shape exactly, with two additions relevant to mutation:

```python
@dataclass(frozen=True)
class WriteEndpointInfo:
    path_suffix: str
    http_method: str  # "POST" | "PUT" | "PATCH" | "DELETE"
    verified: bool  # same meaning as Endpoints.verified
    min_api_version: ApiVersion
    reversible: bool  # can RollbackExecutor act on this?
    dry_run_supported: bool  # must be True to ever be registered


class WriteEndpoints:
    """Empty in this build. Every future entry requires: independent
    live verification (verified=True, same bar as Endpoints), an
    explicit RollbackPlan if reversible=True, and dry_run_supported=True.
    scripts/write_allow_list_check.py enforces zero entries until Tier 1."""
```

`WriteApiClient.execute()` looks up `plan.endpoint_symbol` in
`WriteEndpoints`; if absent, raises `WriteNotAllowedError` before any
network call. `scripts/write_allow_list_check.py` (new, static, no network,
mirrors `get_only_check.py`'s style) parses `write_endpoints.py` via `ast`
and fails the build if any `WriteEndpointInfo(...)` instantiation exists
inside the `WriteEndpoints` class body — Tier 0's version of this script
asserts strictly zero.

## 5. Dry-run execution flow

```
caller → PfSenseWriteClient.dry_run(plan: MutationPlan) -> DryRunResult
           ↓
         WriteApiClient.dry_run(plan)
           1. plan.endpoint_symbol in WriteEndpoints?  (no → refused, done)
           2. plan.http_method matches the allow-listed entry's method?
           3. fetch current state via the injected PfSenseClient (a GET —
              never a mutating call)
           4. compute predicted_diff = current vs plan.payload (pure,
              in-process comparison)
           5. return DryRunResult(allowed, reasons, predicted_diff)
```

No step above ever calls `Transport.request()` with a non-GET method — dry
run is provably network-mutation-free by construction, not by convention.
`DryRunResult.allowed is False` for every plan in Tier 0, since step 1 always
fails (empty allow-list) — exercised directly by unit tests.

## 6. Rollback framework

`rollback.py`:

```python
class RollbackPlan(Protocol):
    def execute(self, write_client: "WriteApiClient") -> RollbackResult: ...

class RollbackExecutor:
    def rollback(self, contract: RecoveryContract, write_client: WriteApiClient) -> RollbackResult:
        # refuses unless contract.status == ContractStatus.COMMITTED
        # invokes contract.rollback_plan.execute(write_client)
        # updates the contract's status via RecoveryContractStore
```

Concrete `RollbackPlan` implementations are capability-specific and are
**not written in Tier 0** — each real write capability (Tier 1+) supplies
its own alongside its `WriteEndpoints` entry. Tier 0 tests this framework
exclusively against a synthetic, test-only `RollbackPlan` double defined in
`tests/test_rollback.py` — never a real pfSense-facing implementation.

## 7. Capability registration model

No changes to `capabilities.py` or `profiles.py` (Design Principle 4). One
small, additive change to `tools/registry.py`:

```python
def register_all(self) -> None:
    ...  # 34 existing read checks, byte-for-byte unchanged
    self.register_all_write()


def register_all_write(self) -> None:
    """Write-capability registration dispatch point. Empty in this
    build — no *_WRITE capability is ever present in self._capabilities
    (independently enforced by scripts/write_capability_check.py).
    Each future write capability adds one
    `if Capability.X_WRITE in self._capabilities: self._register_x_write()`
    branch here, mirroring register_all()'s existing per-capability
    dispatch pattern, under a separately authorized tier."""
```

`ToolRegistry.__init__` is unchanged (still takes only the read `client`) —
Tier 0 does not thread a write client through it, since nothing constructs
one in production (Design Principle 1). Tier 1 is what adds a `write_client`
parameter here, alongside the first real capability.

## 8. Logging and audit model

Two logs, kept structurally separate so write activity is trivially
greppable/alertable on independent of ordinary read traffic:

- **Existing** `pfsense-mcp-server.log` (`tools/audit.py`'s `audit_logged`,
  unchanged) — continues covering the 34 read tools exactly as today.
- **New** `pfsense-mcp-server-write-audit.log` (`write_audit.py`) — one JSON
  line per event: `write_dry_run_requested`, `write_dry_run_completed`,
  `write_recovery_contract_created`, `write_execution_requested`,
  `write_execution_committed`, `write_execution_failed`,
  `write_rollback_requested`, `write_rollback_completed`. Fields: `identity`,
  `capability`, `endpoint_symbol`, `contract_id`, `dry_run: bool`,
  `duration_ms`, `outcome`. **Never** includes `pre_state_snapshot` content or
  `payload` values — only the fact and shape of the event, consistent with
  `errors.py`'s existing "no raw response body" rule. Reuses the existing
  `SecretRedactionFilter` class (imported, not modified) on its own handler.
  `configure_write_audit_logging(log_dir, ...)` lives in `write_audit.py`
  itself (not `logging_setup.py`) so it stays unreachable/unused unless a
  future tier explicitly wires it into `Application._bootstrap()`.

## 9. Testing strategy

Follows existing conventions exactly: `MockTransport`-backed unit tests, no
new mocking library, JUnit-driven meta-checks via `validate_junit.py`,
static AST/regex checks for architectural invariants, opt-in live tests
gated by `PFSENSE_RUN_LIVE_TESTS`.

- **New `validate_junit.py` stage**: `write-infrastructure` — every testcase
  whose classname matches `test_write_*`/`test_recovery_contract`/
  `test_rollback` must be `passed` (mirrors the existing
  `endpoint-registry`/`profile-registration` stage pattern exactly).
- **`Makefile`**: `validate` grows from 13 → 16 stages (adds
  `write-infrastructure-check` [JUnit], `write-allow-list-check` [static],
  `write-capability-check` [static]); `quick` grows from 7 → 9 stages (adds
  the two static ones only, matching why `quick` already skips every
  JUnit-dependent stage today). All existing stage numbers/labels are
  renumbered mechanically; no existing stage's logic changes.
- Full per-module unit/integration test list is in §12.

## 10. Live verification strategy

Tier 0 adds **no** live-network write test that could ever mutate pfSense —
that would contradict "infrastructure only." Two things happen live:

1. **One new, genuinely safe live pytest**:
   `tests/test_live_write_allow_list_empty.py` (`pytest.mark.live`, same
   `PFSENSE_RUN_LIVE_TESTS` gate as every existing live test) — calls the
   *already-accepted* `pfsense_get_system_restapi_settings` READ tool and
   asserts pfSense's own API config still reports `read_only: true`. This
   directly reuses this session's own acceptance finding as an ongoing
   regression guard: even a bug in Tier 0's client-side gates would still be
   caught by pfSense refusing writes at its own API layer.
2. **A repeatable acceptance procedure**, structurally identical to the
   v0.1.0 acceptance just completed (fresh Claude Code process, fresh MCP
   subprocess started after it, enumerate `mcp__pfsense__*` tools): confirm
   the live tool count is still exactly **41** (unchanged) under the default
   `auditor` profile, confirm it is **0** under `engineer` profile (proving
   `EngineerProfile.capabilities` really is still empty end-to-end, not just
   in a unit test), and confirm every one of the 3 new static checks passes.
   This produces `docs/ACCEPTANCE_v0.2.0.md`, written the same way
   `ACCEPTANCE_v0.1.0.md` was — only after this passes does v0.2.0 get
   tagged.

## 11. Release plan from v0.2.0 onward

- **v0.2.0** = Tier 0 exactly as specified here: infrastructure present,
  fully tested, zero live-reachable mutating capability. Tagged only after
  the §10 acceptance procedure passes, mirroring the v0.1.0 rhythm from this
  session (implement → live-verify → checkpoint/acceptance doc → commit →
  tag → stop for approval before anything further).
- **v0.2.x** = patches to Tier-0 infrastructure only (bug fixes, no new
  capability surface, no new `WriteEndpoints` entry).
- **v0.3.0 (Tier 1)** = exactly **one** real write capability, named and
  explicitly authorized separately from this spec — requires a
  `WriteEndpoints` entry (`verified=True` only after independent live
  testing, same bar as `Endpoints`), a real `RollbackPlan`, a real
  `dry_run`/`execute` path wired into `ToolRegistry`/`factory.py`/
  `Application`, and its own acceptance record before tagging.
- **v0.4.0+** = one additional write capability per minor version, each
  independently authorized and accepted before tag — no two capabilities
  land in the same release without separate re-authorization for each,
  matching how READ capabilities were added one at a time in v0.1.0's
  history.

## 12. Complete file manifest

### New files

| File | Purpose | Public API | Dependencies | Unit tests | Integration tests |
|---|---|---|---|---|---|
| `src/pfsense_mcp/write_types.py` | Shared write-domain dataclasses/enums, no behavior | `MutationPlan`, `DryRunResult`, `ExecutionResult`, `RollbackResult`, `ContractStatus(Enum)` | `capabilities.Capability` | `tests/test_write_types.py` — construction/equality/immutability | — (pure data) |
| `src/pfsense_mcp/write_endpoints.py` | Mutation allow-list; empty in Tier 0 | `WriteEndpointInfo` (frozen dataclass), `WriteEndpoints` (empty container class) | `api_version.ApiVersion` | `tests/test_write_endpoints.py` — asserts `WriteEndpoints` has zero attributes of type `WriteEndpointInfo` | — |
| `src/pfsense_mcp/recovery.py` | Recovery Contract + in-memory expiring store | `RecoveryContract` (frozen dataclass), `RecoveryContractStore.{create,get,mark_committed,mark_rolled_back}` | `write_types`, `capabilities.Capability`, `rollback.RollbackPlan` | `tests/test_recovery_contract.py` — create/get/expiry/status transitions, snapshot never logged | `tests/test_write_integration_dry_run.py` (contract lifecycle inside a full dry-run→refuse flow) |
| `src/pfsense_mcp/rollback.py` | Rollback protocol + executor | `RollbackPlan(Protocol)`, `RollbackExecutor.rollback(contract, write_client)` | `write_types`, `recovery.RecoveryContract` | `tests/test_rollback.py` — refuses non-COMMITTED contracts, invokes a synthetic test-double plan, updates status | `tests/test_write_integration_dry_run.py` |
| `src/pfsense_mcp/write_api_client.py` | 2nd transport chokepoint: dry-run (network-free) + execute (allow-list + contract gated) | `WriteApiClient.__init__(transport, *, identity, api_version)`, `.dry_run(plan) -> DryRunResult`, `.execute(plan, contract) -> ExecutionResult` | `transport.base.Transport`, `write_endpoints.WriteEndpoints`, `write_types`, `recovery.RecoveryContract`, `errors.WriteNotAllowedError`, `api_version` | `tests/test_write_api_client.py` — refuses unknown endpoint (allow-list empty), refuses missing/expired/non-OPEN contract, dry-run never calls `transport.request` (assert on `MockTransport.calls`), method-mismatch refusal | `tests/test_write_integration_dry_run.py` |
| `src/pfsense_mcp/pfsense_write_client.py` | Domain-semantic write layer; zero domain mutating methods in Tier 0 | `PfSenseWriteClient.__init__(write_rest_client, read_client)`, `.dry_run(plan)`, `.prepare_recovery_contract(plan) -> RecoveryContract`, `.execute(plan, contract, *, confirm: bool)`, `.rollback(contract)` | `write_api_client.WriteApiClient`, `pfsense_client.PfSenseClient`, `recovery`, `rollback` | `tests/test_pfsense_write_client.py` — `confirm=False` always refuses, contract snapshot sourced from injected `PfSenseClient` | `tests/test_write_integration_dry_run.py` |
| `src/pfsense_mcp/write_audit.py` | Separate structured (JSON-lines) write-audit log | `configure_write_audit_logging(log_dir, *, max_bytes, backup_count) -> SecretRedactionFilter`, `write_audit_logged(event_name, identity) -> decorator` | `logging_setup.SecretRedactionFilter`, `logging_setup.DEFAULT_LOG_DIR` | `tests/test_write_audit.py` — JSON-line shape, snapshot/payload never present in a logged line, redaction filter applied | — |
| `scripts/write_allow_list_check.py` | Static: `WriteEndpoints` has zero entries | `find_write_endpoint_entries() -> list[str]`, `main() -> int` | `ast` (stdlib) | `tests/test_write_allow_list_check.py` (mirrors `test_get_only_check.py`'s structure) | — |
| `scripts/write_capability_check.py` | Static: no `*_WRITE` capability active anywhere | `find_active_write_capabilities() -> list[str]`, `main() -> int` | `pfsense_mcp.capabilities`, `pfsense_mcp.profiles` | `tests/test_write_capability_check.py` | — |
| `docs/WRITE_TIER0_SPEC.md` | Committed copy of this approved spec, for repo-native reference | — (doc) | — | — | — |

### Modified files

| File | Change | Why |
|---|---|---|
| `src/pfsense_mcp/errors.py` | Add `WriteNotAllowedError(PfSenseMCPError)` | Refusal reason for allow-list/contract failures in `WriteApiClient` |
| `src/pfsense_mcp/tools/registry.py` | Add empty `register_all_write()`, call it from `register_all()` | Documented, tested, currently-inert extension point (§7) |
| `src/pfsense_mcp/logging_setup.py` | Add `DEFAULT_LOG_DIR` constant (the same path `application.py` already computes) | Lets `write_audit.py` share the log-directory convention without importing `application.py` |
| `src/pfsense_mcp/application.py` | Replace local `LOG_DIR = Path.home() / ...` literal with `from .logging_setup import DEFAULT_LOG_DIR as LOG_DIR` | Mechanical; value and behavior unchanged, existing tests unaffected |
| `scripts/get_only_check.py` | `_ALLOWED_CALLER: str` → `_ALLOWED_CALLERS: tuple[str, ...] = ("rest_api_client.py", "write_api_client.py")`; docstring updated to state the invariant is now "only these two named, audited files call `Transport.request()`" | The one deliberate relaxation Tier 0 requires (Design Principle 2) — everything else about the check (regex, "exactly these callers, no others, and each must appear at least once") stays the same |
| `Makefile` | Insert `write-infrastructure-check`, `write-allow-list-check`, `write-capability-check` into `validate` (13→16 stages) and the latter two into `quick` (7→9 stages); renumber existing stage labels; update `.PHONY` | New enforcement needs a place in the existing gate structure |
| `scripts/validate_junit.py` | Add `--stage write-infrastructure` branch (same pattern as `endpoint-registry`/`profile-registration`) | Proves the new unit tests actually ran and passed, not just that the scripts exist |
| `tests/test_get_only_check.py` | Extend existing assertions for the new two-caller allow-list | Keeps the existing meta-test honest about the changed invariant |
| `README.md` | `## Status` line updated once v0.2.0 is accepted (not before) | Same pattern as the v0.1.0 closeout — status pointer only, no duplicated detail |

### Explicitly unchanged (stated for the record, per Design Principles 1 & 4)

`capabilities.py`, `profiles.py`, `factory.py`, `config.py`,
`rest_api_client.py`, `pfsense_client.py`, `endpoints.py`, `tools/audit.py`,
`transport/*.py`, `tools/write/__init__.py`, `tools_write_check.py`,
`bounded_params_check.py`, `docs/READ_BACKLOG.md`.

### New test files (full list, for §9)

`tests/test_write_types.py`, `tests/test_write_endpoints.py`,
`tests/test_recovery_contract.py`, `tests/test_rollback.py`,
`tests/test_write_api_client.py`, `tests/test_pfsense_write_client.py`,
`tests/test_write_audit.py`, `tests/test_tool_registry_write.py` (asserts
`register_all_write()` registers nothing, for both `AuditorProfile` and
`EngineerProfile`, reusing the existing fake-MCP test double already present
in `tests/test_tool_registry.py`), `tests/test_write_allow_list_check.py`,
`tests/test_write_capability_check.py`,
`tests/test_write_integration_dry_run.py` (integration: full
`PfSenseWriteClient` → `WriteApiClient` → `RecoveryContractStore` →
`RollbackExecutor` flow against `MockTransport`, using one synthetic
test-only `MutationPlan`/`RollbackPlan` pair defined in the test file itself
— never a real endpoint), `tests/test_live_write_allow_list_empty.py`
(live, §10).

## Verification (once implementation is authorized)

1. `make validate` passes 16/16 stages (including all 3 new ones).
2. `make quick` passes 9/9 stages.
3. `PFSENSE_RUN_LIVE_TESTS=true pytest -m live` passes, including the new
   `test_live_write_allow_list_empty.py`.
4. Fresh-process acceptance procedure per §10: exactly 41 tools under
   `auditor`, exactly 0 under `engineer`, both confirmed live.
5. `docs/ACCEPTANCE_v0.2.0.md` written and reviewed before tagging `v0.2.0`.
6. Manual read-through confirms zero references to a real pfSense mutating
   endpoint exist anywhere in the diff (i.e. `WriteEndpoints` is still
   empty, `tools/write/` is still empty and unimported).
