# ADR-033: pfSense least-privilege bootstrap architecture (setup-wizard phase)

- **Status:** §§1-2 (privilege derivation and drift detection) and §5
  (transaction state model) are **implemented** as of Phase B
  (2026-08-17) -- see "Implementation Phase B" below. The actual HTTP
  provisioning sequence (§3's read-before-write/partial-failure model,
  §9's operation list) is **implemented, offline-tested only**, as of
  Phase C (2026-08-17) -- see "Implementation Phase C" below. §4
  (`doctor` integration) remains research/design only -- `doctor` and
  `bootstrap` remain deliberately separate subsystems. A later,
  explicitly owner-authorized Phase D LAB exercise partially executed
  and left the recovery state documented below; it created no standing
  live authority. CLI/runtime integration Slices 1-3 (durable operation
  journal, fixed administrative composition, and journal-aware locking
  orchestration + the `pfsense-mcp-security bootstrap` subcommand) are
  **implemented, offline-verified only**, as of 2026-08-23 -- see "CLI/
  runtime integration Slice 3" below. **No current phase authorizes a
  live bootstrap run against any real pfSense appliance (LAB or
  production), any `pfsense-mcp-security setup` subcommand (not yet
  implemented), or wiring this engine into normal application
  startup/MCP tool registration.** Owner-authorized 2026-08-17 (initial
  research pass), 2026-08-17 (Phase B), 2026-08-17 (Phase C), and
  2026-08-23 (CLI Integration Slice 3), each explicitly scoped, each
  gating a later, separately-authorized implementation phase.
- **Scope:** Establishes the exact current minimum privilege
  requirements (READ and existing WRITE), the authoritative derivation
  mechanism, and the proposed bootstrap security/rollback model. Does
  not modify `pfsense-mcp-security doctor`, Tier 1, or `ADR-031`'s
  backend/target identity boundary in any way.

## Implementation Phase B (2026-08-17)

Owner-authorized as "privilege derivation and drift detection only" --
explicitly excluding pfSense user creation, privilege mutation,
API-key creation, and any other provisioning action. Implements §§1-2
and §5 below as real, tested, pure production code:

- **`src/pfsense_mcp/security_privileges.py`** (new): `compute_privilege_from_url()`
  (the pure `get_method_priv_name()` reimplementation), `lookup_schema_privileges()`/
  `resolve_privilege()` (the fail-closed schema+source combination §2/§3
  describe), `read_profile_requirements()`/`write_protected_profile_requirements()`
  (derived mechanically from `tools/read/*.py`'s own source via the same
  AST technique `scripts/public_contract.py` already uses, plus
  `WriteEndpoints.active_entries()` -- never a hand-maintained tool
  list), `compute_account_drift()`/`check_package_version_support()`
  (the §4 drift model, with the three evidence classes
  `SCHEMA_DERIVED`/`SOURCE_CROSS_CHECKED`/`ACCOUNT_OBSERVED` this ADR's
  own "clearly distinguish evidence classes" requirement named). No
  network access anywhere in this module -- every function takes an
  already-fetched schema dict; none fetches one.
- **`src/pfsense_mcp/security_bootstrap_transaction.py`** (new): the §5
  transaction state model -- `BootstrapState`'s six-state lifecycle,
  `allowed_next_states()`/`is_legal_transition()` as the one source of
  truth for legal transitions, and `check_invariants()` enforcing the
  one invariant this phase was explicitly asked to make explicit: the
  temporary `api-v2-auth-key-post` bootstrap privilege must never be
  present once a transaction reaches `BOOTSTRAP_PRIVILEGE_REVOKED`/
  `VERIFIED`. No HTTP operations, no pfSense contact -- a pure state
  container an eventual, separately-authorized implementation would
  drive.
- **Regression-verified against real evidence**: both the 41-privilege
  READ set and the 42-privilege `write_protected` set this document's
  §1 states are reproduced exactly by the new code, cross-checked
  against `tests/fixtures/pfsense_openapi_schema_trimmed.json` -- a
  real, trimmed (42-path) subset of the actual live schema captured
  during `ADR-026`'s provisioning work, not synthetic data.
- **77 new tests** (`tests/test_security_privileges.py`,
  `tests/test_security_bootstrap_transaction.py`,
  `tests/test_security_privileges_isolation.py`) covering every case
  §7's requirement list named: known-good schema, missing/malformed/
  ambiguous/duplicate privilege metadata, endpoint/method mismatch,
  schema/source agreement and disagreement, supported and unsupported
  package versions, missing/unexpected/exact account-privilege drift,
  multiple simultaneous findings, deterministic ordering, and every
  transaction-state invariant.
- **Not wired into `security_cli.py` or `security_doctor.py`** --
  proven by a dedicated isolation test, not merely by omission. §6's
  `doctor`-integration candidates remain undone, exactly as this
  phase's own scope required.

## Implementation Phase C (2026-08-17)

Owner-authorized as "isolated provisioning engine, offline-tested
only" -- authorizing production HTTP provisioning code for the first
time, explicitly **not** authorizing live provisioning against any
appliance and explicitly forbidding CLI/runtime wiring. Composes Phase
B's primitives with a new, narrow HTTP surface:

- **`src/pfsense_mcp/security_bootstrap_client.py`** (new): the third
  module (alongside `rest_api_client.py`/`write_api_client.py`) ever
  permitted to call a `Transport`'s `request()` directly
  (`scripts/get_only_check.py`'s allow-list updated accordingly).
  Exposes exactly four named operations, no generic dispatch:
  `list_users()` (`GET /api/v2/users`), `create_user()`
  (`POST /api/v2/user`), `update_user_privileges()`
  (`PATCH /api/v2/user`, full-replace semantics), `create_auth_key()`
  (`POST /api/v2/auth/key`, must be called on a Transport authenticated
  as the target account itself). **Payload/response shapes are not
  guessed** -- transcribed directly from the real, already-executed,
  already-authorized live provisioning procedure `ADR-026`'s
  acceptance-matrix work performed (2026-08-16, the
  `pfsense_mcp_tier1_lab` identity's creation/key-generation/privilege
  grant-revoke sequence). The returned `ProvisionedApiKey`'s secret is
  reachable only via an explicit `reveal()` method -- never present in
  `repr()`/`str()`/an ordinary exception message.
- **`src/pfsense_mcp/security_bootstrap_engine.py`** (new):
  `provision_service_account()`, the orchestrator. Read-before-write
  throughout: every mutation is preceded by an observation and followed
  by an independent re-read that confirms it (never trusts a mutating
  call's own response echo). Derivation gate is **stricter** than
  `doctor`'s advisory `DriftReport.clean` posture -- a missing schema,
  any privilege not reaching `SOURCE_CROSS_CHECKED` confidence, or an
  unsupported package version refuses the whole attempt before any HTTP
  call. Three top-level paths: (1) account absent → full transaction
  sequence (`NOT_STARTED → USER_CREATED → BOOTSTRAP_PRIVILEGE_GRANTED →
  KEY_GENERATED → BOOTSTRAP_PRIVILEGE_REVOKED → VERIFIED`, driven
  through `security_bootstrap_transaction.py`'s state machine exactly);
  (2) account present and already exactly correct → no-op
  (`ALREADY_SATISFIED`, mirroring `security_plan.py`'s `NO_CHANGE`
  pattern); (3) account present but missing some expected privileges →
  additive-only sync (adds exactly the missing privileges, never
  touches an unrelated extra privilege already present, never
  re-creates or re-keys the account). An account already holding the
  temporary bootstrap privilege is treated as evidence of an
  interrupted prior run and is refused (`BLOCKED_EXISTING_PARTIAL`) --
  no automatic resume, matching §"Rollback/recovery"'s stated
  discipline.
- **No automatic compensating mutation on failure** -- if API-key
  creation fails after the bootstrap privilege was already granted, or
  revocation itself fails after a key was already issued, the engine
  does not attempt to auto-revoke or auto-clean-up; it returns a
  `FAILED` outcome whose `BootstrapTransaction.failure_detail` names
  exactly which step failed and states plainly that the temporary
  privilege is still present and requires manual/operator-reviewed
  remediation.
- **Self-service authentication is caller-supplied.** Phase C initially
  had no Basic-Auth-capable `Transport`. A later offline implementation
  added `transport/http.py`'s deliberately single-use
  `BasicAuthHttpTransport`: HTTPS/TLS-verification-only, no redirect or
  retry, strict credential validation, automatic client disposal after
  one attempt, and no X-API-Key fallback. `provision_service_account()`
  still takes a
  `self_service_transport_factory(username, password) -> Transport`
  parameter rather than building one itself. Offline integration tests
  bind the new transport at that existing seam; no CLI/application
  runtime path does. Selecting the real target/TLS configuration and
  invoking it live remain future, separately-authorized work.
- **CLI/runtime isolation, proven mechanically**: neither new module is
  referenced by `server.py`, `application.py`, `factory.py`,
  `security_cli.py`, `security_doctor.py`, or any file under
  `tools/read/` -- a dedicated isolation test
  (`tests/test_security_bootstrap_engine_isolation.py`) asserts this by
  direct source inspection, not by omission. The only way to invoke
  `provision_service_account()` in this build is a direct Python
  import.
- **45 new tests** (`tests/test_security_bootstrap_client.py`,
  `tests/test_security_bootstrap_engine.py`,
  `tests/test_security_bootstrap_engine_isolation.py`) covering every
  case requirement 10 named: already-correct account, account absent,
  wrong/missing expected privileges, unrelated additional privileges
  preserved, both target profiles, unsupported package version,
  schema/source disagreement, malformed evidence, each of the four
  named HTTP operations, account-creation/privilege-update/API-key-
  creation/revocation/final-verification failure at its own named
  checkpoint, partial-state reporting, retry/re-entry/idempotency,
  API-key secret redaction, no temporary privilege in the successful
  steady state, and no Tier 1 interaction. Full suite: 3032 → 3077.
- **Zero live pfSense calls made or possible in this build** -- neither
  new module imports `httpx`/`requests`/`socket`/`urllib` (isolation
  test); every test drives an in-memory fake `Transport`.

### Offline Phase D prerequisite closure (2026-08-19)

No live phase was started. The existing `PFSENSE_API_KEY_FILE` reader
now has a matching `config.store_api_key()` custody primitive:
exclusive non-following creation, mode `0600`, complete write + fsync,
descriptor-bound reread verification, failure cleanup, and no secret in
errors. It remains unwired from CLI/runtime/bootstrap execution.

`PRIVILEGES_SYNCED` now means that an authoritative final pre-PATCH
snapshot was taken, the same enabled account remained selected, every
required privilege was observed after PATCH, and every privilege in
that final snapshot remained present. The API supplies no revision/CAS
primitive; the result therefore requires an exclusive administrative
window and does not claim to eliminate the residual read-to-PATCH
TOCTOU interval. The future controlled procedure and interruption
handling are fixed in
[`ADR033_PHASE_D_LAB_RUNBOOK.md`](../ADR033_PHASE_D_LAB_RUNBOOK.md).
Cross-process bootstrap persistence remains deliberately deferred for
the first supervised one-shot LAB exercise.

## Summary

This project's Tier 1 architecture and its one live-verified WRITE
capability already prove least-privilege pfSense credentials work in
practice — a scoped identity with exactly 4 privileges executed two
real mutations against a disposable LAB appliance
([ADR-026](ADR-026-first-write-capability-adapter.md)). What has never
existed is a **general, evidence-backed answer** to "what is the
minimum privilege set for *any* current configuration of this
project, and how would an operator safely reach it" — the WRITE
matrix was derived once, by hand, for one capability. This ADR
produces that general answer for the full 42-tool READ surface plus
the existing WRITE capability, and designs (without implementing) how
a future bootstrap operation would apply it safely.

## 1. Current privilege requirements (evidence, not design)

Full matrix, methodology, and live cross-validation:
[`PFSENSE_LEAST_PRIVILEGE_MATRIX.md`](../PFSENSE_LEAST_PRIVILEGE_MATRIX.md).
Summary:

- **A. Default READ-only operation**: 41 distinct privileges, one per
  tool (41 of the 42 registered tools call exactly one pfSense
  endpoint each; the 42nd, `pfsense_mcp_info`, needs none). Zero
  overlap between tools — each privilege is used by exactly one tool.
- **B. Existing WRITE capability** (`set_firewall_alias_description_v1`):
  4 privileges, re-derived independently this pass and found
  **unchanged** from ADR-026's live-provisioned values — 3 of the 4
  overlap with the READ set (`firewall-aliases-get`,
  `status-system-get`, `system-hasync-get`); only
  `api-v2-firewall-alias-patch` is WRITE-exclusive. Combined
  READ+WRITE minimum: 42 distinct privileges.
- **C. Setup/bootstrap-only privileges**: exactly one, already
  discovered and live-tested during ADR-026's own provisioning:
  `api-v2-auth-key-post` — required only because pfSense's REST API
  key model (`RESTAPIKey`, confirmed from source) hardcodes
  self-service key generation (`username = $this->client->username`),
  so a brand-new identity cannot obtain its first API key without
  briefly holding this one privilege. Confirmed **temporary and
  revocable without invalidating the already-issued key** (live-tested
  in ADR-026: the scoped credential kept working after this privilege
  was revoked).

**Do not assume previously documented privilege IDs remain correct**
was honored literally: every value above was independently re-derived
from the pinned package source and independently re-cross-checked
against a real captured live OpenAPI schema this pass, not copied
forward from ADR-026's prose. All matched.

## 2. Derivation mechanism (evidence, not design)

Full detail in the matrix document's "Method" section. Summary:

- **Source**: `pfrest/pfSense-pkg-RESTAPI`'s `Core/Endpoint.inc::get_method_priv_name()` —
  a deterministic slug of the endpoint's URL plus lowercase HTTP
  method (`/` and `_` → `-`, strip leading `-`).
- **Version stability**: confirmed **byte-identical** across `v2.7.7`
  through `v2.10.0` (the current latest tag) — the algorithm has never
  changed in this project's observed history. This is evidence, not a
  guarantee for all future versions; see "Detecting privilege drift"
  below for how a future implementation should treat this.
- **A materially better live-verification path than re-deriving from
  GitHub each time was found this pass**: the installed package's own
  `Schemas/OpenAPISchema.inc` embeds every operation's exact allowed
  privileges directly in the live OpenAPI schema's `description` text
  (`"**Allowed privileges**: [ page-all, api-v2-status-system-get ]"`).
  This project already fetches this schema for endpoint-catalogue
  purposes — a future implementation should **parse this live text as
  the primary, always-current source**, falling back to (or
  cross-checking against) the pinned-source algorithm only for
  privileges not yet observable live (e.g. planning a *new* capability
  against a target appliance version not yet running).
- **Ambiguous/renamed/missing detection**: an endpoint whose privilege
  string cannot be found in a freshly-fetched live schema, or whose
  live schema value disagrees with the pinned-source-derived value,
  must be treated as **unresolved, not assumed** — see "Detecting
  privilege drift" below.
- **`requires_page_all_privilege`**: 1 of 268 endpoints package-wide
  hard-codes `page-all` as the only accepted privilege (a POST-only
  sync action this project doesn't use). None of the 41 READ
  privileges or 4 WRITE privileges require it — reconfirmed this pass,
  not assumed from ADR-026. A future implementation adding any *new*
  capability must re-check this per endpoint; it is not a general
  guarantee.
- **Modifies nothing**: every fetch this pass was a plain HTTPS GET
  against public GitHub source/tags, or a read of an already-locally-cached
  live schema snapshot from a prior, separately-authorized session. No
  installed package file was touched.

## 3. Bootstrap security model (design, not implemented)

### Existing user vs. dedicated service account

**Always a dedicated service account, never the operator's own admin
account or an existing shared account.** ADR-026's own live evidence
already proves this pattern works end-to-end; nothing here changes it.
A future bootstrap flow must refuse to proceed against an account it
did not itself create and cannot uniquely identify as
project-dedicated (e.g. by a recognizable, configurable username
prefix/convention), to avoid silently altering an unrelated existing
account's privileges.

### READ-only vs. write_protected profile

Directly follows §1: a `read_only`-profile deployment needs the 41 READ
privileges only; a `write_protected`-profile deployment needs the
combined 42. **The bootstrap flow must ask which profile the operator
is provisioning for and grant exactly that profile's set — never both
"just in case," never the WRITE set for a `read_only` deployment.**

### Setup-specific elevated privileges are temporary, not incidental

The one known case (`api-v2-auth-key-post`) must be modeled as a named,
temporary, always-revoked-before-completion state in any future
transaction design — not simply "one more privilege in the initial
grant that happens to also get removed later." A bootstrap operation
that crashes or is interrupted after granting this privilege but
before revoking it must leave that fact **visibly reported**, not
silently forgotten (see "Partial failure" below).

### Preventing privilege escalation

- The bootstrap identity that *performs* provisioning (the operator's
  existing admin credential, used once, interactively, never stored)
  is categorically different from the *provisioned* identity being
  created — the design must never let the provisioned identity grant
  privileges to itself or any other account. `POST /api/v2/user` and
  `PATCH /api/v2/user` both require an authenticated admin-equivalent
  caller in this package's model; the provisioned scoped identity is
  never used to call them.
- A future bootstrap must **compute the exact target privilege set
  from §1's matrix (or its live-schema equivalent) and grant exactly
  that set** — never a broader named pfSense role, never `page-all`,
  never an administrative group, regardless of how convenient that
  would be to implement.

### Preserving existing unrelated privileges

If a bootstrap operation ever *modifies* (rather than creates) an
account — e.g. re-running setup after the tool's own privilege
requirements grew — it must **read the account's current full
privilege list first, compute the minimal additive diff, and apply
only that diff**, exactly mirroring ADR-026's own live-executed
pattern (`PATCH /api/v2/user` with the full desired list, always
preceded by an independent `GET /api/v2/users` read, always followed
by an independent re-read to confirm, never trusting the PATCH
response's own echo). Never assume an account decided to be
project-dedicated has *no* other privileges — verify before touching.

### Privilege removal should never be automatic (except the one named bootstrap case)

Beyond revoking the temporary `api-v2-auth-key-post` bootstrap
privilege (a `pfsense-mcp-server`-added privilege being removed by the
same operation that added it, on the same run), **no future bootstrap
operation should ever remove a privilege automatically** — including
privileges that appear to have become unused after a downgrade (e.g.
`read_only` → nothing, or a future narrower READ tool set). Detected
"privileges wider than currently needed" should be **reported**
(a `doctor`-style finding — see §6), never silently pruned; removal
is always an explicit, separate, owner-reviewed action.

### Idempotency

Re-running bootstrap against an already-correctly-provisioned identity
must be a no-op that reports "already satisfied" — mirroring
`security_plan.py`'s own established `AxisTransitionKind.NO_CHANGE`
pattern exactly, not a new concept. Re-running against a
*partially*-provisioned identity (see next) must resume/complete
safely, never duplicate a step already done (e.g. never attempt to
create a user that already exists; detect and continue).

### Partial failure

Every step of a future bootstrap transaction must be independently
observable and re-verifiable by a fresh read — matching ADR-026's own
executed discipline (never trust an API response's own echo; always
follow with a separate read). A future design should define an
explicit small state sequence for the transaction itself (e.g.
`NOT_STARTED → USER_CREATED → BOOTSTRAP_PRIVILEGE_GRANTED →
KEY_GENERATED → BOOTSTRAP_PRIVILEGE_REVOKED → VERIFIED`), persisted
locally (not on the appliance) so a crash mid-sequence can be resumed
or reported precisely — never guessed at from scratch.

### Rollback/recovery

If a bootstrap operation fails partway, the safe default is **leave
the partial state in place and report it precisely** (which step
completed, which didn't) rather than attempting automatic rollback —
an automatic "undo" that itself fails partway is a worse state than a
clearly-reported partial success. Full teardown (deleting the created
account) should be an explicit, separate, operator-confirmed action,
never automatic.

### Re-running setup after package upgrades

Directly enabled by §2's live-schema-first derivation strategy: if a
future package version renames or restructures an endpoint, its
privilege string changes, and re-running bootstrap against the new
live schema naturally picks up the new name — **as long as the design
re-fetches the live schema each run rather than caching a privilege
list from install time.** A cached list must always be re-validated
against a fresh live fetch before being trusted for a new bootstrap
run.

### Detecting privilege drift

Three independent signals, all read-only:

1. Live schema's own "Allowed privileges" text disagreeing with what
   this project's matrix expects for a given endpoint.
2. A provisioned identity's actual `priv` list (from `GET
   /api/v2/users`) disagreeing with what this project's matrix says it
   should hold — either broader (scope creep, possibly from manual GUI
   changes) or narrower (accidental revocation, possibly breaking the
   deployment).
3. The installed REST API package's reported version (already visible
   via the live OpenAPI schema's own version field, or
   `pfsense_get_system_packages`) falling outside the range this
   project has verified the algorithm against (`v2.7.7`–`v2.10.0`).

All three map directly to future `doctor` checks — see §6.

## 4. Credential handling

- **No new secret store.** This project already has an established
  pattern (`PFSENSE_API_KEY_FILE`, mode-600, exclusive-create,
  descriptor-bound loading — the existing "Preserve descriptor-bound
  API-key loading as a security invariant" roadmap commitment). A
  future bootstrap must write the newly-generated scoped identity's
  API key through this exact same mechanism, never a second one.
- **No credential is ever logged, printed, or embedded in an
  exception/evidence string** — matching `security_discovery.py`'s and
  `security_doctor.py`'s already-audited discipline for this class of
  problem.
- **The bootstrap-performing admin credential is never persisted by
  this tool** — supplied interactively for the duration of the
  bootstrap operation only (matching how the actual ADR-026
  provisioning was performed: the admin `X-API-Key` was used directly
  by the owner's own session, never written to a file this project
  manages).
- **The provisioned identity's password field** (required by pfSense's
  user model even for API-key-only use, per ADR-026's own finding)
  should be a randomly generated value, held only transiently in
  memory for the duration of account creation, never written to disk
  at all — not even temporarily. (ADR-026's live procedure used a
  mode-600 scratch file for this and deleted it afterward; a future
  implementation should improve on this by never touching disk for
  the password at all, since the API key — not the password — is the
  credential this project actually uses afterward.)

The output half of this design is now implemented offline by
`config.store_api_key()`: the configured `PFSENSE_API_KEY_FILE` is
created exclusively through a non-following parent descriptor, forced
to mode `0600`, completely written and fsynced, verified through the
existing descriptor-bound loader, and removed on a safely attributable
failure. It remains intentionally unwired from bootstrap, CLI, and
runtime paths.

## 5. Relationship to `ADR-021`'s two-axis model

Privilege assignment follows **capability requirements** (§1), never
anchor assurance:

| Preset | Capability posture | Anchor assurance | pfSense privilege set |
|---|---|---|---|
| READ-only | `read_only` | `none` | 41 READ privileges |
| Software-protected WRITE | `write_protected` | `software` | 42 (READ+WRITE) — **identical to hardware-witness WRITE below**; the anchor backend affects how the *mutation is authorized*, never which pfSense privileges the identity holds |
| Hardened hardware-witness WRITE | `write_protected` | `hardware_witness` | 42 (READ+WRITE) — this is what ADR-026 actually live-tested |

**Stronger anchor assurance must never be treated as license for
broader pfSense privileges.** The TPM witness protects the integrity
of this project's own `RecoveryContract` store against rollback; it
says nothing about, and must never be conflated with, what the
pfSense-side identity is permitted to do. A `hardware_witness`
deployment and a (currently unimplemented) `software`-anchor
deployment need the *exact same* pfSense privilege set for the same
capability posture — the two axes are independent by `ADR-021`'s own
design, and this ADR's privilege model must not quietly break that
independence.

## 6. `doctor` integration opportunities (not implemented this phase)

Four candidate future `pfsense-mcp-security doctor` checks, all
READ-only, all directly justified by §3's "Detecting privilege drift":

1. **Installed REST API package/version detected** — read
   `pfsense_get_system_packages`'s existing data (or the live OpenAPI
   schema's own version field) and report whether it falls within the
   algorithm-verified range (`v2.7.7`–`v2.10.0`), flagging (not
   failing) an out-of-range version as "unverified, re-confirm before
   relying on the derived privilege set."
2. **Required privilege definitions found** — for a given target
   profile (READ-only or write_protected), fetch the live OpenAPI
   schema and confirm every required privilege string actually appears
   in some operation's "Allowed privileges" text; report any that
   don't (renamed/removed upstream).
3. **Configured service account has expected privileges** — given a
   configured identity, `GET /api/v2/users`, compare its actual `priv`
   list against the exact expected set for the configured profile;
   report both over-grant and under-grant.
4. **Privilege drift detected** — the combination of 1–3: a single
   `doctor` verdict distinguishing "matches expected exactly," "broader
   than expected" (flag, never auto-narrow), and "narrower than
   expected" (flag, explains why the deployment may be failing).

**Not implemented this phase.** All four require either a live pfSense
connection (`doctor` today is 100% local-filesystem/witness-only, by
design — see `ADR-033`'s own §"Safety constraints" below and
`security_doctor.py`'s existing "known limitation" note) or new,
not-yet-reviewed code to call `GET /api/v2/users`/parse the OpenAPI
schema. Adding either is exactly the kind of change this ADR's own
"do not expand `doctor` in this phase unless independently justified"
instruction was written to gate — correctly deferred to the
implementation phase this ADR is itself gating.

## 7. Safety constraints (binding on any future implementation)

The eventual bootstrap design must not:

- Grant administrator-equivalent (`page-all` or any admin group)
  access merely for convenience — §1/§3 establish that the narrow
  privilege set is sufficient and sufficient is what must be granted.
- Silently broaden privileges on re-run — §3's idempotency/drift
  sections require any broadening to be an explicit, reported,
  operator-confirmed action.
- Remove unrelated existing privileges — §3's "preserving existing
  unrelated privileges" requires reading before writing, always.
- Derive permissions from untrusted remote text — §2's derivation
  sources are exactly two: pinned package source at a specific tag,
  and the live OpenAPI schema **of the appliance being provisioned
  itself** (not a third party's report of what it should be).
- Bypass WRITE authorization — nothing in this ADR touches Tier 1's
  authorization/confirmation/execution chain; pfSense privilege
  provisioning and Tier 1's cryptographic authorization remain
  independent layers (see next bullet).
- Make WRITE default-reachable — bootstrap provisions a pfSense-side
  identity only; it has no relationship to, and cannot change,
  `WriteEndpoints`/`Capability`/profile gating, which remain the only
  things that make a WRITE tool reachable at all.
- Weaken Tier 1 — zero files under `tier1/` are touched by this ADR or
  would be touched by implementing it; pfSense privilege provisioning
  is entirely orthogonal to the `RecoveryContract`/authorization chain.
- Conflate pfSense RBAC with this project's cryptographic authorization
  boundary — **stated explicitly, as required**: a pfSense privilege
  answers "can this API credential technically call this endpoint,"
  which is necessary but nowhere near sufficient for a mutation to
  actually happen in this project — the full Tier 1 chain (plan →
  authorization → `RecoveryContract` → confirmation → sealed
  execution) is the layer that decides whether a *specific* mutation is
  *authorized*, entirely independent of what the underlying pfSense
  credential is technically capable of. These are two independent
  defense layers by design, not one system with two names.

## 8. Evidence

In preference order, as required:

1. **Installed REST API package source** — `Core/Endpoint.inc`
   (`get_method_priv_name()`, `get_default_privs()`,
   `requires_page_all_privilege`), `Core/Auth.inc` (`array_intersect()`
   ANY-match), `Schemas/OpenAPISchema.inc` (live-schema privilege
   embedding), `Caches/PrivilegesCache.inc` (confirms pfSense's own
   `/etc/inc/priv/restapi.priv.inc` generation mechanism — noted as a
   possible future on-appliance derivation source if this project ever
   gains local file-read access to the appliance; not usable today).
   All fetched from `pfrest/pfSense-pkg-RESTAPI` at the pinned tag
   `v2.10.0` (confirmed the current latest tag) plus `v2.7.7` for the
   stability cross-check.
2. **Authoritative upstream documentation** — none consulted beyond
   source directly, per this project's own established preference for
   source over prose wherever both exist.
3. **Existing independently verified LAB evidence** — the previously
   captured live OpenAPI schema (`pfsense_openapi_schema.json`, fetched
   during the ADR-026 provisioning work) used to cross-validate all 42
   READ privileges plus the WRITE and bootstrap privileges against a
   real running appliance, not merely computed values.

No privilege semantics in this document were guessed. Where evidence
was insufficient (the exact minimum-privilege guarantee for any *future*
package version beyond `v2.10.0`), this document says so explicitly
(§2, §3) rather than extrapolating.

## 9. Proposed CLI/user flow (illustrative, not committed)

Sketch only — exact naming/flags are a future implementation decision,
not fixed here:

```
$ pfsense-mcp-security bootstrap --profile write_protected --dry-run
[reads live OpenAPI schema; computes exact 42-privilege target set]
[prompts for admin credential, interactively, never stored]
[reports the exact proposed user/privilege grant; performs nothing]

$ pfsense-mcp-security bootstrap --profile write_protected
[same, but actually executes: create user -> grant 42 + bootstrap priv
 -> generate key -> revoke bootstrap priv -> verify final state]
[writes the resulting API key through the existing PFSENSE_API_KEY_FILE
 mechanism; prints nothing sensitive]
```

A `--dry-run`/mandatory-confirmation split mirroring `security_plan.py`'s
own established "a plan is never authorization" discipline is the
natural fit, not a new pattern.

## 10. Proposed deterministic test strategy (described, not implemented)

- Golden-file test asserting the derivation function's output for every
  URL in `PFSENSE_LEAST_PRIVILEGE_MATRIX.md` matches the documented
  value exactly (mirrors `security_doctor.py`'s own
  `test_artifact_path_env_var_names_match_production_runtime` drift-guard
  pattern).
- Fixture-based tests for the bootstrap transaction's state machine
  (§3): each state transition, idempotent re-run, partial-failure
  resume, using a fake/mock pfSense client — no live appliance.
- Negative tests proving the design's own constraints (§7): the
  computed grant never includes `page-all`; a diff-based re-grant never
  drops an unrelated existing privilege from a synthetic "already has
  extra privileges" fixture; the bootstrap privilege is always revoked
  in the same transaction that added it, proven by a fault-injection
  test that fails the key-generation step and confirms revocation still
  occurs (or is clearly reported as pending, per §3's partial-failure
  design).
- Isolation test (mirroring `security_doctor.py`/`security_discovery.py`)
  proving whatever future module implements this never imports
  `pfsense_mcp.tier1` and never constructs a `WriteApiClient`/`RecoveryContract`.

## 11. Unresolved blockers

1. **No live privilege-catalog HTTP endpoint exists** — the derivation
   still requires either pinned-source knowledge or a full OpenAPI
   schema fetch/parse; there is no single lightweight "list valid
   privileges" call.
2. **`PrivilegesCache`'s on-appliance generated file
   (`/etc/inc/priv/restapi.priv.inc`) is not reachable by this project**
   — no SSH/local-file-read capability exists or is authorized; noted
   as a possible future authoritative source, not usable today.
3. **Version range verified is `v2.7.7`–`v2.10.0` only** — a future
   package major version could in principle change the algorithm; §2's
   live-schema-first strategy is the designed mitigation, not a proof
   this can never happen.
4. **Local, cross-process transaction persistence is still not
   implemented** — Phase C's `BootstrapTransaction` lives only in the
   calling process's memory for the duration of one
   `provision_service_account()` call; a crash mid-sequence loses the
   in-memory record entirely (the *server-side* partial state is still
   safely, precisely reported via re-reads on the next run — see
   `BLOCKED_EXISTING_PARTIAL` — but there is no local file recording
   which step was last attempted). Where such a record would live, its
   exact schema, and its relationship to Tier 1's own `RecoveryContract`
   persistence remain open questions for a future phase.
5. **No decision has been made on whether `bootstrap` becomes part of
   `pfsense-mcp-security setup` directly or a standalone subcommand** —
   §9's sketch is illustrative only.
6. **Resolved offline and partially exercised in the LAB: a Basic-Auth-capable `Transport` now exists** —
   `BasicAuthHttpTransport` is tested against the real `httpx` stack and
   through `provision_service_account()`'s existing caller-supplied
   factory seam. It remains runtime-unwired. Read-only LAB authentication
   attempts correctly returned HTTP 401 while BasicAuth was disabled; a later
   temporary enable transition exposed the availability hazard documented in
   the Phase D runbook. This closes an implementation prerequisite, not the
   separate live provisioning or runtime-wiring authorization boundaries.
7. **The "modify an existing, differently-provisioned account"
   additive-sync path (Phase C's `PRIVILEGES_SYNCED` outcome) has never
   been exercised against a real appliance** — offline-tested only,
   same as the rest of Phase C; the payload shapes it reuses
   (`PATCH /api/v2/user`) are the same live-evidenced shape the
   create-path also uses, but the specific "existing account, partial
   privilege set" scenario itself was never live-executed during
   `ADR-026`.

## GO / NO-GO recommendation (original pass)

**GO for a narrowly-scoped implementation phase**, conditional on:

- Implementation phase begins with the derivation mechanism and its
  drift-guard test (§10, first bullet) — the lowest-risk, most
  mechanically verifiable piece, and the prerequisite for everything
  else. **Done, Phase B.**
- The bootstrap transaction's state machine (§3) gets its exact schema
  designed and reviewed *before* any code that would call
  `POST /api/v2/user` is written — not concurrently. **Done, Phase B**
  (`security_bootstrap_transaction.py`) — no HTTP code exists anywhere
  in this project referencing `POST /api/v2/user`.
- Live provisioning against a real appliance (even the disposable LAB
  one) remains its own separate, explicit owner authorization, exactly
  as every prior live action in this project's history has required —
  this ADR's evidence and design do not themselves authorize touching
  pfSense. **Unchanged after Phase B** — Phase B performed zero pfSense
  contact.

**NO-GO on**: implementing `bootstrap`/`setup` provisioning code in the
same pass as this research (correctly not attempted here or in Phase
B); expanding `doctor` to make live pfSense calls (§6, correctly
deferred, still deferred after Phase B); assuming any privilege value
in this document is unconditionally guaranteed for package versions
beyond `v2.10.0` without re-verification (§2/§3's drift-detection
design exists specifically because this can't be assumed).

## GO / NO-GO recommendation (Phase C, post-Phase-B)

**GO for a narrowly-scoped Phase C** implementing the actual HTTP
provisioning operations (`POST /api/v2/user`, the bootstrap-privilege
grant/revoke, `POST /api/v2/auth/key`), conditional on:

- Phase C wires `security_privileges.py`'s derivation functions and
  `security_bootstrap_transaction.py`'s state machine together with
  real HTTP calls, rather than reimplementing either — both are now
  tested, reviewed building blocks, not merely a design to re-derive.
  **Done, Phase C** (`security_bootstrap_engine.py`).
- Live provisioning remains its own separate, explicit owner
  authorization for the specific target appliance, exactly as §3's
  original conditional required — Phase C's own code existing does not
  itself authorize running it against pfSense. **Unchanged after
  Phase C** — Phase C performed zero pfSense contact; every test uses
  an in-memory fake `Transport`.
- `doctor` integration (§6) remains a distinct, separately-scoped
  decision — Phase C implementing provisioning does not by itself
  authorize adding live pfSense calls to `doctor`. **Unchanged** —
  neither `security_bootstrap_client.py` nor
  `security_bootstrap_engine.py` is referenced anywhere in
  `security_doctor.py`.

## GO / NO-GO recommendation (Phase D prerequisites)

**GO for owner consideration of one narrowly scoped,
disposable-LAB-only Phase D; no live action is authorized by this
text.** The offline prerequisites are now closed:

1. **Resolved offline:** the single-use `BasicAuthHttpTransport` exists,
   is adversarially tested, and composes through the existing factory
   seam. It is deliberately not wired into a CLI or runtime path and
   has not been live-tested.
2. **Resolved offline:** generated-key custody uses the existing
   `PFSENSE_API_KEY_FILE` model with exclusive, owner-only, fail-safe
   creation and descriptor-bound reread verification.
3. **Resolved by owner decision:** the dedicated account is
   `pfsense-mcp`, description `Dedicated service account for
   pfsense-mcp-server`, key description `pfsense-mcp-server primary API
   key`, and target profile `write_protected` (41 READ privileges plus
   only `api-v2-firewall-alias-patch`).
4. **Resolved offline as a precise contract:** `PRIVILEGES_SYNCED`
   preserves every privilege in its final authoritative pre-mutation
   snapshot and proves every target privilege after PATCH. The absence
   of an API revision/CAS primitive remains explicit; a controlled live
   exercise requires an exclusive administrative window.
5. **Deliberately deferred:** cross-process transaction persistence is
   not required for one synchronous, supervised LAB exercise with hard
   stop, authoritative reobservation, and manual recovery. It is
   mandatory before unattended or normal CLI/runtime use.

The remaining `PRIVILEGES_SYNCED` evidence is necessarily live evidence
to be gathered *inside* a separately owner-authorized Phase D, not an
offline implementation prerequisite. The exact permitted ceremony,
interruption states, recovery actions, and stop conditions are in
[`ADR033_PHASE_D_LAB_RUNBOOK.md`](../ADR033_PHASE_D_LAB_RUNBOOK.md).
Wiring a CLI subcommand or normal runtime remains a distinct later
decision even after Phase D succeeds.

### 2026-08-19 partial Phase D evidence and transition hardening

One owner-authorized absent-account exercise reached verified server-side
account/key state but failed local key custody, leaving one disposable account
and one unrecoverable orphan key pending cleanup. A later temporary
authentication-method enablement persisted but immediate REST API reads timed
out; the owner restored exact KeyAuth out of band and two independent reads
verified recovery. No cleanup or exercise retry followed.

The resulting closed `AuthMethodTransitionCoordinator` treats the settings
PATCH as at-most-once and any post-submit disconnect/timeout as indeterminate,
throws away the old connection, performs bounded verification with newly
constructed transports, preserves an unrelated-settings digest, and requires
out-of-band recovery when exact state cannot be proven. It is isolated from
bootstrap, recovery, CLI, application, and MCP paths. Live orphan cleanup,
Exercise 1 retry, Exercise 2, and any runtime wiring remain separately
owner-gated.

## CLI/runtime integration Slice 1: durable operation state

Phase D Exercise 1 and Exercise 2 subsequently completed under separate owner
authorizations. Their supervised one-shot process model is evidence, not a safe
normal CLI interruption model. Before any mutating administrative CLI can be
wired, `security_operation_journal.py` now provides an offline-only persistence
foundation:

- an owner-only HMAC-SHA256 chained JSON-lines journal, domain-separated from
  its separately authenticated head checkpoint and lock metadata;
- append fsync before an atomically replaced head, followed by directory
  fsync, so torn/truncated appends and journal/head disagreement fail closed;
- immutable operation binding covering operation/type, target identity/origin,
  account, approved profile, schema evidence, and starting auth methods;
- a closed durable state graph with an explicit send-intent boundary. A crash
  after that boundary is always classified as unknown delivery and never as
  permission to resend;
- an owner-only advisory lock whose authenticated operation ownership survives
  process death as stale metadata. A free OS lock does not erase that evidence
  or authorize continuation; restart classification is required; and
- a pure restart classifier combining trusted journal/lock/local-artifact
  evidence with caller-supplied authoritative observations. It has no client,
  transport, endpoint, CLI, or mutation authority.

Only `CREATED`/`PRE_SEND_READY` with matching authoritative clean state can be
`PRE_SEND_RESUMABLE`. Unknown sends, partial server state, recovery-required
state, pending final verification, and corrupt/untrusted local state remain
distinct. An unfinished journal always blocks a new bootstrap. Recovery actions
are closed enum values, owner-directed, and never chain into provisioning.

The HMAC key is external secure bootstrap material and is never journaled. The
journal stores no password, API key, Basic-Auth material, raw response, request,
transport, or client. Local HMAC plus an authenticated head detects record
forgery, truncation, internal replay, and journal-only rollback. It does not
claim protection if a privileged attacker replays both journal and head while
also bypassing owner-only directory controls; a stronger external monotonic
anchor would be a separate architecture decision and is not required for this
local administrative interruption model.

Slice 1 remains unwired from `pfsense-mcp-security`, application startup, MCP
tools, bootstrap/recovery engines, and `doctor`. A later composition/CLI slice
requires separate owner authorization.

## CLI/runtime integration Slice 2: fixed administrative composition

The next offline slice adds `security_admin_composition.py` as the one fixed
construction boundary for ADR-033 administration. It accepts an explicit
mapping of secure references and binds the complete internal component graph
to one normalized HTTPS origin, one configured appliance identity, the fixed
`pfsense-mcp` account, the fixed `write_protected` profile, and one
source-cross-checked schema digest. No endpoint, HTTP method, adapter,
transport, account, profile, or mutation authority is caller-selectable.

The explicit required configuration is:

- `PFSENSE_API_URL`, `PFSENSE_IDENTITY`, `PFSENSE_API_VERSION`,
  `PFSENSE_TLS_MODE`, and (for `auto`) `PFSENSE_TLS_CA_FILE`;
- `PFSENSE_API_KEY_FILE`, the administrator KeyAuth credential reference;
- `PFSENSE_ADMIN_USERNAME` and `PFSENSE_ADMIN_PASSWORD_FILE`, the temporary
  bootstrap BasicAuth references;
- `PFSENSE_SERVICE_API_KEY_FILE`, the exclusive service-key custody target;
- `PFSENSE_ADMIN_STATE_DIR` and `PFSENSE_ADMIN_JOURNAL_KEY_FILE`; and
- `PFSENSE_ADMIN_SCHEMA_FILE`, `PFSENSE_ADMIN_SCHEMA_VERSION`, and
  `PFSENSE_RESTAPI_PACKAGE_VERSION`.

Target, identity, credential, custody, state, schema, and integrity-key paths
have no discovery fallback and must be explicit. API v2, the account name,
descriptions, profile, and target-namespaced journal/lock filenames are safe
fixed values. Insecure TLS is refused. Secret files and state directories are
owner-only and non-symlink; CA material may be shared read-only but must be a
non-symlink regular file owned by the invoking user and not writable by group
or other. Existing custody artifacts are validated but never overwritten or
read during composition.

The namespace is a domain-separated digest of origin, target identity,
account, and profile. Journal and lock paths derive from that stable namespace,
preventing accidental cross-target reuse while ensuring changed schema/version
evidence cannot select a fresh path and hide an unfinished operation. Schema
evidence remains authenticated in the journal binding, so drift fails closed.
An existing journal is authenticated and checked against every binding; a
corrupt, replayed, mismatched, or unsafe journal/lock fails construction.

The only public service is `AdministrativeStatusService`, which combines the
authenticated journal, lock observation, an internally revalidated service-key
custody observation, and caller-supplied authoritative observation through
Slice 1's pure classifier. A caller cannot hide an existing or unsafe custody
artifact. The service exposes only `classify()` and `availability()`. A new
bootstrap is available only for `CLEAN_NO_OPERATION`; completed, unfinished,
unknown-send, corrupt, drifted, and recovery states never silently reopen it.
Partial/recovery state exposes only the classifier's closed `RecoveryAction`.

Fixed KeyAuth/BasicAuth factories and exact bootstrap, recovery, and
auth-transition call bindings are assembled privately so later orchestration
cannot replace their target or dependencies. They are intentionally absent
from the public context API in this slice. In particular, Slice 2 does not yet
provide journal-aware mutation orchestration, operation locking around an
engine call, key custody, command parsing, or any callable mutating service.
No transport is constructed and no file, network, or mutation action occurs
merely by building the context.

The module remains absent from `pfsense-mcp-security`, `doctor`, application
startup, the MCP factory/server, and all tool modules. A separately authorized
next slice must first compose journal-aware administrative actions and then
register any human-invoked command; construction alone is not CLI wiring and
does not grant permission to provision or recover.

## CLI/runtime integration Slice 3: locking orchestration + `bootstrap` command

Slice 3 (2026-08-23, offline-verified only) composes Slice 1's journal/lock
primitives and Slice 2's fixed `AdministrativeContext` into one narrow
orchestration function, `security_bootstrap_orchestration.run_bootstrap()`
(and its environment-driven entry point,
`run_bootstrap_from_environment()`), and exposes exactly one new CLI
subcommand: `pfsense-mcp-security bootstrap`. This is a composition/
productization slice, not a redesign -- it reuses `provision_service_account()`
and the composition/journal/lock primitives exactly as already implemented
and reviewed; no engine, client, recovery, or journal semantics changed.

**Control flow.** `run_bootstrap()` first calls the context's own read-only
`status.classify(authoritative=None)` -- the CLI's offline default always
omits a live server observation, so per Slice 1's already-designed,
already-tested `classify_restart()` behavior, *any* pre-existing journal is
conservatively reported as requiring recovery attention, regardless of its
specific state. Only `CLEAN_NO_OPERATION` proceeds to provisioning;
`CLEAN_COMPLETED` is reported without touching the lock or journal; every
other classification refuses to start. On `CLEAN_NO_OPERATION`, it acquires
the exclusive lock (contention is reported distinctly and never silently
retried or stolen), creates the journal, appends `PRE_SEND_READY` then
`MUTATION_INTENT_RECORDED` unconditionally before calling the engine (the
engine's single blocking call can perform anywhere from zero to several real
HTTP mutations, and the orchestration cannot know in advance which), calls
`provision_service_account()` inside one `try/except Exception`, and closes
the journal based on the returned outcome: a verified success
(`ALREADY_SATISFIED`, `ALREADY_SATISFIED_WITH_EXTRA_PRIVILEGES`,
`PRIVILEGES_SYNCED`, `COMPLETED`) advances through `FINAL_VERIFICATION_PENDING`
to `COMPLETED` and releases the lock; anything else
(`DERIVATION_FAILED`, `BLOCKED_EXISTING_PARTIAL`, `FAILED`, or an unexpected
exception) is closed at `MUTATION_RESULT_UNKNOWN` with the lock **held**,
requiring human review before any further attempt against the same
target/account/profile namespace.

**A deliberate, documented offline-only limitation.** Because
`classify_restart()` treats any pre-existing journal as `RECOVERY_REQUIRED`
whenever `authoritative` is `None` -- which this offline slice's CLI always
is -- there is no journal-closure strategy that lets a *second*, later
`bootstrap` invocation against the same namespace proceed automatically,
even one that ended as cleanly as possible (e.g. a purely local
`DERIVATION_FAILED`, proven zero network activity). This is not a gap Slice
3 needs to fix: it is the correct, fail-closed consequence of Slice 1's
already-accepted design applied honestly to an offline-only caller. Only a
future, separately-authorized live-verification slice -- one that can
supply a real `AuthoritativeRestartObservation` -- can safely distinguish
"already done, all good" from "needs review" without manual state
inspection or cleanup. `run_bootstrap()`'s own tests exercise the granular
classification (`MUTATION_SENT_RESULT_UNKNOWN`, `CLEAN_COMPLETED`, etc.) by
injecting a synthetic `authoritative` observation, proving the plumbing is
ready for that future slice without claiming this one performs live
verification.

**Custody-key persistence (the one genuine missing seam found).** On a
`COMPLETED` outcome (a brand-new account with a freshly generated API key),
the orchestration persists the revealed key to the already-validated
`PFSENSE_SERVICE_API_KEY_FILE` custody path *before* closing the journal,
reusing `pfsense_mcp.tier1.artifact_exchange.write_secure_new()`'s existing
exclusive-creation, owner-only-permission discipline rather than
introducing a second implementation of it. This was required because Slice
2's own composition-time restart check
(`test_custody_artifact_is_observed_internally_and_cannot_be_hidden` /
`test_completed_operation_never_silently_reopens_bootstrap` in
`tests/test_security_admin_composition.py`) already expects a completed
journal and a present custody artifact to appear *together* -- nothing
before Slice 3 ever wrote to that path.

**CLI surface.** `pfsense-mcp-security bootstrap [--json]` -- the minimal
surface derivable from the existing composition layer: `build_admin_context()`
already reads its entire target/credential/schema configuration from the
same `PFSENSE_*`/`PFSENSE_ADMIN_*` environment variables Slice 2 defined, so
no additional flags for target, credentials, or profile selection were
introduced (matching `discover`/`plan`/`doctor`'s own zero-required-flags
pattern). A distinct posture/profile selector was considered and rejected as
premature: this slice provisions only the one existing accepted
`write_protected` capability posture Slice 2 already fixes; no other posture
combination is wired. Exit codes distinguish success; provisioning failure
(auth/authorization failure, duplicate-account detection, and post-mutation
verification mismatch are all engine-level `FAILED` outcomes the CLI reports
uniformly under this one code, since the engine itself does not expose a
non-fragile way to sub-classify them further); preflight/derivation failure;
lock contention; prior-operation-requires-recovery; corrupt local state; and
configuration error -- see `security_cli.py`'s `bootstrap` subparser epilog
for the authoritative, exact list. Never prints, logs, or serializes a
secret; the CLI's `--json` output surfaces only paths, classifications, and
already-sanitized detail strings.

**Isolation preserved.** `security_cli.py` imports *only*
`security_bootstrap_orchestration` -- never any of the five lower-level
bootstrap-stack modules it composes -- keeping every existing isolation
assertion in `tests/test_security_bootstrap_engine_isolation.py` (module
names absent from all shipped runtime entry points and `tools/*`) true
unmodified; only new, additive tests were needed to prove the new module
is the sole gateway.

**Recovery execution remains out of scope.** `security_bootstrap_recovery.py`'s
two closed actions (`revoke_failed_bootstrap_api_key()`,
`delete_dedicated_recovery_user()`) are never called by this orchestration.
A `RECOVERY_REQUIRED`/`BLOCKED_PRIOR_OPERATION` result surfaces the
classifier's `recovery_action` (when the journal names one) purely as
information for a human -- no `recover` CLI verb exists in this build, and
none is planned until a separately authorized future slice makes that a
deliberate decision.

**What Slice 3 does not authorize.** Live LAB bootstrap; live production
bootstrap; credential creation on any real appliance; pfSense mutation;
package installation; privilege changes beyond what Slice 2's fixed
`write_protected` profile already derives; API-key creation against a real
target; runtime MCP exposure changes; or the full `pfsense-mcp-security
setup` interactive wizard (reserved, not yet designed in detail).
