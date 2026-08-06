# Project health review

Reviewed: 2026-08-06  
Baseline: `89eef27` (`chore(ci): add v0.2.2 project hardening`)

## Executive summary

The repository is unusually disciplined for its age: capability registration
is explicit, production transport remains GET-only, fixture capture is
fail-closed, credential non-disclosure has schema-level regression coverage,
and the offline suite is broad and fast. The strongest qualities are the
redundant WRITE-inactivity checks, typed response mapping, and separation of
production bootstrap from dormant Tier 0 infrastructure.

The main maintainability cost is concentration. `pfsense_client.py`,
`tools/registry.py`, and their corresponding tests have grown into large,
repetitive dispatch/mapping modules. The main project-health defect is stale
generated/planning documentation: `CHECKPOINT.md` and `docs/READ_BACKLOG.md`
describe a much older implementation state. No externally visible API change
is needed to address the findings below.

## Findings by priority

### High — stale project-state documents can misdirect maintainers

**Confirmed.** `CHECKPOINT.md` names commit `75a563b`, reports 1,070 tests,
describes a dirty Tier 0 worktree, and recommends resuming a READ backlog that
has since been largely implemented. `docs/READ_BACKLOG.md` still says only four
capabilities/eight endpoints are complete even though the accepted build has
34 capabilities and 41 tools.

Impact: a new maintainer following these files could duplicate work, infer the
wrong release state, or attempt an obsolete capability sequence.

Recommendation: either regenerate the checkpoint as an explicitly ephemeral,
ignored artifact or replace it with a short pointer to current acceptance and
release documents. Mark the backlog as historical or reconcile it against the
capability enum and endpoint registry. Do not rewrite historical acceptance
documents.

### High — dormant WRITE infrastructure is intentionally incomplete

**Confirmed and already documented as a pre-Tier-1 gate.** Tier 0 types and
clients exist but are not constructed by production bootstrap. Recovery
contracts are not yet bound authoritatively to capability, endpoint, and
target; store-loaded state and legal transitions are incomplete; payload
transmission/HTTP outcome validation and crash persistence remain unresolved.

Impact: none in the current production path because zero WRITE tools register,
the allow-list is empty, and WRITE capabilities are inactive. Activating Tier 1
before resolving these items would be unsafe.

Recommendation: preserve current inertness and use the dedicated Tier 1
roadmap produced in this phase as the only activation path.

### Medium — response-shape mapping is highly repetitive

**Confirmed.** `pfsense_client.py` is roughly 50 KB and repeats the same
singleton/list response checks, item type checks, model construction, and
sanitized `KeyError`/`TypeError`/`ValidationError` translation dozens of times.

Impact: new endpoints can receive subtly inconsistent error text or miss one
shape check. The previously inconsistent `get_system_status()` behavior shows
this is a real maintenance risk.

Recommendation: introduce small private typed helpers for singleton and list
mapping only after characterization tests prove identical exceptions and
messages. Do not create a generic endpoint framework that hides endpoint-
specific semantics.

### Medium — registry and registry tests are oversized

**Confirmed.** `tools/registry.py` is approximately 15 KB;
`tests/test_tool_registry.py` is approximately 80 KB. Registration follows a
deliberately explicit pattern, but the single-file layout makes reviews and
merge conflict resolution harder.

Recommendation: retain explicit capability gates while splitting registration
tests by capability family. A future registry decomposition should use static
declarative descriptors only if it preserves tool signatures, audit wrapping,
and obvious capability ownership.

### Medium — core client tests are concentrated in one 150 KB file

**Confirmed.** `tests/test_pfsense_client.py` is the largest repository file.
It provides strong coverage but makes focused navigation and ownership
difficult.

Recommendation: split by domain (`system`, `firewall`, `services`, `users`,
and diagnostics) without changing fixtures or test behavior. This is a
mechanical test-only refactor suitable for a dedicated change.

### Medium — local key-file validation has a metadata/open race

**Plausible under a hostile local-filesystem actor.** Configuration uses
`lstat()` to reject symlinks and validate owner/mode, then later opens the path
normally to read the key. A local actor able to replace entries in the parent
directory between those operations could race validation.

The production parent directories are mode 0700, so this is structurally
prevented in the intended deployment unless the launching user itself is
compromised. It is not exploitable by an MCP-only attacker.

Recommendation: consider an `os.open()`/`O_NOFOLLOW` file-descriptor-based
load with `fstat()` validation in a future security patch. Preserve the current
metadata-only preflight workflow and add platform-aware tests.

### Medium — package metadata is not yet polished for PyPI

**Confirmed.** Before this phase, `pyproject.toml` lacks authors/maintainers,
license declaration, classifiers, keywords, project URLs, and a declared
readme/content type. A root license file is also absent.

Recommendation: add standard metadata, an OSI-approved license chosen by the
owner, and validate both artifacts with Twine. This phase can prepare metadata,
but the license choice must not be guessed if repository history does not
establish one.

### Low — naming reflects upstream vocabulary inconsistently

**Confirmed but mostly justified.** Examples include `PfSenseUser` in
`pf_sense_user.py`, `FreeRadiusEap` versus `freeradius_eap`, and upstream
`hasync` terminology. Renaming public models or tools would be breaking and is
not warranted.

Recommendation: establish naming guidance for new internal modules: preserve
pfSense endpoint spellings in wire-facing code, use conventional product names
in prose, and do not rename existing public symbols without a deprecation plan.

### Low — security scanner exclusions need periodic review

**Confirmed.** Bandit excludes five local-only scripts after manual review of
fixed-argv subprocess calls and trusted locally generated JUnit XML. The
exclusions are narrow and documented, but an entire excluded file could later
gain unrelated risky code.

Recommendation: add an annual/release-major review item, or replace exclusions
with exact-line suppressions when those scripts next change materially.

### Low — diagnostics are code-level rather than an MCP capability

**Confirmed and intentional.** `diagnostics.py` is tested but not registered as
an MCP tool. It reports local construction state without contacting pfSense.
This is not dead code, but its intended invocation surface is under-documented.

Recommendation: document it as an internal/library diagnostic helper or remove
it only if no supported caller exists. Do not expose a new MCP tool without
explicit authorization.

## Dead-code assessment

No obvious accidental dead production module was found. The following are
deliberately unreachable in production and must not be removed as ordinary
dead code:

- `pfsense_write_client.py`, `write_api_client.py`, `write_audit.py`,
  `write_endpoints.py`, `write_types.py`, `recovery.py`, and `rollback.py` are
  accepted Tier 0 infrastructure kept inert by bootstrap/capability/allow-list
  boundaries.
- `tools/write/__init__.py` is an intentionally empty namespace guarded by
  static import-absence checks.
- proposal, checkpoint, fixture-capture, and audit scripts are local workflow
  tools with direct test coverage.

Ruff reports no unused imports or undefined names. Determining unused public
methods through a tool such as Vulture would have limited signal because MCP
registration and CLI entry points are dynamic; any future dead-code removal
should require reference search plus tests, not scanner output alone.

## Duplication and complexity

- List/singleton response validation is duplicated throughout
  `pfsense_client.py`.
- Identifying-metadata projection is repeated across models. The repetition is
  transparent and security-auditable, so a helper must not make secret-field
  policy implicit.
- Tool modules intentionally repeat thin build functions to preserve precise
  MCP signatures and descriptions.
- `ToolRegistry` repeats capability checks and registration calls. This is
  verbose but safer than reflection for the current threat model.
- Test fixtures and MockTransport setup are repeated in the two largest test
  modules; domain-local helper fixtures would improve readability.

## Documentation assessment

Strong and current:

- `README.md`, `SECURITY.md`, `docs/SECURITY_MODEL.md`, and accepted release
  documents clearly describe credential handling and inert WRITE status.
- `docs/RELEASE_CHECKLIST.md` cleanly separates public CI from private live
  acceptance.

Missing or incomplete before this phase:

- contributor guide, changelog, code of conduct, public API reference, Tier 1
  implementation roadmap, and PyPI metadata guidance;
- troubleshooting and first-user workflow in README;
- an explicit policy for generated checkpoint/backlog freshness;
- documentation for all 41 MCP tools.

## Security assessment

No new credential-return path was found. Public schemas exclude the prohibited
credential fields, fixtures fail closed on those keys, audit logs omit values
and messages, and authentication errors are sanitized. The local stdio model
correctly treats the launcher as the caller-authentication boundary.

Residual risks are operational rather than MCP-protocol vulnerabilities:

- anyone controlling the stdio channel receives the selected profile's full
  authority;
- `PFSENSE_TLS_MODE=insecure` remains available as an explicit operator choice;
- public certificates can carry identifying metadata even though they are not
  secret;
- the production credential file is protected by local filesystem ownership
  and directory modes rather than a separate secret service;
- dormant WRITE code must remain unreachable until the Recovery Contract gates
  are accepted.

## Maintainability recommendations

1. Correct or retire stale checkpoint/backlog state.
2. Keep Tier 1 blocked and implement its prerequisites milestone-by-milestone.
3. Split the two largest test modules by domain before splitting production
   modules.
4. Characterize and then extract only the repeated response-shape helpers.
5. Add public API, contribution, release-history, and PyPI documentation.
6. Review Bandit exclusions and certificate-fixture provenance periodically.
7. Consider descriptor-based key-file opening as a future defense-in-depth
   improvement.

## Verification used for this review

This review used repository-wide file/reference searches, size analysis,
current acceptance/security documents, capability/endpoint architecture,
coverage evidence from the v0.2.2 pre-commit phase, and the existing successful
Ruff, mypy, pytest, `make quick`, `make validate`, package, Bandit, fixture,
GET-only, and WRITE-inactivity gates. No live pfSense call was made.
