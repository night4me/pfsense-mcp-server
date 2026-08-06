# Final repository quality review

Reviewed: 2026-08-06  
Scope: repository-wide, offline, no production credentials or pfSense access

## Decision

The repository is in strong pre-release condition for a security-focused beta.
Its production path remains explicit, GET-only, typed, and well tested. The
documentation added during this phase materially improves external review and
operator onboarding without changing the public MCP API.

The project is not yet ready to claim complete open-source/PyPI readiness
because no software license has been selected. GitHub Actions also remains
unobserved until service availability and an authorized push. Neither issue is
a runtime security defect.

## Current invariants

- 41 READ tools are expected to register in the auditor profile.
- Zero WRITE tools register.
- The WRITE endpoint allow-list is empty and WRITE capabilities are inactive.
- Production construction uses `RestApiClient`, whose transport calls are
  statically constrained to GET.
- Tier 0 WRITE modules exist as accepted but dormant infrastructure and must not
  be treated as ordinary dead code.
- Public Pydantic schemas exclude credential fields and upstream extras are not
  serialized automatically.
- Live tests are opt-in and public verification is offline.

Final verification results are recorded separately in the handoff report after
all documentation changes are committed.

## Findings

### P0 — none

No confirmed issue was found that exposes credentials, activates mutation, or
requires an emergency compatibility change.

### P1 — license decision blocks genuine open-source publication

**Confirmed.** There is no root license file or license metadata. Build and
Twine checks can succeed without one, but recipients do not receive explicit
reuse rights.

Recommendation: the owner must select an OSI-approved license, add its exact
text, and add matching PEP 639 package metadata before PyPI publication or a
claim of open-source licensing. Do not infer the choice from repository
visibility.

### P1 — Tier 1 prerequisites remain unresolved by design

**Confirmed, no current exploit path.** Dormant Recovery Contract and WRITE
client code must not be activated until contracts are bound to capability,
endpoint, target, and intent; authoritative store loading and legal transitions
are enforced; payload transmission and HTTP outcome validation are correct; and
persistence/crash semantics are accepted.

Recommendation: keep the allow-list and WRITE capability set empty. Follow
`docs/TIER1_ROADMAP.md` only after separate approval.

### P2 — large client and test modules increase change risk

**Confirmed.** `src/pfsense_mcp/pfsense_client.py` is about 50 KB,
`tests/test_pfsense_client.py` about 155 KB, and
`tests/test_tool_registry.py` about 80 KB. Response-shape validation and test
setup repeat across domains.

Recommendation: first split the two large test modules mechanically by domain.
Then characterize exact error behaviour and extract only small private
singleton/list mapping helpers while preserving the `PfSenseClient` facade.

### P2 — key-file check/open sequence has a local TOCTOU opportunity

**Plausible defense-in-depth issue, not MCP-exploitable in the intended model.**
Metadata is validated before the credential path is opened. A hostile local
filesystem actor able to replace directory entries could race those steps.
Mode-0700 parent directories structurally prevent this for other local users;
an MCP-only attacker has no filesystem primitive.

Recommendation: in a dedicated security change, evaluate `os.open` with
no-follow semantics followed by descriptor `fstat`, retaining platform-aware
tests and current fail-closed errors. Never weaken existing ownership/mode
validation.

### P2 — generated status artifacts lack a durable freshness contract

**Confirmed.** `CHECKPOINT.md` and `.checkpoint/state.json` are tracked, while
the checkpoint generator records ephemeral Git/test state. The Markdown now
has a historical warning, but regenerating it can replace that warning and
reintroduce ambiguous authority. `docs/READ_BACKLOG.md` is likewise an initial
schema snapshot and is now clearly marked historical.

Recommendation: choose one policy in a focused change: make checkpoint output
untracked/ephemeral, or version it with a generated-data banner and an automated
freshness assertion. The public roadmap and source registries should remain
authoritative.

### P2 — newly expanded public documentation is not included in the sdist

**Confirmed.** Hatchling uses an explicit minimal sdist include list. It ships
core API/security/release documents but not the threat model, diagrams, ADRs,
roadmap, benchmarks, or examples added in this phase.

Recommendation: decide whether PyPI source users should receive the complete
public documentation set. If yes, expand the explicit allow-list rather than
using a broad include that could admit reports, fixtures, or private files.
Re-run distribution member and secret scans after any change.

### P2 — public CI configuration has not run remotely

**Confirmed operational gap.** CI and CodeQL workflows are locally reviewed and
tested structurally, but GitHub Actions availability prevented remote evidence.

Recommendation: after explicit push approval and service restoration, inspect
all Python matrix, coverage, package, Bandit, and CodeQL jobs. Treat action
permissions, immutable SHA pins, dependency resolution, artifact membership,
and live-test skipping as release gates.

### P3 — strict typing is incomplete at internal JSON/tooling boundaries

**Confirmed.** An exploratory strict mypy run reports 17 issues in seven files;
most are `Any` returns or missing annotations in OpenAPI/fixture/scaffolding
code. Configured mypy remains the authoritative passing gate.

Recommendation: tighten scripts incrementally and pilot a recursive JSON alias.
Avoid a mechanical `Any` purge that obscures runtime validation. Details are in
`reports/type_audit.md`.

### P3 — Bandit exclusions need change-triggered review

**Confirmed and currently justified.** Several local-only scripts are excluded
after review of fixed-argument subprocess use and locally generated JUnit XML.
Whole-file exclusions can hide future unrelated findings.

Recommendation: review exclusions whenever an excluded script changes; move to
narrow line suppressions where this improves signal without noise.

### P3 — certificate fixture provenance remains uncertain

**Confirmed residual concern, no credential finding.** The fixture contains
public certificate material and passes current safety checks, but its external
provenance cannot be proven from Git history. Public certificates can still
identify infrastructure.

Recommendation: replace it prospectively with wholly synthetic public material
and keep the historical warning. Do not rewrite published history unless a
future incident establishes secret material was committed.

### P3 — external client examples require manual smoke testing

**Confirmed documentation limitation.** Formats were validated against current
first-party documentation and parsed locally. Desktop UIs and plan/organization
policies vary. ChatGPT correctly documents that it cannot directly use this
local stdio-only server.

Recommendation: smoke-test Claude Desktop, Cursor, VS Code, and Continue after
release packaging. Do not claim direct ChatGPT support or introduce an ad hoc
network bridge.

## Dead code and duplication

No accidental dead production module was identified by reference review and
Ruff. Apparent exceptions are intentional:

- Tier 0 WRITE modules are inert future infrastructure with dedicated tests;
- `tools/write/__init__.py` is an intentionally empty, statically guarded
  namespace;
- exception-class `pass` bodies are normal;
- scaffold-generated `TODO(human)` and `NotImplementedError` text are proposal
  placeholders, not executed production paths;
- sanitizer `pass` statements implement intentionally ignored parsing probes
  and are covered by tests.

Duplication is highest in response mapping, explicit registration, and large
domain tests. Tool-builder repetition is intentional because it preserves exact
signatures, descriptions, and auditable capability ownership. Reflection-based
deduplication would be a security and maintainability regression.

## Naming and style

- Public tools consistently use `pfsense_get_`.
- Internal naming varies around upstream terms (`hasync`, FreeRADIUS, pfSense),
  but renaming established public symbols would be breaking.
- Formatting and lint rules are centralized and the repository has no broad
  style inconsistency requiring refactoring.
- A future naming glossary should distinguish upstream wire spellings from
  prose/product capitalization.

## Security posture

The layered controls remain appropriate: local stdio trust boundary,
fail-closed configuration, credential-file metadata enforcement, TLS strict by
default, GET-only REST chokepoint, endpoint and capability gates, sanitized
typed errors, value-free audit records, fixture approval, repository scans, and
negative MCP schema/output tests.

Residual risk is chiefly operational: the local launcher controls all exposed
READ authority; optional metadata can reveal topology; `insecure` TLS is an
explicit operator choice; dependencies and the host remain trusted; public
certificate data can identify infrastructure. These are documented rather than
misclassified as remotely exploitable vulnerabilities.

## Maintainability priorities

1. Obtain the owner license decision.
2. Observe and stabilize public CI/CodeQL after an approved push.
3. Resolve checkpoint/backlog artifact ownership and freshness.
4. Replace the uncertain certificate fixture with synthetic material.
5. Split large tests by domain, then extract private response-shape helpers.
6. Expand sdist documentation deliberately if desired.
7. Tighten internal typing and Bandit suppression scope incrementally.
8. Keep Tier 1 blocked until every Recovery Contract milestone is accepted.

## Manual review required

- License selection and published author/maintainer identity.
- GitHub-rendered Mermaid diagrams and community forms.
- Remote CI, CodeQL, and action-permission results.
- Desktop-client smoke tests.
- Whether complete public docs belong in the sdist.
- Synthetic certificate-fixture provenance decision.
- Any future live acceptance, publication, push, or Tier 1 work.
