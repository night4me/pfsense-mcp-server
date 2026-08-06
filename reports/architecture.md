# Architecture review

Reviewed: 2026-08-06

## Current architecture

The production path has four clear layers:

```text
HttpTransport
    → RestApiClient (GET-only, API/error boundary)
        → PfSenseClient (semantic mapping to typed models)
            → ToolRegistry and thin MCP tool builders
```

`Application` owns configuration, logging, dependency construction, MCP
registration, and lifecycle. Capabilities and profiles gate tool registration;
the endpoint registry gates upstream paths. `MockTransport` makes the full
stack testable without network access.

Tier 0 WRITE infrastructure is a separate dormant path. Production bootstrap
does not construct it, the allow-list is empty, WRITE capabilities are
inactive, and no WRITE tool registers.

## Architectural strengths

- **Defense in depth:** profile, capability, endpoint, HTTP-method, fixture,
  schema, and static checks overlap without relying on a single convention.
- **Explicit registration:** tool exposure is easy to audit and resistant to
  accidental discovery/reflection.
- **Typed boundary:** raw upstream JSON is translated once into explicit
  Pydantic models with sanitized shape errors.
- **Transport substitution:** tests exercise request construction and mapping
  without monkeypatching the entire domain layer.
- **Inert future infrastructure:** Tier 0 code can be tested without making it
  reachable in production.
- **Operational fail-closed behavior:** configuration and package entry point
  stop before networking when required state is absent or unsafe.

## Modules that should eventually be split

### `pfsense_client.py`

At roughly 50 KB, this module contains every domain query and repeated response
shape/mapping logic. Split only after extracting characterization tests.

Suggested internal organization:

```text
client/
    base.py          private response-shape helpers
    system.py
    interfaces.py
    firewall.py
    services.py
    users.py
    diagnostics.py
```

Preserve `PfSenseClient` as the public facade so imports and MCP behavior remain
compatible. Composition or private mixins are preferable to exposing many new
client classes publicly.

### `tools/registry.py`

The registry's explicit branches are a security property, but one large module
is becoming difficult to review. Split private registration functions by
capability family while keeping one authoritative `register_all()` order and
one public registry type. Avoid reflection, module scanning, decorators with
import-time side effects, or naming-convention discovery.

### Test modules

Split tests before production modules:

- `tests/test_pfsense_client.py` (approximately 155 KB) by domain;
- `tests/test_tool_registry.py` (approximately 80 KB) by domain;
- `tests/test_scaffold_capability.py` by new-capability versus extension flows.

This lowers review/merge cost without architectural risk and prepares safe
production decomposition.

### Proposal/scaffolding tooling

`scripts/scaffold_capability.py` and `scripts/lib/code_templates.py` contain a
substantial code-generation subsystem. Separate manifest validation, source
transformation, rendering, and proposal output once new capability work
resumes. Keep generation proposal-only and human-reviewed.

## Abstractions that should exist

### Private response mappers

Two carefully limited helpers would remove the most error-prone duplication:

- map a singleton `data` object through a model factory;
- map a bounded list of `data` objects through a model factory.

They should accept endpoint-specific sanitized error strings, never log raw
data, and preserve exact typed exceptions. They must remain private until their
shape proves stable.

### Sensitive-metadata policy type

Models currently use repeated tuples and projection comprehensions. A small
immutable internal policy object could distinguish ordinary fields, optional
sensitive metadata, public cryptographic material, and prohibited credential
fields. It would reduce drift between model, capture, and fixture policy.

Risk: over-generalization could hide credential decisions. Any helper must make
the prohibited set explicit at each model and retain schema/output negative
tests.

### Recovery Contract state machine

Before Tier 1, Recovery Contract identity, binding, transitions, persistence,
and crash behavior need one authoritative state-machine abstraction. It should
not be added piecemeal to the current generic clients. See
`docs/TIER1_ROADMAP.md` for the staged design.

### Repository-state document ownership

Generated checkpoint/backlog state needs a freshness contract: either generated
and ignored, or versioned and asserted against current capability/tool counts.
Currently it occupies an ambiguous middle ground.

## Abstractions to avoid

- A generic “call any endpoint” MCP tool.
- Reflection-based tool or capability discovery.
- A shared READ/WRITE HTTP client that weakens the GET-only chokepoint.
- A generic model that returns arbitrary upstream dictionaries.
- Logging middleware that captures arguments, payloads, responses, or exception
  messages.
- A repository-wide identifying-field helper that can accidentally classify a
  credential as optional metadata.

## Technical debt

### Near term

- Stale `CHECKPOINT.md` and `docs/READ_BACKLOG.md`.
- Missing license decision blocks genuine open-source/PyPI readiness.
- Public CI/CodeQL are configured locally but cannot be observed until push.
- Bandit file exclusions need review when excluded scripts change.
- Certificate-fixture provenance remains uncertain, though the material is
  public and current scans pass.

### Before Tier 1

- Bind recovery contracts to capability, endpoint, target, and mutation intent.
- Load authoritative contract state from the store by ID.
- Enforce legal transitions atomically.
- Transmit mutation payloads and validate HTTP outcomes.
- Resolve persistence, expiry, replay, concurrency, and crash recovery.
- Specify upstream least-privilege credentials and operator authorization.

### Long term

- Large client/registry/test modules.
- Repetitive model projection and mapping patterns.
- Development dependency reproducibility (bounded ranges but no constraints
  snapshot).
- No formal compatibility-test fixture for MCP schema evolution between tags.

## Performance opportunities

- Cold startup is dominated by importing the MCP SDK, not project mapping
  code. Avoid eager imports in optional tooling, but do not complicate the
  production path merely to reduce a sub-second startup.
- Each request creates typed models once; this is appropriate for bounded
  administrative data. Do not cache live operational results without an
  explicit freshness/security contract.
- Bounded list parameters already prevent accidental unbounded result mapping.
- Model validation could use `TypeAdapter` for large homogeneous lists, but the
  observed workload and test runtime do not justify the complexity yet.
- Log formatting and audit duration measurement are negligible relative to
  appliance/network latency.

## Testability improvements

1. Add focused tests for currently uncovered configuration parse/open error
   branches and transport timeout/connection translation.
2. Add a cross-release MCP-schema snapshot/diff tool that classifies additive
   versus breaking changes without approving them automatically.
3. Split large test files and create domain-local fixture builders.
4. Add contract/state-machine property tests before Tier 1.
5. Test package metadata and sdist member policy as part of the authoritative
   validation target, not only CI/package-check.
6. Once workflows run remotely, test CodeQL/Bandit configuration drift through
   scheduled maintenance rather than broad suppressions.

## Recommended sequence

1. Resolve license and stale state documentation.
2. Observe and stabilize public CI/CodeQL.
3. Split the two largest test modules mechanically.
4. Add missing security-boundary tests.
5. Extract private response-shape helpers with no public API change.
6. Implement the Tier 1 Recovery Contract milestones without activating a
   capability until final acceptance.

Large production refactors are not recommended during v0.2.2 hardening.
