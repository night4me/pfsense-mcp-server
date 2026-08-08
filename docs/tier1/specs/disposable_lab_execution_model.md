# Tier 1 — Disposable-lab execution model

Status: implementation-ready specification; implementation not authorized
to run yet (requires separate command-level approval per
`TIER1_ROADMAP.md` Milestone 8).
Activation gate: Milestone 8; requires
[ADR-016](../../adr/ADR-016-alias-candidate-lab-authorization.md).
Related: [TIER1_LAB_PLAN.md](../../TIER1_LAB_PLAN.md) (existing plan; this
document adds the concrete execution/harness detail the existing plan
describes at a design level but does not fully operationalize).

## Purpose

Turn `docs/TIER1_LAB_PLAN.md`'s scenario list into a concrete, scripted,
repeatable harness so that disposable-lab acceptance is executed
identically every time it runs (including after any adapter code change),
rather than being a manual, ad hoc exercise whose thoroughness depends on
who runs it that day.

## Security goals

- G1: No production address, credential, or configuration can enter the
  lab harness — the harness itself refuses to start against anything that
  looks production-shaped (see Invariants).
- G2: Every fault scenario in `TIER1_LAB_PLAN.md` is scripted and
  re-runnable, not manually reproduced each time, so regression in fault
  handling is caught automatically on the next lab run, not only the
  first one.
- G3: The harness produces the same value-free evidence format the rest
  of this system already uses (hashes, counts, state transitions — never
  raw configuration, credentials, or captured payloads) so lab output can
  be safely retained and reviewed without becoming a new sensitive-data
  liability.

## Invariants

- I1: The harness's target `PFSENSE_API_URL` must match a configured
  allow-list of lab-only host patterns (e.g., a specific RFC 5737 address
  range or a `.lab.invalid`-style hostname convention) — if the resolved
  target does not match, the harness refuses to start, structurally
  separate from (not merely additive to) the existing `PFSENSE_TLS_MODE`/
  credential fail-closed checks in `config.py`.
- I2: The harness runs against a **separate** API identity holding only
  the one candidate capability's exact test permission — provisioned per
  `TIER1_LAB_PLAN.md`'s existing provisioning steps — and the harness
  itself never receives or handles the production credential path at all
  (not "must not use it" as a runtime check, but "does not have a code
  path capable of loading it" — reuse a distinct config-loading entry
  point, not the production `load_api_key()`, or an explicitly
  lab-scoped wrapper around it that hard-codes a separate env var name).
- I3: Every fault scenario is implemented as a composable fault-injection
  hook using the **existing** `FaultHook`/`fault_hook` parameter already
  present in `store.py` (`_invoke_fault("before_transaction")`, etc.) plus
  a new transport-level fault proxy for network-level faults (connection
  reset, timeout, response-drop) — reusing the existing hook mechanism
  rather than inventing a second one.
- I4: The harness captures evidence in the same JSON-lines,
  value-free shape as `write_audit.py`'s existing log format — method,
  path, status, timing, and outcome classification only, never request/
  response bodies.
- I5: The harness's final step is always exit-condition verification
  (permission revocation, `read_only=true` confirmation) — even on a
  harness-internal failure, a `finally`-equivalent cleanup path must
  attempt this, so a crashed lab run does not silently leave elevated
  permissions active.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Lab harness vs. production config | Lab-scoped credential/config loader | Production `PFSENSE_API_URL`/key file | Separate loader entry point (I2); host allow-list check (I1) |
| Harness vs. lab pfSense VM | Harness's assertions about observed behavior | The lab appliance's actual (possibly surprising) API behavior | Every assertion is a positive check against captured evidence, never an assumption |
| Fault injection vs. real faults | Scripted, deterministic fault hooks | Organic network/process faults the harness isn't specifically injecting | Both are exercised — scripted faults for repeatability (G2), plus at least one organic run without injected faults as a baseline |

## State ownership

- A new, **not-packaged** directory, e.g. `lab/` at the repository root
  (excluded from the sdist/wheel via the existing packaging policy in
  `DEPENDENCY_POLICY.md`/`RELEASE_CHECKLIST.md` — this is lab tooling,
  never shipped), owns the harness scripts, fault-proxy, and evidence
  writer.
- The harness constructs its own `MutationExecutor`
  (`sealed_executor.md`) instance, wired to the lab's `SqliteRecoveryContractStore`
  (a throwaway file per run, per `TIER1_LAB_PLAN.md`'s "destroy after each
  scenario" requirement) and a real `HttpTransport` pointed at the lab
  VM — this is the **only** place in the entire project where a real
  `MutationExecutor` is constructed and actually allowed to send a
  mutating request, and it must never be reachable from `pytest`'s
  default collection (separate directory, separate invocation, per
  `TIER1_LAB_PLAN.md`'s existing "no production appliance" boundary,
  extended here to "no accidental CI collection" as well).

## Interfaces

```python
# lab/harness.py (new; not created yet; not packaged; not collected by
# the default pytest run — invoked explicitly, e.g. `python -m lab.harness`)


@dataclass(frozen=True)
class LabConfig:
    base_url: str  # must match the lab host allow-list (I1)
    identity: str
    key_file: Path  # lab-scoped env var, distinct from PFSENSE_API_KEY_FILE
    candidate: str  # e.g. "firewall_alias_description" — names the adapter under test


def load_lab_config() -> LabConfig:
    """Refuses to load if base_url doesn't match the lab allow-list, or
    if the production env vars (PFSENSE_API_URL etc.) are the only ones
    set — the lab requires its own distinctly-named variables."""


class FaultProxy:
    """Sits between HttpTransport and the lab VM. Can inject: connection
    reset mid-upload, response-drop after upstream commit (simulated via
    a controllable delay + kill), timeout, and clean passthrough."""

    def install(self, scenario: FaultScenario) -> None: ...


def run_scenario(config: LabConfig, scenario: FaultScenario) -> ScenarioReport:
    """Runs one full prepare -> confirm -> execute (-> rollback) cycle
    under the given fault scenario, using a fresh throwaway store, and
    returns a value-free ScenarioReport (state transitions, timing,
    outcome — never payloads)."""


def run_full_acceptance(config: LabConfig) -> AcceptanceReport:
    """Runs every scenario in TIER1_LAB_PLAN.md's "Fault scenarios"
    section plus the baseline (no-fault) acceptance sequence, aggregates
    ScenarioReports, and performs the exit-condition verification (I5)
    unconditionally at the end, including on partial failure."""
```

## Failure modes

| Failure | Detection | Resulting state | Automatic retry |
|---|---|---|---|
| Harness resolves a non-lab host | I1 allow-list check | Refuses to start, zero calls made | No |
| Production credential path accidentally referenced | I2's separate loader has no code path to it | `AttributeError`/`ConfigurationError` at load, not a silent fallback | No |
| A fault scenario's assertion fails (adapter/executor didn't behave as specified) | `ScenarioReport` marks the scenario failed | Lab run continues to remaining scenarios (not abort-on-first-failure, to gather complete evidence in one run), full report marks overall acceptance failed | No — this is exactly the evidence the lab exists to produce |
| Harness process itself crashes mid-run | External supervision (the operator running it) | Exit-condition verification must still run — see I5; if the harness process itself is gone, the **VM snapshot restore** (per `TIER1_LAB_PLAN.md`) is the backstop, not a harness-internal recovery |

## Recovery behavior

- Lab stores are throwaway by design (`TIER1_LAB_PLAN.md`: "Destroy the
  clone after each scenario") — there is no cross-run recovery
  requirement; each scenario starts from a known-good VM snapshot.
- The one recovery property that matters here is I5: even a hard harness
  crash must not leave the lab's elevated WRITE permission active
  indefinitely. Recommend a belt-and-suspenders approach: the harness
  attempts revocation in a `finally` block, **and** the lab provisioning
  step (`TIER1_LAB_PLAN.md` step 5, "clone the VM snapshot and grant only
  the candidate permission") uses a time-bounded credential/permission
  where the lab identity provider supports it, so an abandoned run
  self-expires rather than relying solely on the harness's own cleanup
  code.

## Non-goals

- This spec does not implement the lab VM provisioning/snapshot tooling
  itself (hypervisor automation) — `TIER1_LAB_PLAN.md`'s provisioning
  section remains the source of truth for that; this spec only covers the
  harness that drives the MCP-side test sequence once the VM is ready.
- This spec does not attempt to make lab results a substitute for the
  owner decisions in the ADRs — lab evidence informs `ADR-015`'s numeric
  defaults and validates `ADR-016`'s candidate assumptions, but does not
  itself constitute authorization for anything.
- This spec does not run against production under any configuration —
  there is no flag, environment variable, or code path that widens
  `load_lab_config()`'s allow-list to include a production-shaped host;
  changing that allow-list is itself a reviewable source change, not a
  runtime option.

## Required tests

(These test the harness itself, offline, before it is ever pointed at a
real lab VM — using `MockTransport`, consistent with every other Tier 1
test in this codebase.)

- `load_lab_config()` refuses non-allow-listed hosts.
- `load_lab_config()` has no code path reaching
  `PFSENSE_API_KEY_FILE`/`PFSENSE_API_URL` (grep-based/AST-based test,
  same discipline as the isolation tests elsewhere in this project).
- `FaultProxy` correctly injects each fault type against a
  `MockTransport`-backed harness run (offline proof the injection
  mechanism works before it's ever pointed at a real VM).
- `run_full_acceptance()` aggregates a mix of passing/failing
  `ScenarioReport`s into a correct overall `AcceptanceReport` (offline,
  synthetic scenario results).
- Exit-condition verification (I5) runs even when a scenario raises an
  unexpected exception mid-`run_full_acceptance()` (fault-injected into
  the harness's own control flow, not just the pfSense-facing calls).

## Activation requirements

- [ ] `ADR-016` accepted (which candidate, and explicit authorization to
      spend lab time on it — not production authorization).
- [ ] `lab/` harness implemented and its own offline tests (above) pass.
- [ ] `sealed_executor.md`, `capability_adapter_contract.md`, and the
      specific candidate adapter are implemented (the harness needs a
      real adapter to test against — it cannot run before one exists).
- [ ] Lab VM/network environment provisioned per
      `TIER1_LAB_PLAN.md`'s existing environment section.
- [ ] Separate, explicit command-level approval to actually execute the
      harness against the live lab VM (per `TIER1_ROADMAP.md` Milestone
      8's existing requirement) — implementing and testing the harness
      offline does **not** imply approval to run it.

## Implementation checklist

- [ ] Create `lab/` directory (not packaged — verify via
      `make package-check`'s existing artifact-member inspection that it
      is excluded, extending that check's exclusion list if needed).
- [ ] Implement `LabConfig`/`load_lab_config()` with the lab-only
      allow-list and distinct env var names.
- [ ] Implement `FaultProxy` covering every fault type in
      `TIER1_LAB_PLAN.md`'s "Fault scenarios" list.
- [ ] Implement `run_scenario`/`run_full_acceptance` with unconditional
      exit-condition verification.
- [ ] Confirm `lab/` is excluded from `pytest`'s default collection
      (e.g., via `pyproject.toml` `[tool.pytest.ini_options]` `testpaths`
      already scoping to `tests/`, or an explicit `--ignore`) so lab code
      never runs as part of `make quick`/`make validate`.

## Review checklist

- [ ] Confirm the lab-only allow-list genuinely cannot match any
      production-shaped host — review the exact regex/pattern, don't just
      trust the variable name.
- [ ] Confirm `load_lab_config()` really has zero references to
      `pfsense_mcp.config.load_api_key`/`PFSENSE_API_KEY_FILE` — grep,
      don't infer from the function name.
- [ ] Confirm every scenario in `TIER1_LAB_PLAN.md`'s fault-scenario list
      has a corresponding `FaultScenario` entry — line-by-line
      cross-check against the existing plan document, so nothing on that
      list is silently dropped when building the harness.

## Security checklist

- [ ] Confirm `ScenarioReport`/`AcceptanceReport` never contain captured
      request/response bodies, credentials, or raw target data (I4) —
      run the existing repository security scan
      (`scripts/security_scan.py`) against any evidence files the harness
      produces before they are retained anywhere.
- [ ] Confirm `lab/` is covered by the same fixture/security scan
      discipline as `tests/` even though it isn't part of the packaged
      distribution — lab code is still first-party source and subject to
      the same "no credentials, no real IPs" rules.

## Test checklist

- [ ] Offline `load_lab_config()` allow-list and credential-isolation
      tests.
- [ ] Offline `FaultProxy` injection tests against `MockTransport`.
- [ ] Offline `run_full_acceptance()` aggregation test.
- [ ] Offline exit-condition-verification-under-crash test.
- [ ] (Live, gated by separate approval per Activation requirements) full
      run against the provisioned lab VM producing a complete
      `AcceptanceReport` covering every `TIER1_LAB_PLAN.md` scenario.
