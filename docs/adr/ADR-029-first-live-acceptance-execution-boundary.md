# ADR-029: First-live-acceptance execution boundary

- **Status:** Accepted (2026-08-16, owner)
- **Date:** 2026-08-16
- **Scope:** Architecture and implementation for resolving the first-live-
  acceptance evidence circularity discovered during a real W3 Slice 6
  execution attempt (2026-08-15/16). This ADR authorizes exactly one new,
  narrowly-scoped execution path for gathering ADR-026's remaining live
  evidence (rows 6, 17, 18) against the disposable LAB pfSense only. It does
  not authorize a second WRITE capability, a generic bypass mechanism, or
  any change to normal `WriteApiClient`/`MutationExecutor` behavior.

## Context

W3 Slice 6 (live acceptance of `FIREWALL_ALIAS_DESCRIPTION`, the sole
`WriteEndpoints` entry) was authorized and attempted end-to-end against the
disposable LAB pfSense on 2026-08-15/16, after all four provisioning steps
(witness client, Tier1 runtime state, authority keypairs + a genuinely
separate signer, RecoveryContract store schema) completed successfully.
Phase A (pre-flight) and Phase B (LAB alias selection) both passed. Phase C
(bootstrap semantics) discovered a genuine, previously-undocumented
architectural circularity and correctly hard-stopped rather than improvise
(see `reports-ai/reviews/W3_SLICE6_LIVE_ACCEPTANCE_HARD_STOP_2026-08-16.md`).

### The circularity

`WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.verified` is `False`. ADR-026's
first-WRITE acceptance matrix rows 6 ("explicit apply/reload suppression
contract"), 17 ("least privilege for exact endpoint/capability"), and 18
("sufficient authoritative side-effect evidence") remain `MUST COMPLETE` —
the only remaining gate before `verified` may become `True`. Row 18 in
particular requires observing the *actual effects* of a real
alias-description mutation; it cannot be satisfied by inference, offline
tests, or documentation reading alone.

`write_api_client.py`'s `WriteApiClient.dry_run()`, `.execute()`, and
`.send_for_tier1()` (the sealed Tier 1 executor's only entry point to
pfSense) each unconditionally refuse when `endpoint.verified` is not `True`:

```python
if not endpoint.verified:
    raise WriteNotAllowedError(...)
```

This is deliberate (`write_endpoints.py`'s own docstring: *"This is an
intentional, additional layer of protection beyond the activation gate, not
an oversight"*), and no override, flag, or bootstrap path exists anywhere in
the codebase. The result: the live evidence required to justify
`verified=True` can only be gathered by successfully sending a real mutation
through `WriteApiClient`, but `WriteApiClient` refuses to send anything
(including a dry-run) until `verified=True` already holds. No code path in
the shipped implementation resolves this.

### Rejected alternatives

**Raw/manual PATCH outside the Tier1 architecture.** Rejected by explicit
owner decision. It would gather row 6/17/18 evidence about the *underlying
pfSense API's* behavior, but proves nothing about *this codebase's*
authorization → contract → execution → confirmation → reconciliation chain,
which is what actually needs live evidence before being trusted with a real
send. It also reintroduces exactly the class of risk (unmediated, unaudited,
non-idempotent mutation) the whole Tier1 architecture exists to eliminate.

**Provisional `verified=True`.** Rejected by explicit owner decision. Setting
`verified=True` before evidence exists inverts the acceptance matrix's own
ordering (`verified` is meant to be a *consequence* of evidence, never a
precondition manufactured to obtain it) and would leave the endpoint
permanently marked verified regardless of what the first live attempt
actually showed.

**A generic bypass flag** (`execute(..., force=True)`, an environment
variable, monkeypatching the catalogue, a temporary catalogue mutation).
Rejected: any of these would be reachable by more than the one narrow
ceremony they were built for, and several (env var, catalogue mutation)
would affect the *entire process*, not one call — directly contradicting
"acceptance-only execution eligibility," not just an unfortunate side effect.

## Decision

Separate two previously-conflated concepts that `WriteEndpointInfo.verified`
currently represents at once:

- **Normal exposure eligibility** — whether this endpoint is available
  through the ordinary `WriteApiClient` surface (`dry_run()`/`execute()`/
  `send_for_tier1()`) and, eventually, any MCP tool built on it. Continues to
  require `verified == True`, checked exactly as today, in exactly the same
  three methods, **unmodified**.
- **Acceptance execution eligibility** — whether this specific endpoint may
  be exercised through a separate, narrowly-typed, structurally-isolated
  path whose *only* purpose is gathering the live evidence needed to justify
  flipping `verified`. Governed by a new, independent catalogue field,
  `WriteEndpointInfo.acceptance_eligible: bool`, `True` only for
  `FIREWALL_ALIAS_DESCRIPTION`.

### Architecture

```
WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION
    verified = False              (unchanged)
    acceptance_eligible = True    (new)

tier1/acceptance.py                          <- new module
    AcceptanceExecutionContext (frozen dataclass)
    issue_acceptance_context(pf_config, endpoint_symbol=...)
        - hardcodes and checks the exact LAB base_url + identity
          (compile-time constants, never read from env)
        - re-derives the endpoint from WriteEndpoints (never trusts a caller
          -supplied endpoint object)
        - refuses unless acceptance_eligible is True
        - refuses unless verified is False  <-- the one-time gate (see below)

write_api_client.py
    WriteApiClient.send_for_tier1_acceptance(*, acceptance_context, ...)
        - NEW, additive method; send_for_tier1()/execute()/dry_run() are
          byte-for-byte unchanged
        - independently re-validates: endpoint.acceptance_eligible,
          endpoint.verified is False, context fields agree with the live
          call arguments, self._identity equals the pinned LAB identity
        - on success, delegates to the SAME private _request() transport
          helper send_for_tier1() already uses -- no duplicated wire logic

executor.py (MutationExecutor)
    execute(..., acceptance_context: AcceptanceExecutionContext | None = None)
    _send(..., acceptance_context=None)
        - default (None): calls write_client.send_for_tier1(...) exactly as
          today -- every existing call site, and rollback(), is unaffected
        - when supplied: calls write_client.send_for_tier1_acceptance(...)
          instead -- the entire surrounding state machine, fingerprint/
          target/lifecycle-locator verification, and fault classification
          is 100% shared, unmodified code

alias_description_execution.py (AliasDescriptionExecutionCoreV1)
    confirm_and_handoff(..., acceptance_context=None)
        - threads the parameter through to executor.execute(); authorization
          consumption, contract creation, and confirmation verification
          above this point are completely unmodified

production_runtime.py (ProductionAliasDescriptionRuntime)
    request_alias_description_change(..., acceptance_context=None)
        - threads the parameter through to confirm_and_handoff()
```

Every threaded parameter defaults to `None` and every existing call site
(including every test) is unaffected by construction — proved by a
regression test asserting `build_production_runtime()`'s normal path is
unchanged.

### Trust boundary

`tier1/acceptance.py` is never imported by `production_runtime.py`'s own
construction path in a way that reaches the MCP surface, by `application.py`,
`server.py`, `factory.py`, or any tool-registration module — enforced by a
dedicated AST-based isolation test, the same technique
`tests/test_signing_tool_isolation.py` already uses to prove no production
module imports `signing.*`. `AcceptanceExecutionContext` is a plain Python
object with no JSON-schema-compatible representation; there is no way for an
MCP tool's argument schema (derived from Pydantic/JSON-primitive input
models) to construct or pass one. Today `request_alias_description_change()`
itself remains entirely unreachable from any MCP tool (Slice 4, unstarted) —
so there is currently zero live path from any external caller to any of this
code, by the pre-existing architecture alone. This ADR's isolation guarantee
is additionally future-proofed for whenever Slice 4 does wire an MCP tool to
this method: `issue_acceptance_context()` is never called from that wiring,
so no ordinary tool invocation will ever populate `acceptance_context`.

### Fail-closed properties preserved unmodified

Because every existing method (`authorize_and_create`, `confirm_and_handoff`'s
confirmation-verification logic, the contract state machine, fingerprint/
target/lifecycle-locator binding, `AuthorizationConsumptionStore.try_consume()`,
the anti-rollback anchor requirement in `build_production_runtime()`, and
reconciliation) is either completely untouched or only gains a
default-`None`, behavior-preserving parameter, every Tier1 invariant applies
identically in acceptance mode:

- Real `PlanAuthorizationV2`, independently signature-verified, is still
  required before any `RecoveryContract` reaches PREPARED.
- Real `ConfirmationEvidence`, independently signature-verified and bound to
  the exact contract/request, is still required before executor handoff.
- The contract state machine (PREPARED → EXECUTING → VERIFIED/FAILED/
  RECONCILIATION), its CAS-based transitions, and durable-before-effect
  ordering are unchanged.
- `MutationExecutor`'s exactly-once-send discipline, fault classification,
  and post-send authoritative read-back/verification are unchanged.
- Anti-rollback anchor provisioning (`read_only_anchor_provisioning_status()`)
  is required for `build_production_runtime()` to construct at all, exactly
  as today.
- Reconciliation, if ever needed, uses the same signed, pinned-authority
  path, unmodified.

### Target/endpoint restriction

`issue_acceptance_context()` hardcodes two compile-time constants —
`https://pfsense-test.lab.invalid` and `pfsense_lab1` — and refuses unless
the supplied `PfSenseConfig` matches both exactly. This is deliberately not
read from environment configuration: an operator error in `PFSENSE_API_URL`
cannot cause this path to target anything else, because the comparison value
itself is not derived from that same environment. `send_for_tier1_acceptance()`
independently re-checks the `WriteApiClient` instance's own bound identity
against the same pinned constant, a second, structurally-independent check.
Endpoint restriction is enforced by `WriteEndpoints.acceptance_eligible`
being `True` for exactly one catalogue entry, mechanically alongside the
existing "exactly one `WriteEndpoints` entry" enforcement
(`scripts/write_allow_list_check.py`).

### Lifecycle / one-time semantics

No new durable/persistent state is introduced for the one-time property.
Two independently-owned, already-durable facts provide it:

1. **`verified` itself is source code, not runtime state.** Flipping it to
   `True` requires an edited, reviewed, committed source file — it can never
   change during a running process, and once a build with `verified=True`
   ships, `issue_acceptance_context()` and `send_for_tier1_acceptance()`'s
   own independent re-checks both permanently refuse (`endpoint.verified is
   False` is required at both issuance and send time). This is the existing
   durable evidence this ADR reuses rather than inventing a new flag,
   per the owner's explicit "use existing durable evidence/state where
   sufficient" instruction.
2. **Replay/repetition within a single unverified run** is already
   prevented by the unmodified authorization-consumption and contract
   state-machine layers (burn-on-use `authorization_id`, CAS-based state
   transitions) — the same protection the normal path already relies on,
   not something acceptance mode needs its own copy of.

### Rejected: a persistent "acceptance already run" flag

Considered and rejected as unnecessary complexity: it would duplicate a
property already guaranteed by (1) above, and would itself become a new
piece of durable state requiring its own integrity/tamper protection for no
security benefit over what already exists.

## Consequences

- Two new, small, additive surfaces (`WriteEndpointInfo.acceptance_eligible`,
  `WriteApiClient.send_for_tier1_acceptance`) plus one new isolated module
  (`tier1/acceptance.py`) and four narrowly-scoped, default-preserving
  parameter additions through the existing call chain.
- `verified=False` continues to mean "not normally exposed" exactly as
  before; it now additionally coexists with a distinct, separately-gated
  "may gather its own promotion evidence" property, but only for the one
  endpoint this ADR explicitly names.
- No change to default or currently-configured MCP exposure: 42 READ / 0
  WRITE remains true regardless of this ADR, until `verified` is separately
  and explicitly promoted based on the evidence this path gathers.

## Owner decision status

This ADR fully resolves the policy question the owner posed (raw PATCH and
provisional `verified=True` both explicitly rejected; the separation-of-
concerns model, trust boundary, lifecycle reasoning, and scope restriction
are all owner-specified requirements, not open design choices). No material
policy choice remains outstanding. Accepted.
