# Tier 1 — Capability adapter contract

Status: implementation-ready specification; implementation not authorized.
Activation gate: Milestone 9 (first capability, separately authorized);
this document defines the **interface** every future adapter must satisfy,
not any specific adapter.
Related: [sealed_executor.md](sealed_executor.md) (defines the
`CapabilityAdapter` Protocol this document explains how to implement
safely), [adapter_restrictions.md](adapter_restrictions.md) (defines how
violations of this contract are mechanically enforced).

## Purpose

`sealed_executor.md` defines *what* a `CapabilityAdapter` must implement.
This document defines *how* to implement one such that an unsafe
implementation is structurally awkward to write, not merely against the
rules. This is the interface the first real adapter (whichever capability
is eventually authorized) must satisfy — this document does not implement
that adapter.

## Security goals

- G1: The easiest way to implement `build_request()` must be the safe
  way — a narrow, closed, typed model — not the unsafe way (an open
  dict).
- G2: An adapter author who copies this contract's guidance cannot
  accidentally widen the field projection beyond what was approved,
  because the type system, not just documentation, refuses it.
- G3: An adapter's identity/fingerprint functions cannot accidentally
  depend on mutable, non-deterministic, or externally-influenceable state
  (wall-clock time, random values, environment variables).

## Invariants

- I1: Every adapter module defines its own `TypedWriteRequest` subclass
  (Pydantic `BaseModel` with `model_config = ConfigDict(extra="forbid")`,
  matching the existing strict-typing convention already used for READ
  response models in this codebase) — `extra="forbid"` is not optional
  guidance, it is the mechanism that makes G1/G2 true: a caller (or a
  compromised/careless future edit) that tries to add a field the model
  doesn't declare gets a validation error, not silent pass-through.
- I2: `natural_identity()` and `fingerprint()` are declared as
  `@staticmethod` or free functions wherever the language allows it, to
  make "this cannot read `self` state" structurally visible in the
  signature, not just true by convention.
- I3: The full set of fields an adapter's `fingerprint()` reads from the
  raw target must be a documented, explicit list in the adapter's module
  docstring — including every field that must **not** change
  (name/type/other identity-adjacent fields for the alias-description
  case) as well as the ones that legitimately do. A fingerprint that
  silently omits a field is a silent hole in drift detection.
- I4: `build_request()`'s input type is the **decrypted, canonicalized**
  intent object (already validated by `canonical.py` at contract-
  preparation time) — never the raw MCP tool call arguments. This keeps
  "what the operator confirmed" and "what gets sent" provably the same
  object lineage, not two independently-constructed things that happen to
  agree today.
- I5: `is_semantically_verified()` must compare **every** field the
  projection is allowed to change against the intended value, and
  **every** field the projection forbids from changing against the
  pre-state — an implementation that only checks the changed field is
  incomplete by this contract's definition, not merely weak.

## Trust boundaries

Adapter code trust boundaries are identical to those in
`sealed_executor.md` — this document does not introduce new boundaries,
it explains how to write code that respects the ones already defined
there without needing the author to re-derive them.

## State ownership

Adapters own no state (per `sealed_executor.md`). This document's
contribution is guidance on how to keep it that way in practice: an
adapter class (if a class is used at all, vs. a module of functions) must
have no `__init__` parameters beyond static, immutable configuration
(e.g., nothing) — if an adapter "needs" a client or a key, that is a sign
the design has leaked executor responsibility into the adapter and must be
rejected in review.

## Interfaces

This document does not redefine the `CapabilityAdapter` Protocol — see
`sealed_executor.md`'s Interfaces section for the authoritative
definition. This section gives the **shape a compliant implementation
takes**, illustrated generically (not for any specific approved
capability — no endpoint/capability names below should be read as
pre-approving a candidate; compare against
`WRITE_ENDPOINT_RISK_MATRIX.md`/`TIER1_ACTIVATION_DECISIONS.md` for actual
candidates):

```python
# Illustrative shape only — not a real adapter.

class _ExampleIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    natural_key: str
    projected_field: str = Field(max_length=255)

class _ExampleWriteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    projected_field: str = Field(max_length=255)
    # No other field. Adding one requires touching this model directly,
    # which is a reviewable diff — not a silent runtime behavior change.

class _ExampleAdapter:
    endpoint_symbol: str = "EXAMPLE_ENDPOINT"
    http_method: str = "PATCH"
    capability: Capability = Capability.EXAMPLE_WRITE  # not a real enum member

    @staticmethod
    def natural_identity(raw_target: RawReadModel) -> CanonicalValue:
        return {"natural_key": raw_target.natural_key}

    @staticmethod
    def fingerprint(raw_target: RawReadModel) -> CanonicalValue:
        # Every field that must not silently change, explicitly listed.
        return {
            "natural_key": raw_target.natural_key,
            "forbidden_field_a": raw_target.forbidden_field_a,
            "forbidden_field_b": raw_target.forbidden_field_b,
        }

    @staticmethod
    def build_request(intent: _ExampleIntent) -> _ExampleWriteRequest:
        return _ExampleWriteRequest(projected_field=intent.projected_field)

    @staticmethod
    def is_semantically_verified(
        pre: RawReadModel, post: RawReadModel, intent: _ExampleIntent
    ) -> bool:
        return (
            post.projected_field == intent.projected_field
            and post.forbidden_field_a == pre.forbidden_field_a
            and post.forbidden_field_b == pre.forbidden_field_b
        )
```

## Failure modes

| Failure | Detection | Resulting state | Automatic retry |
|---|---|---|---|
| Adapter's `build_request()` raises (invalid intent shape) | Exception propagates to executor before any send | Executor treats as pre-send refusal, `FAILED`, zero sends | No |
| Adapter's `fingerprint()` omits a field that later changes unexpectedly | **Not detectable by the framework** — this is exactly why I3 requires explicit, reviewed field enumeration; a code-review gap here is a real residual risk this contract cannot fully close by itself | Silent drift undetected until a human notices | N/A — this is a review discipline requirement, not a runtime check |
| `is_semantically_verified()` returns `True` for a case it shouldn't (bug) | Not detectable by the framework at runtime | Contract incorrectly reaches `VERIFIED` | N/A — required-tests below are the mitigation |

## Recovery behavior

Adapters have no recovery behavior of their own — recovery is entirely
the executor's and store's responsibility (see `sealed_executor.md`).

## Non-goals

- This document does not approve any specific capability, endpoint, or
  field projection — that remains a separate, explicit authorization per
  `TIER1_ROADMAP.md` Milestone 0/9.
- This document does not define a code-generation tool for adapters. A
  future `scaffold_capability.py`-style generator (the repository already
  has a READ-side scaffolding script) is a reasonable future convenience
  but is out of scope here.

## Required tests

Every adapter, once one is authorized and written, must include:

- Round-trip test: `build_request(intent)` produces exactly the expected
  narrow payload for a representative intent, and rejects (via Pydantic
  validation) any attempt to construct an intent or request with an extra
  field.
- Fingerprint completeness test: mutate each field in the adapter's own
  documented forbidden-field list independently, assert
  `is_semantically_verified()` returns `False` for each — this is the
  test that would have caught an incomplete comparison (Failure modes,
  third row), and it must be written against the documented field list in
  the adapter's own docstring (I3), not against whatever the
  implementation happens to check, so a reviewer can see the test was
  derived from the spec, not from the code.
- Positive verification test: only the approved field differs, all
  forbidden fields match pre-state → `True`.
- Adapter isolation test: the adapter module itself passes the AST checks
  in `adapter_restrictions.md`.

## Activation requirements

- [ ] `sealed_executor.md`/`ADR-014` accepted (defines the Protocol this
      contract targets).
- [ ] The specific capability this adapter implements has separate,
      explicit authorization (Milestone 0/9) naming the exact endpoint,
      method, and field projection.
- [ ] Disposable-lab evidence (`disposable_lab_execution_model.md`) exists
      proving the adapter's assumptions about upstream API behavior
      (partial-PATCH semantics, implicit reload, etc.) before the adapter
      is written against them.

## Implementation checklist

(Applies to whichever adapter is eventually authorized — no adapter exists
yet.)

- [ ] Define `TypedWriteRequest`/intent models with `extra="forbid"`.
- [ ] Enumerate every fingerprint field in the module docstring before
      writing `fingerprint()`, not after.
- [ ] Implement all `CapabilityAdapter` Protocol methods as
      `@staticmethod`/pure functions.
- [ ] Write the fingerprint-completeness test first (per I3/I5), then
      implement `is_semantically_verified()` against it.

## Review checklist

- [ ] Confirm every model uses `extra="forbid"` — a model without it is
      an automatic review rejection, not a style preference.
- [ ] Confirm the fingerprint field list in the docstring matches what
      `fingerprint()` actually reads — line-by-line, not by skimming.
- [ ] Confirm no adapter method reads wall-clock time, randomness, or
      environment state (I3's determinism requirement).
- [ ] Confirm `build_request()`'s input type is the contract's decrypted
      intent type, not raw MCP arguments (I4) — trace the actual call
      site in `executor.py`, don't assume from the adapter's signature
      alone.

## Security checklist

- [ ] Confirm no adapter code path can construct a `dict` and pass it
      anywhere the executor treats as a validated request (I1/G1).
- [ ] Confirm the adapter's own tests include the fingerprint-completeness
      test (required, not optional) before the adapter can be merged.
- [ ] Confirm the adapter has zero imports flagged by
      `adapter_restrictions.md`'s AST check.

## Test checklist

- [ ] Round-trip / rejection tests for both intent and request models.
- [ ] Fingerprint-completeness test (every forbidden field individually).
- [ ] Positive verification test.
- [ ] Adapter isolation AST test.
