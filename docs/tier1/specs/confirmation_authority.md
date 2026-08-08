# Tier 1 — Confirmation authority

Status: implementation-ready specification; implementation not authorized.
Activation gate: Milestone 6 in [TIER1_ROADMAP.md](../../TIER1_ROADMAP.md);
requires [ADR-012](../../adr/ADR-012-confirmation-authority.md).
Related: `src/pfsense_mcp/tier1/confirmation.py` (existing, unchanged by
this spec — this spec defines the `ConfirmationVerifier` implementation,
not the already-built evidence/protocol shape).

## Purpose

Define a concrete, production-usable implementation of the
`ConfirmationVerifier` Protocol already defined in `confirmation.py`, so
that an actual human owner — not an LLM assertion, not a plaintext token —
can authorize exactly one Recovery Contract's execution. The Protocol and
the store-side enforcement (`store.confirm()`) already exist and are
already tested; this spec is scoped to the missing piece: what a real
verifier does.

## Security goals

- G1: A prompt, chat message, or any LLM-generated boolean can never
  satisfy confirmation — confirmation requires a cryptographic signature
  produced by a process the LLM/agent does not control.
- G2: Confirmation evidence for one contract cannot be replayed to confirm
  a different contract, even one that happens to target the same pfSense
  object (already enforced by `ConfirmationEvidence.verify_bindings`
  binding `contract_id`/`operation_id` exactly — this spec's verifier must
  not weaken that).
- G3: The signing key never resides on the host running the MCP server
  process.
- G4: An expired or revoked signing key cannot produce evidence this
  verifier accepts, even if the signature itself is mathematically valid.
- G5: The human confirming can see, in full, what they are approving
  (capability, endpoint, target, intent) before signing — the verifier
  must not be satisfiable by signing a digest alone without an
  operator-facing rendering step existing somewhere in the workflow (the
  rendering step is out of this module's scope but is a hard activation
  requirement — see Activation requirements).

## Invariants

- I1: The verifier checks a detached signature over the canonical
  `ConfirmationEvidence.evidence_digest` bytes (already computed,
  domain-separated via `DigestPurpose.CONFIRMATION`) against exactly one
  pinned public key identified by `evidence.authority_id`.
- I2: `authority_id` must match a currently-active entry in the verifier's
  pinned-key table; an `authority_id` naming a retired or unknown key is
  refused, not matched against "the newest key" or any fallback.
- I3: The verifier itself never persists `evidence.proof` — it is handed
  the evidence object, verifies, and returns a boolean, matching the
  existing `store.confirm()` contract exactly (`store.py` already ensures
  raw proof bytes are never written to the database).
- I4: Verification failures never leak *why* a signature failed (wrong
  key, malformed signature, expired key) beyond a generic refusal, in
  logs or exceptions — mirroring the existing "sanitized failure class"
  discipline used throughout `pfsense_mcp.tier1`.
- I5: The verifier is synchronous, pure with respect to store state (it
  reads its own pinned-key configuration and the passed-in evidence only;
  it does not query `store.py` or any other stateful component), so it
  can be unit-tested without a store fixture.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Signing key vs. MCP host | Owner's separate signing device/workflow | This process, this host | Private key never present here (G3); verifier only ever holds public keys |
| Evidence vs. contract | `store.confirm()`'s authoritative contract load | Caller-supplied `ConfirmationEvidence` | `evidence.verify_bindings(contract)` (existing) + this verifier's signature check |
| Human intent vs. agent intent | Operator-facing rendering + signature | Agent/LLM-constructed `MutationPlan`/intent | Signature can only be produced by a process holding the private key, which the agent never has |

## State ownership

- `src/pfsense_mcp/tier1/confirmation_providers.py` (new module) owns the
  concrete verifier implementation(s): `Ed25519ConfirmationVerifier`.
- The pinned public key table is owned by configuration, loaded the same
  way `PfSenseConfig` loads other settings — fail-closed, no default —
  and is a **list** of `(authority_id, public_key_bytes, active: bool)`
  tuples, not a single key, so rotation (I2) is representable without a
  code change.
- The verifier does not own or construct a `SqliteRecoveryContractStore`
  — it is constructed independently and passed into the store at
  `Application`-equivalent construction time (see `sealed_executor.md`
  for where that wiring lives once activated).

## Interfaces

```python
# src/pfsense_mcp/tier1/confirmation_providers.py (new; not created yet)


@dataclass(frozen=True)
class PinnedAuthority:
    authority_id: str
    public_key: bytes  # 32 bytes, Ed25519 raw public key
    active: bool


class Ed25519ConfirmationVerifier:
    """Concrete ConfirmationVerifier (satisfies the Protocol in
    confirmation.py) using detached Ed25519 signatures."""

    def __init__(self, authorities: tuple[PinnedAuthority, ...]) -> None:
        """Raises ConfigurationError-equivalent if authorities is empty,
        contains duplicate authority_id values, or any public_key is not
        exactly 32 bytes."""

    def verify(self, evidence: ConfirmationEvidence) -> bool:
        """Looks up evidence.authority_id among active authorities;
        returns False (never raises) for: unknown authority_id, inactive
        authority_id, malformed proof, or signature mismatch. Signature
        is verified over evidence.evidence_digest.encode() using the
        pinned public key. algorithm field must equal a fixed accepted
        string (e.g. "ed25519-v1") or verification returns False."""
```

Signing-side tooling (a separate CLI/script, **not** part of the MCP
server process, intentionally outside `pfsense_mcp` entirely) is
out of scope for this spec but is a hard activation requirement — see
below.

## Failure modes

| Failure | Detection | Resulting state | Automatic retry |
|---|---|---|---|
| Wrong/forged signature | Ed25519 verification failure | `verify()` returns `False` → `store.confirm()` raises `ConfirmationError` | No |
| Unknown `authority_id` | Lookup miss in pinned table | `verify()` returns `False` | No |
| Retired `authority_id` (rotated out) | `active=False` in pinned table | `verify()` returns `False` | No |
| Malformed proof bytes (not a valid signature encoding) | Signature library raises → caught, returns `False` | Same as above | No |
| Verifier misconfigured (empty authority table) | Constructor-time validation | Refuses to construct — server cannot start with confirmation enabled and no authority, closing the "no verifier configured" gap from the other direction | No |

## Recovery behavior

- This module holds no durable state of its own — all state is either the
  static configuration (pinned keys) or delegated to `store.py`'s existing
  crash/restart handling. There is nothing new to recover.
- Key rotation (revoking one `authority_id`, adding another) takes effect
  on next process start (configuration reload is not a requirement for
  v1) — an in-flight `PREPARED` contract awaiting confirmation under a
  key that gets rotated out mid-wait will simply fail confirmation and
  eventually expire to `EXPIRED`, which is the correct, safe outcome (no
  special-cased "grandfather the old key for pending contracts" logic,
  which would reintroduce exactly the kind of implicit trust-extension
  this system is designed to avoid).

## Non-goals

- This spec does not implement the signing-side tool the human owner uses
  to review and sign a confirmation request. That tool is deliberately
  outside `pfsense_mcp` (it must not run on the same host/process as the
  thing being confirmed, per G3) and is a separate deliverable, tracked as
  an activation requirement below, not part of this module.
- This spec does not implement hardware-backed signing (e.g., a hardware
  security key). `ADR-012` records this as a future upgrade path that
  requires no change to `Ed25519ConfirmationVerifier` — only the signing
  tool changes, since the verifier only ever sees a public key and a
  signature, regardless of where the private key lived.
- This spec does not implement a nonce-replay database. Per the
  architecture review, replay is already prevented structurally by
  contract-id-exact binding and single-use-per-contract confirmation; see
  `ADR-012` for the explicit reasoning and the condition under which this
  decision should be revisited.

## Required tests

- Valid signature from an active pinned authority → `verify()` returns
  `True`.
- Valid signature from a key not in the pinned table → `False`.
- Valid signature from a retired (`active=False`) authority → `False`.
- Signature over a *different* digest than `evidence.evidence_digest`
  (e.g., signed the raw contract_id instead) → `False`.
- Malformed/truncated `proof` bytes → `False`, no unhandled exception.
- Empty authority table at construction → refuses to construct.
- Duplicate `authority_id` at construction → refuses to construct.
- End-to-end test through `store.confirm()`: a full
  create → transition(PREPARED) → confirm() flow using
  `Ed25519ConfirmationVerifier`, both success and refusal paths, replacing
  the synthetic `_AcceptingVerifier` test double currently used in
  `tests/tier1/test_store.py` for at least one representative test (the
  synthetic double should remain for tests that aren't specifically about
  the verifier's own correctness, to keep those tests focused).

## Activation requirements

- [ ] `ADR-012` accepted (algorithm, key custody model).
- [ ] `confirmation_providers.py` implemented and tested.
- [ ] A separate, reviewed signing-side workflow/tool exists and is
      documented in an operator runbook — this is a hard gate: a verifier
      with no usable signing tool is unusable, and building the tool
      hastily under deployment pressure is how key-custody mistakes
      happen.
- [ ] The operator-facing rendering step (G5 — showing the human what
      they're about to approve) is implemented somewhere in the
      confirmation workflow and reviewed for completeness (it must show
      capability, endpoint, target identity, and intent in
      human-readable form, not just digests) before this module is wired
      into any executor.
- [ ] `cryptography`'s Ed25519 support (already available once the
      dependency is added for `protected_artifact_encryption.md`; no
      second library needed) confirmed sufficient — no new dependency
      required beyond what encryption already introduces.

## Implementation checklist

- [ ] Create `src/pfsense_mcp/tier1/confirmation_providers.py`.
- [ ] Add configuration loading for the pinned-authority table (fail
      closed on empty/malformed, no default, following `config.py`'s
      existing "missing required value fails closed" pattern).
- [ ] Implement `Ed25519ConfirmationVerifier` exactly per Interfaces.
- [ ] Build the separate signing-side CLI as its own deliverable (outside
      `pfsense_mcp`, likely its own small script/repo) — track as a
      distinct implementation task, not a subtask of this module.

## Review checklist

- [ ] Confirm `verify()` never raises — every failure path returns
      `False`, matching `store.confirm()`'s existing
      `except Exception: raise ConfirmationError(...) from None` wrapper
      expectations (defense in depth: even if `verify()` did raise,
      `store.py` already sanitizes it, but the verifier itself should not
      rely on that).
- [ ] Confirm the `algorithm` field is checked against a fixed accepted
      value, not accepted as any string — this prevents a downgrade
      attack where evidence claims a weaker/different algorithm.
- [ ] Confirm the signing tool (reviewed separately) never has network
      access to the MCP server's host, or if it does, that access is
      read-only/one-directional (receiving the rendering, never able to
      push a signature automatically without human action).

## Security checklist

- [ ] No private key material anywhere in `pfsense_mcp` — grep the entire
      package for any private-key-shaped constant or fixture; only public
      keys are ever loaded by `confirmation_providers.py`.
- [ ] Confirm `PinnedAuthority.public_key` validation rejects anything
      that isn't exactly 32 bytes (Ed25519 public key length) — no
      lenient parsing.
- [ ] Confirm failure messages are generic ("confirmation refused"), never
      distinguishing "wrong key" from "unknown authority" from "malformed
      signature" in any user-visible or logged text (I4).

## Test checklist

- [ ] Valid/invalid signature tests (all failure modes above).
- [ ] Retired-authority refusal test.
- [ ] Algorithm-downgrade refusal test.
- [ ] Empty/duplicate authority-table construction refusal tests.
- [ ] End-to-end `store.confirm()` integration test using the real
      verifier.
- [ ] Negative test: module has zero forbidden imports (AST isolation).
