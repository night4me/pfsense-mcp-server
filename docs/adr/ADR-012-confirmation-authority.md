# ADR-012: Confirmation authority

- **Status:** Recommended — pending owner decision
- **Date:** 2026-08-08

## Context

`ConfirmationVerifier` (`src/pfsense_mcp/tier1/confirmation.py`) is an
already-implemented, already-tested Protocol with no concrete production
implementation — `store.confirm()` fails closed when none is configured.
A production mutation cannot be confirmed until a real verifier exists.

## Options considered

| Option | Strengths | Costs |
|---|---|---|
| Detached signature, owner key, local verification (**recommended**) | Strong, offline, no new infrastructure beyond a signing workflow | Requires a separate signing-side tool/workflow (out of `pfsense_mcp`'s scope, tracked as its own deliverable) |
| Hardware-backed signature (security key, HSM) | Strongest key custody | Higher operator friction; good v2 upgrade, not required for v1 given the verifier interface is unchanged either way |
| Local confirmation file, atomically consumed | Simple | Weaker than a cryptographic signature unless the file itself carries one — reduces to "detached signature" with extra steps if done correctly, or is insecure if not |
| CLI challenge/response | Familiar UX | Only as strong as its underlying cryptographic derivation — reduces to the same recommendation if done correctly |
| MCP-carried confirmation evidence | Convenient — no out-of-band step | Only acceptable if the evidence itself carries an externally authenticated signature; a plaintext token or boolean over MCP is explicitly rejected (this is the exact class of attack — prompt-asserted approval — the entire confirmation-boundary design exists to prevent) |

## Recommendation

Detached Ed25519 signature over a canonical digest of every
`ConfirmationEvidence` field except `proof` (implemented as
`confirmation_providers.signing_payload()` — deliberately not
`ConfirmationEvidence.evidence_digest`, which is circular as a signature
pre-image; see the linked spec's Invariant I1 implementation note),
verified locally against a pinned public key set with explicit
`authority_id`-based rotation. Private key custody lives entirely outside
the MCP server's host/process. Full specification:
[confirmation_authority.md](../tier1/specs/confirmation_authority.md).

### Self-challenge

*"Why Ed25519 specifically, not RSA or ECDSA which are more commonly
supported across tooling?"* — Ed25519 has no parameter-choice footguns
(no curve selection, no nonce-reuse catastrophic failure mode like ECDSA's
k-reuse issue), small keys and signatures, and fast verification — a
better fit for a from-scratch, first-implementation signing scheme where
minimizing the ways to misconfigure the cryptography matters more than
maximizing tooling compatibility. `cryptography`, already a dependency
per ADR-009, has first-class Ed25519 support, so this adds no additional
library.

*"Should a persistent nonce-replay database be mandatory before this ships,
given the original red-team report listed 'nonce replay store' as an open
item?"* — Reconsidered explicitly, and the recommendation is **no, not for
v1**: replay is already prevented structurally by `contract_id`/
`operation_id` exact binding (verified in
`ConfirmationEvidence.verify_bindings`) and single-use-per-contract
confirmation (`RecoveryContract.with_confirmation` refuses if already
confirmed). A persistent nonce store would add real operational
complexity (retention, restart durability, cleanup) against a threat this
design already closes by other means. If a future review identifies a
concrete replay path this reasoning misses, revisit — but "the original
report listed it as an open question" is not itself evidence a database is
required, and this ADR records the closed reasoning explicitly rather than
leaving it as unresolved caution.

## Consequences

### Positive

- No plaintext/prompt-based approval path exists anywhere in the system.
- Key rotation representable via `authority_id` without a code change.
- No new dependency beyond what encryption already requires.

### Negative

- Requires building and operating a separate signing tool/workflow, which
  is real, non-trivial operational tooling this ADR does not itself
  deliver.
- An owner who loses access to the signing key/device cannot confirm any
  mutation until key recovery/rotation is complete — an intentional
  tradeoff (availability sacrificed for the confirmation guarantee), not
  an oversight.

## Future migration path

Hardware-backed signing (security key, HSM) can replace the signing-side
tool without any change to `Ed25519ConfirmationVerifier` — the verifier
only ever sees a public key and a signature. Revisit the "no nonce-replay
database" decision if a future adversarial review identifies a concrete
replay scenario not already closed by contract-ID binding.

## References

- [confirmation_authority.md](../tier1/specs/confirmation_authority.md)
- [reconciliation_authority.md](../tier1/specs/reconciliation_authority.md)
  (reuses this mechanism)
- `src/pfsense_mcp/tier1/confirmation.py` (existing Protocol)
