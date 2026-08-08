# ADR-009: Protected-artifact encryption provider

- **Status:** Recommended — pending owner decision
- **Date:** 2026-08-08

## Context

`ProtectedArtifact` (`src/pfsense_mcp/tier1/contract.py`) is deliberately
opaque ciphertext metadata with no codec — the framework authenticates it
with HMAC but does not encrypt it, by design, until a provider is chosen.
`SqliteRecoveryContractStore`'s HMAC proves integrity, not confidentiality:
anyone with read access to the store file can read target identity,
intent, and pre-mutation snapshot in full today, because nothing currently
encrypts them. This must be resolved before Milestone 3 (persistence and
crash contract) can be considered complete, per
[TIER1_ROADMAP.md](../TIER1_ROADMAP.md).

The deployment reality: this server runs as a directly-launched stdio
subprocess (confirmed from this session's actual MCP client configuration)
under a caller-controlled account, on Linux, with no existing crypto
dependency (`pyproject.toml` currently declares only `mcp`, `httpx`,
`pydantic`). It is not necessarily running under systemd.

## Options considered

| Option | Strengths | Costs / failure modes |
|---|---|---|
| OS keyring | Familiar API, rotation indirection | Headless/no-session availability is unreliable; wrong fit for a stdio-launched server with no guaranteed desktop session |
| systemd credential | Strong service-time delivery, tmpfs-backed | Assumes systemd-managed deployment, which this server's actual launch model does not guarantee; still needs a separate encryption primitive underneath |
| libsodium SecretBox/AEAD, local key | Mature AEAD, offline, simple | New dependency; equivalent security properties to the recommended option below with a less common Python binding |
| age-style local encryption | Good for backup/export, auditable recipients | Better fit for cold export than hot, per-record store access; adds subprocess/library complexity for no benefit here |
| TPM-sealed key | Hardware binding | Right idea for the **anti-rollback anchor** (ADR-011), wrong layer for artifact encryption in v1 — disproportionate complexity for the first capability |
| **AES-256-GCM via `cryptography`, local key file (recommended)** | Reuses the exact `O_NOFOLLOW`+`fstat()` pattern already implemented and tested in `config.py` for the pfSense API key; `cryptography` is the most widely reviewed Python crypto library; pairs naturally with `ProtectedArtifact`'s existing `key_id`/`algorithm` fields | New pinned dependency; key-file operator discipline required (see ADR-010) |

## Recommendation

AES-256-GCM via the `cryptography` package, key delivered from a local
file validated with the same `O_NOFOLLOW` + `fstat()` descriptor pattern
already proven in `config.py`, stored in a directory **separate** from the
SQLite store file. Full technical specification:
[protected_artifact_encryption.md](../tier1/specs/protected_artifact_encryption.md).

This is preferred over OS keyring/systemd credential specifically because
it does not assume a deployment model (desktop session, systemd unit)
this server does not actually require today, and it reuses
already-reviewed code rather than introducing a new credential-delivery
pattern alongside the existing one.

### Self-challenge

*"Why not just use systemd credentials — most production Linux deployments
use systemd anyway?"* — Because this project's own MCP configuration in
this session launches the server as a plain subprocess, not a systemd
unit; recommending a mechanism the actual deployment doesn't use would be
architecture divorced from reality. If the owner's actual production
deployment *is* systemd-managed, `ADR-009`'s recommendation still works
unchanged (systemd credentials could deliver the same key-file path this
design already expects) — the local-file pattern is the more general
answer, not a rejection of systemd as a delivery mechanism.

*"Why not derive the encryption key from the same HMAC integrity key to
avoid managing two keys?"* — Rejected: key separation (Security goal G1 in
`key_lifecycle.md`) means compromising one key must not compromise the
other's guarantee. A derived key from a single root is a reasonable
alternative in some designs (HKDF with distinct info strings per purpose)
but adds a key-derivation step whose correctness must itself be reviewed;
two independently-generated keys are simpler to reason about for a first
implementation and are what this ADR recommends. HKDF-based derivation
from one root secret is recorded as a viable future simplification, not
adopted now.

## Consequences

### Positive

- No new credential-delivery pattern to review — extends one already
  accepted.
- `key_id`/`algorithm` fields already in `ProtectedArtifact` support
  rotation without a schema change.
- AES-256-GCM is a FIPS-adjacent, extremely well-reviewed primitive with
  first-class library support.

### Negative

- Adds `cryptography` as a new runtime dependency, requiring its own
  `DEPENDENCY_POLICY.md`-governed review and pinning.
- Local-file key delivery still depends on host filesystem permissions
  being correctly configured by the operator — same class of operational
  trust already accepted for the pfSense API key today.

## Future migration path

`ProtectedArtifact.key_id` already namespaces keys, so a future migration
to OS keyring, systemd credentials, or a TPM-sealed key requires only a
new `load_key_material()`-equivalent function in `key_lifecycle.py` with
the same return shape (`KeyRecord`) — `crypto.py`'s encrypt/decrypt
functions do not need to change. Revisit this decision if production
deployment moves to a systemd-managed or HSM-backed environment where a
stronger delivery mechanism becomes available at no added operational
cost.

## References

- [protected_artifact_encryption.md](../tier1/specs/protected_artifact_encryption.md)
- [ADR-010](ADR-010-key-lifecycle-and-delivery.md)
- [RECOVERY_CONTRACT_SPEC.md](../RECOVERY_CONTRACT_SPEC.md)
- `reports-ai/CLAUDE_TIER1_ARCHITECTURE_REVIEW_v0.3.0.md`
