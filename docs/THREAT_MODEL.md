# Threat model

Version: v0.3.0 production baseline (same active READ path as v0.2.2) with inert Tier 1 development framework and inert ADR-017 guidance-layer scaffolding
Scope: current local stdio MCP server, 41 READ tools, unreachable WRITE infrastructure, and the unreachable official-documentation guidance layer

## Purpose and scope

This document models threats to the current production architecture. It covers
the local MCP process, its configuration and credential file, stdio caller,
pfSense REST API connection, typed response mapping, logs, fixtures, package
artifacts, and dormant Tier 0 WRITE modules.

It does not claim that a compromised operating-system account or compromised
pfSense appliance can be made trustworthy. The isolated Tier 1 domain framework
is included in this analysis, but no WRITE capability, endpoint, executor, or
tool is active or authorized by this document. The isolated official-
documentation guidance layer (`ADR-017`) is included in this analysis on the
same terms: it is inert scaffolding with no consumer, and this document does
not authorize wiring it into any READ tool output or any Tier 1 PREPARE path.

## Assets

| Asset | Security objective |
|---|---|
| pfSense API key | Confidentiality; use only in the upstream API-key header |
| pfSense configuration and operational data | Confidentiality and integrity |
| Appliance identity and topology | Confidentiality; optional disclosure only where modeled |
| MCP tool schemas and outputs | Integrity, predictable typing, credential non-disclosure |
| Capability/profile configuration | Integrity; no unauthorized tool registration |
| Endpoint registries | Integrity; production READ path remains GET-only |
| Audit and operational logs | Integrity, availability, and absence of values/secrets |
| Approved fixtures | Synthetic/sanitized integrity; no production identifiers or credentials |
| Package artifacts and source | Integrity and absence of private/local files |
| Recovery Contract state (future) | Integrity, confidentiality, freshness, target binding, durability |
| Official-guidance registry/content (inert, `ADR-017`) | Integrity of the capability→document mapping; content provenance; never a source of authorization |

## Trust boundaries

### TB1 — MCP caller to local server over stdio

The process that launches and controls stdio is the caller-authentication
boundary. The server does not authenticate individual MCP messages or
differentiate users sharing the same channel. A caller with channel control can
invoke every tool in the selected profile.

### TB2 — process to local filesystem

Configuration arrives through environment variables. The API key and optional
CA bundle are local files. On the supported Linux production platform, the key
is opened with `O_NOFOLLOW`; ownership, type, permissions, and size are checked
with `fstat()`, and the same descriptor is read and reliably closed. Logs and
local stores depend on operating-system directory permissions.

### TB3 — server to pfSense over HTTPS

The server sends GET requests with one upstream API identity. TLS validation is
strict by default; an explicit CA bundle is supported. `insecure` is a
deliberate operator override that removes server authentication.

### TB4 — untrusted upstream JSON to typed public models

pfSense responses are untrusted input. Shape checks and Pydantic factories
translate them to public models. Prohibited credential fields are absent from
those models and ignored if upstream returns them.

### TB5 — runtime data to logs/errors

Audit and transport logging cross from runtime state into persistent local
records. Policies permit tool/endpoint identity, duration, status classes, and
disclosure choices—but not arguments, payloads, responses, credential values,
or exception messages.

### TB6 — development/private evidence to repository artifacts

Fixtures, reports, distribution archives, CI artifacts, and documentation must
not contain credentials or identifying appliance data. Capture uses proposal,
sanitization, audit, and explicit approval stages.

### TB7 — dormant WRITE code to production bootstrap

Tier 0 WRITE modules are untrusted future infrastructure from the perspective
of current production safety. They are separated by construction: no production
construction, no WRITE profile capability, no endpoint allow-list entry, no
registered WRITE tool, and static tests for each boundary.

### TB8 — inert Tier 1 records to future mutation execution

The v0.3.0 framework accepts contract material only at creation, canonicalizes
and authenticates stored records, enforces compare-and-set legal transitions,
and reserves one canonical target during execution. Protected intent and
snapshot artifacts are opaque ciphertext supplied by a future key provider.
There is currently no executor consuming those records.

### TB9 — official documentation content to guidance output (inert, `ADR-017`)

The guidance layer's registry is Git-tracked, PR-reviewed, load-once data;
bundled excerpt content is treated as untrusted **content** even though its
**source** (official pfSense/Netgate documentation) is comparatively trusted —
this distinction is load-bearing, not cosmetic (see `OFFICIAL_GUIDANCE_LAYER.md`
TB-G2). `GuidanceReference` output has no field of type capability, endpoint,
method, or confirmation token, verified by an isolation test rather than by
convention alone. Live retrieval and any registry-writable path are explicitly
out of scope for the accepted architecture; there is currently no consumer of
this layer's output.

## Attacker models

### A1 — malicious or compromised MCP caller

Has full access to the local stdio MCP protocol but no shell access, no direct
credential-file access, and no pfSense credentials beyond what the server can
exercise. Goals include data discovery, credential extraction, tool abuse,
resource exhaustion, error/log injection, and reaching dormant WRITE paths.

### A2 — untrusted upstream appliance/API response

Can return malformed, oversized, adversarial, credential-bearing, or confusing
JSON and HTTP status codes. May attempt to induce value leakage through model
validation errors, logs, or exception messages.

### A3 — local unprivileged user

Can inspect generally accessible process/filesystem state but cannot write the
mode-0700 private parent directories or control the server account. May try to
read logs, replace configuration files, inject environment values through a
launcher, or race file validation.

### A4 — compromised launching account

Can control environment, stdio, key files, local logs, and executable code.
This actor is largely outside the security boundary: the local deployment model
trusts the launching account. Defense-in-depth can reduce accidental exposure
but cannot preserve upstream credential secrecy from this actor.

### A5 — malicious contributor or dependency

Can propose source/workflow/documentation changes or compromise a package/action
dependency. Goals include secret collection, CI exfiltration, capability
activation, artifact tampering, and bypassing checks.

### A6 — future authorized WRITE caller

Not relevant to current reachability, but critical to Tier 1. May replay or
substitute contracts, targets, intents, and rollback actions; race transitions;
or exploit ambiguous network outcomes.

### A7 — compromised or spoofed official-documentation source (inert, `ADR-017`)

Not relevant to current reachability (no consumer exists), but modeled ahead
of activation. Could attempt to have malicious or misleading content bundled
into the registry (via A5's contributor path), or — only if the deferred
live-retrieval extension is ever built — serve altered content from an
otherwise-allow-listed domain. Goals include prompt injection against a
future model consumer, steering a human toward an unsafe manual action, and
(the specifically-designed-against outcome) attempting to have guidance
content mistaken for authorization. See `OFFICIAL_GUIDANCE_LAYER.md` TB-G2/
TB-G3 and the guidance-layer adversarial-paths table below.

## STRIDE analysis

| Category | Threats | Current mitigations | Residual risk |
|---|---|---|---|
| Spoofing | Caller claims another identity; attacker impersonates pfSense; contract identity substitution | Local launcher is the caller boundary; `PFSENSE_IDENTITY` is explicitly upstream identity; HTTPS strict/default or explicit CA; redirects rejected; inert contracts are loaded authoritatively and exact-bound | No per-message caller identity; `insecure` TLS permits upstream spoofing; operator confirmation authentication is not selected |
| Tampering | Modify capability/profile, endpoints, key/CA files, fixtures, artifacts, responses, logs; modify or spoof guidance-registry content | Explicit registries; static GET/WRITE checks; descriptor-bound `O_NOFOLLOW`/`fstat()` key loading; typed models; public-contract snapshot; fixture audit; pinned actions; artifact member/content checks; file permissions; guidance registry is Git-tracked/PR-reviewed only, load-time content-hash self-check (`ADR-017` I2/I3) | Launch-account compromise defeats local integrity; logs are not cryptographically append-only; a merged malicious registry entry is only caught by review, not by any runtime check (same residual class as any other reviewed-content risk) |
| Repudiation | Caller denies sensitive metadata request or tool use; future mutation lacks trace | Structured READ audit plus inert value-free Tier 1 audit events and atomic store events | stdio caller has no individual identity; local log/store owner can alter or roll back files; audit is operational, not non-repudiation evidence |
| Information disclosure | Credentials in schemas/output/errors/logs/fixtures/docs; topology leakage; exception/body leakage | Credential fields removed; upstream values ignored; optional metadata default-off; sanitized typed transport/API errors; no values/messages in audit; fixture and package hard refusal; security scan; private report policy | Ordinary READ data is still sensitive; public certificates identify infrastructure; trusted caller can request optional metadata; local launcher controls the credential |
| Denial of service | Large limits, slow appliance, malformed responses, log exhaustion, repeated calls | Limits bounded 1–100; HTTP timeouts; response shape validation; rotating bounded logs; process-local stdio; fail-closed config | No per-caller rate limit; a channel controller can saturate process/upstream within timeout/limit bounds; upstream can remain slow or unavailable |
| Elevation of privilege | Reach WRITE transport, register hidden tools, arbitrary endpoints/methods, profile confusion; guidance content mistaken for or manipulated into authorization | GET-only `RestApiClient`; explicit `ToolRegistry`; accepted profile set; empty WRITE allow-list; inactive WRITE capabilities; empty inert Tier 1 policy; no production write-client construction; static architecture checks; `GuidanceReference` has no capability/endpoint/method/confirmation-token field, isolation-tested against every safety-authority import (`ADR-017` G1/G4) | Launch-account/source compromise can alter code/config; activation must replace zero-entry assertions through explicit review rather than remove them; a reviewer who merges a malicious registry entry is still the same A5 risk this table already names elsewhere |

## Security assumptions

- The launching operating-system account and its executable environment are
  trusted.
- Parent directories holding the API key are not writable by another user.
- The configured upstream API key is least-privilege and pfSense REST API is
  configured `read_only=true` for current production use.
- MCP stdio is not bridged to untrusted network clients without an external
  authentication/authorization layer.
- The operating system, Python runtime, certificate store, and installed
  dependencies are maintained and not malicious.
- `MockTransport` and approved fixtures—not production appliances—are used in
  public development and CI.
- Operators understand that `include_identifying_metadata=true` is an explicit
  sensitive-data disclosure and that `PFSENSE_TLS_MODE=insecure` disables
  upstream authentication.

## Existing mitigations

### Credential and data controls

- API key opened without following symlinks, validated by descriptor, read from
  the same inode within strict bounds, and closed on every path.
- Password, PSK, private-key, plaintext API-key, and stored-hash fields excluded
  from public models and schemas.
- Optional sensitive metadata omitted by default and disclosure choice audited.
- Public certificate material classified separately from private keys.
- No raw bodies, arguments, responses, or exception messages in logs.

### Request controls

- One configured HTTPS origin, no URL user info/path/query/fragment.
- Production `RestApiClient` accepts GET only.
- Endpoint, API-version, capability, and bounded-parameter validation.
- Typed connection/auth/API/shape errors with sanitized messages.

### Development and supply-chain controls

- Offline tests; live tests require explicit opt-in and private configuration.
- Credential-field fixture rejection and repository security scans.
- Ruff, mypy, Bandit, CodeQL workflow, pinned GitHub Actions, and branch coverage.
- Sdist/wheel member inspection and clean entry-point installation.
- Explicit approval boundaries for live calls, Git publication, and releases.

### WRITE isolation

- Zero registered WRITE tools and zero allow-listed WRITE endpoints.
- Zero active WRITE capabilities.
- No write client/store/audit construction in production bootstrap.
- Separate transport chokepoint and regression checks for import absence,
  allow-list emptiness, and capability inactivity.

## Residual risks

1. **Trusted-channel breadth:** an MCP caller controls the complete auditor
   capability set; there is no per-tool caller authorization.
2. **Sensitive operational output:** read-only does not mean non-sensitive.
   DHCP, ARP, DNS, policy, package, service, and certificate data can materially
   aid an attacker.
3. **Explicit insecure TLS:** operator-selected `insecure` mode permits a
   man-in-the-middle to observe the API key and forge responses.
4. **Log integrity:** rotating local logs are value-minimized but not
   cryptographically tamper-evident.
5. **Dependency compromise:** pinned actions reduce workflow drift, but Python
   dependencies use bounded ranges rather than hashes/lock constraints.
6. **Historical certificate identity:** current certificate fixtures are wholly
   synthetic, but earlier public fixture material remains in Git history. It
   contained public certificate data, not a private key or credential.
7. **Dormant-code drift:** Tier 0 modules can accumulate defects despite being
   unreachable; tests and activation gates must remain mandatory.
8. **No current rate limiting:** a trusted-channel attacker can cause bounded
   upstream load and local log activity.
9. **Tier 1 key management:** the inert store authenticates records but does
   not encrypt protected artifacts itself; activation requires an approved
   external encryption/key provider.
10. **Whole-store rollback:** record MACs detect modification, not restoration
    of an older valid database. Activation requires a durable monotonic
    anti-rollback anchor and reconciliation procedure.
11. **Confirmation identity:** exact-bound evidence and a verifier interface
    prevent self-asserted confirmation, but no production authority/key is
    selected. Activation requires an owner/authentication decision.

## Future considerations

- Evaluate dependency constraints, provenance/attestation, and advisory scanning
  after CI baseline stability.
- Consider per-caller authorization only if transport expands beyond trusted
  local stdio; do not bolt network exposure onto the current model.
- Add optional tamper-evident audit forwarding without including values.
- Add resource/rate controls if observed workloads justify them.
- Keep certificate fixtures wholly synthetic and reject private-key material.
- Tier 1 contracts, canonical binding, legal transitions, record
  authentication, target reservations, and restart reconciliation now exist as
  inert domain controls. Before activation, add the approved key provider,
  anti-rollback anchor, authenticated confirmation, capability-specific
  payload/target logic, exact HTTP/read-back validation, and lab evidence.

See [Tier 1 roadmap](TIER1_ROADMAP.md) for future WRITE requirements and
[security model](SECURITY_MODEL.md) for normative data classification.

## Tier 1 adversarial paths

These paths apply to the inert v0.3.0 framework and any future executor. A
framework mitigation does not authorize activation.

| Attack or fault | Current inert mitigation | Residual activation requirement |
|---|---|---|
| Prompt injection claims approval | Confirmation digest is a separate contract fact, not an MCP boolean | Authenticate owner confirmation outside prompt text |
| Malformed or oversized tool request | Canonical types and identifiers fail closed; no tool exists | Capability-specific typed models and evidence-based size limits |
| Contract replay or duplicate invocation | Unique contract/operation/idempotency identities and state CAS | Durable anti-rollback anchor and upstream idempotency evidence |
| Capability, endpoint, or method substitution | Exact immutable contract and policy tuple | Independently reviewed non-empty rule and endpoint declaration |
| Endpoint confusion or malicious registration | Empty exact policy; no prefix/wildcard inference | Static manifest parity and owner-approved path/method/version |
| Stale snapshot or concurrent target update | Fingerprint binding and one-target reservation | Immediate authoritative re-read and capability drift projection |
| Unstable numeric ID targets wrong object | Natural identity is authoritative; IDs are locator hints only | Lab proof of uniqueness and duplicate/missing-target refusal |
| Timeout, reset, or lost response after send | Fault model selects `RECONCILIATION`; retry is always false | Executor must record send boundary and implement semantic read-back |
| Process crash during execution or rollback | Durable acquisition; restart moves interrupted records to reconciliation | Fault tests around every actual transport boundary |
| Corrupt or foreign record | Record HMAC and denormalized-index cross-check | Key lifecycle, quarantine, and operator recovery runbook |
| Whole-store rollback to an older valid copy | Explicitly recognized as undetectable locally | External monotonic anti-rollback evidence |
| Conflicting or partial rollback | Closed rollback states; no automatic retry | Capability-specific inverse, unrelated-change detection, manual runbook |
| Audit/log injection or value leakage | Strict metadata tokens/digests and value-free JSON model | Approved durable sink and retention/integrity policy |
| Transport spoofing or malicious response | Production HTTPS/GET boundary remains unchanged and isolated | Exact mutation TLS/status/shape/read-back contract |
| Capability escalation through bootstrap | Tier 1 imports absent; Engineer/profile/endpoints/policy are empty | Replace each zero-entry invariant only through explicit activation review |

## Guidance-layer adversarial paths (inert, `ADR-017`)

These paths apply to the inert `ADR-017` scaffolding and any future
consumer (READ-tool output, Tier 1 PREPARE evidence). No consumer is
authorized by this document or by `ADR-017`'s acceptance. This table is
the record of `reports-ai/reviews/ADR_017_RED_TEAM.md`'s attack list and
this design's response to each; see that review for full reasoning and
any resulting revisions.

| Attack or fault | Current inert mitigation | Residual activation requirement |
|---|---|---|
| Source spoofing (fake "official" domain) | Registry `canonical_url` is Git-reviewed, not runtime-discovered; no live fetch exists yet to spoof | Live retrieval (TB-G3) must enforce an exact hostname allow-list with no wildcard/redirect-following before it may exist |
| Compromised or malicious documentation content | Bundled excerpts are PR-reviewed before merge; load-time content-hash self-check detects any post-review tamper of the shipped file | Live retrieval must independently hash-verify or trust-label unpinned content (TB-G3); no runtime check catches a malicious *reviewed* entry — residual A5 risk, same class already named elsewhere in this document |
| Stale documentation presented as current | `version_applicability`/`snapshot_version` are explicit fields, never inferred | Consumer-side presentation must visibly label snapshot age; not resolved by this layer alone |
| Wrong pfSense edition/version guidance | Edition/version fail-closed to empty result on any ambiguity (I6); no guess-and-serve path exists | An edition-discriminator READ field does not currently exist (`SystemVersion` has none) — flagged, not resolved, this session |
| Guidance/observed-state disagreement | Guidance is a structurally separate field from observed state in every design output (never merged into one narrative) | A future consumer's presentation layer must preserve this separation; not enforceable by the guidance layer alone once content leaves it |
| Prompt injection via document content | No instruction-bearing channel exists for excerpt text to reach (bounded, typed data field only); no WRITE capability exists for an injected instruction to escalate into | Even post-Phase-5, confirmation evidence binds to the contract's own digest, which never includes guidance content — injected text still cannot forge confirmation |
| Poisoned cache/index | No cache or index exists in the accepted scope — the registry itself is the only lookup structure and is Git-tracked, not runtime-built | A future semantic-retrieval extension must define its own integrity story before it may exist |
| Retrieval outside the approved corpus | `lookup_guidance()` takes no free-text query parameter in this scope — only `(Capability, version, edition)` | A future semantic-retrieval extension must be scoped to search *within* an already-capability-selected document set only, never a general query |
| Missing guidance for a valid capability | Explicit empty-result path (I6), never fabricated | None — this is accepted, by-design behavior, not a gap to close |
| Ambiguous guidance (ambiguous version/edition match) | Fails closed to empty result rather than returning a low-confidence guess | None beyond what I6 already requires |
| Citation/provenance loss | `GuidanceReference` always carries `source_id`/`title`/`canonical_url`/`content_hash`/`snapshot_version` together as one object — no code path returns excerpt text without its provenance fields | A future consumer must render provenance alongside content, not strip it for brevity |
| Semantic-search false match | Not applicable — no semantic search exists in the accepted scope | Must be addressed by the semantic-retrieval extension's own design before it may exist |
| Capability/document mapping error | Registry is keyed on the existing reviewed `Capability` enum, not a parallel taxonomy that could drift from it | Registry review must confirm each entry's `Capability` key against `capabilities.py`, not assume it |
| Using guidance as authorization | `GuidanceReference` has no capability/endpoint/method/confirmation-token field (G1); isolation-tested against every safety-authority import (G4) | None — structurally absent, not policy-only |
| Indirect escalation into WRITE via guidance | No import path from the guidance package to `pfsense_mcp.tier1`/`WriteEndpoints`/any WRITE transport (G4, isolation-tested) | Any future Tier 1 PREPARE wiring must remain additive-evidence-only per `OFFICIAL_GUIDANCE_LAYER.md`'s Activation requirements |
| Failure recovery (guidance layer itself fails) | Every failure mode resolves to "no guidance," never a raised exception past the layer's own boundary, never a blocked underlying READ result (I6) | None beyond what I6 already requires |
