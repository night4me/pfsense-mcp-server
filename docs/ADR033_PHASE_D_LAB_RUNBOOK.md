# ADR-033 Phase D: controlled LAB provisioning runbook

Status: **owner-gated procedure; never standing authorization**. The first
owner-authorized Exercise 1 reached server-side `VERIFIED` but its generated
key was not persisted after a caller-side configuration error. The resulting
partial LAB state requires the separately reviewed cleanup below. Every network
step, including cleanup or retry, requires a new explicit owner authorization
naming the disposable LAB target and execution window.

## Fixed exercise identity

- Username: `pfsense-mcp`
- Purpose: dedicated exclusively to `pfsense-mcp-server`; never shared with a
  person or other automation.
- User description: `Dedicated service account for pfsense-mcp-server`
- API-key description: `pfsense-mcp-server primary API key`
- Target profile: `write_protected`, mechanically derived by
  `write_protected_profile_requirements()` and cross-checked against the fresh
  target schema. Its steady state is the existing 41-privilege READ profile
  plus only `api-v2-firewall-alias-patch`, the privilege unique to
  `WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION`.
- Temporary privilege: `api-v2-auth-key-post`, present only between the
  explicitly verified grant and revoke steps.
- Normal authentication: the generated API key. The random password and HTTP
  Basic Auth are bootstrap-only and must never become runtime configuration.

The account must be enabled and must not hold `page-all`, an administrator
role/group, an unrelated convenience privilege, or the temporary bootstrap
privilege in steady state. The profile does not make WRITE default-reachable:
the project's capability, authorization, confirmation, and Tier 1 gates remain
independent.

## Owner authorization and preflight inputs

Before the execution window, the owner must approve all of the following as one
fixed ceremony:

1. The exact disposable pfSense LAB HTTPS origin and expected appliance
   identity.
2. TLS verification mode. Strict public trust or one fixed CA-file path is
   required; `verify=False`, redirects, and origin changes are prohibited.
   This LAB uses repository mode `PFSENSE_TLS_MODE=auto` with the existing
   fixed CA path supplied as `PFSENSE_TLS_CA_FILE`. `custom_ca` is not a valid
   mode. `tls.resolve_verify()` must resolve to that CA path, preserving HTTPS
   certificate and hostname verification; `insecure` is prohibited.
3. API version `v2` and an installed `pfSense-pkg-RESTAPI` version within the
   repository's verified range (`v2.7.7` through `v2.10.0`). A version outside
   that range stops the exercise.
4. A freshly fetched OpenAPI schema from that same authenticated target. Every
   required privilege must resolve as `SOURCE_CROSS_CHECKED`; missing,
   ambiguous, or source-disagreeing evidence stops before mutation.
5. A transient administrator API credential authorized to perform only this
   ceremony. It must not be written by the bootstrap code or appear in command
   arguments, logs, shell history, evidence, or reports.
6. A non-existent `PFSENSE_API_KEY_FILE` destination in a trusted,
   owner-controlled directory. Existing path, symlink, unsafe ownership/mode,
   or inability to create mode `0600` stops before account creation.
7. An exclusive administrative window: no person or automation may create,
   delete, disable, rename, or change privileges on `pfsense-mcp` from the
   initial user read until final verification completes.
8. A manual recovery operator who retains administrator access for the whole
   window and has reviewed the interruption table below.

The reviewed one-shot driver must construct an admin `HttpTransport` and a
single-use `BasicAuthHttpTransport` factory for exactly the same HTTPS origin
and TLS trust. It must call `provision_service_account()` directly; it must not
add a CLI command, application-startup hook, MCP tool, generic dispatch, or
runtime bootstrap behavior.

## Authentication-method transition boundary

The 2026-08-19 LAB exercise established a load-bearing operational fact. A
settings save from exact `KeyAuth` to `KeyAuth + BasicAuth` persisted, while
the immediately following REST API reads timed out. The owner restored exact
`KeyAuth` through the WebGUI; two later, independent KeyAuth reads proved the
safe steady state and API health. Cleanup and provisioning did not continue.

Pinned `pfSense-pkg-RESTAPI` v2.10 source shows that the settings endpoint
writes configuration, always applies the settings model, and starts its apply
dispatcher asynchronously. It does **not** promise that the connection used
for the settings PATCH remains usable, or that the REST API is immediately
available after the save. The package source does not establish one specific
daemon/restart mechanism for the observed timeout, so operators must not claim
one. The supported conclusion is narrower: connection continuity and
immediate availability across this save are not guarantees.

Any future separately authorized transition must use the closed
`AuthMethodTransitionCoordinator` and obey all of these rules:

1. Capture exact `KeyAuth` plus a digest of every unrelated returned setting.
   Any other initial method set stops without mutation.
2. The only enable payload is `KeyAuth + BasicAuth`; the only restore payload
   is exact `KeyAuth`. Each transition is submitted at most once.
3. A timeout/disconnect after submission is indeterminate, never proof of
   failure and never permission to resend.
4. Discard every pre-transition transport. Construct a fresh transport for
   each bounded health/verification attempt.
5. Independently confirm either the expected state, the unchanged pre-state,
   or an unexpected/unobservable state. Verify the unrelated-settings digest.
6. Verify restoration only through a newly constructed KeyAuth transport; do
   not depend on BasicAuth, which restoration intentionally removes.
7. Exhausted reconnects, malformed evidence, sibling-setting drift, or an
   unexpected method set yields `OUT_OF_BAND_RECOVERY_REQUIRED`. Stop all
   cleanup/provisioning. Use the WebGUI recovery procedure and independently
   prove exact `KeyAuth` before any later owner decision.

The expected final steady state is always exact `KeyAuth`. The coordinator is
offline-built and remains absent from CLI, application, MCP, cleanup, and
provisioning entry points. It never auto-chains into another operation.

## Initial authoritative checks

Perform and retain secret-free evidence for:

1. Local repository HEAD equals the owner-authorized SHA; working tree clean;
   CI and CodeQL green.
2. Public contract remains 42 tools, zero default-reachable WRITE; write
   allow-list remains exactly `FIREWALL_ALIAS_DESCRIPTION`.
3. Bootstrap engine remains absent from server, application, factory,
   security CLI/doctor, and MCP tool imports.
4. TLS certificate and configured origin match the approved target.
5. Fresh package version and OpenAPI schema satisfy the derivation gate.
6. `GET /api/v2/users` returns either no `pfsense-mcp` record (new-account
   exercise) or exactly one owner-created, enabled, project-dedicated record
   whose complete starting privilege set has been recorded (separately
   authorized `PRIVILEGES_SYNCED` exercise). A duplicate, disabled account,
   unexplained existing account, or existing `api-v2-auth-key-post` stops.
7. The key destination is absent. Never delete or overwrite an existing file
   merely to make this check pass.

## New-account transaction

The expected sequence is fixed:

1. `NOT_STARTED`: authoritative users read confirms the name is absent.
2. Create one enabled `pfsense-mcp` user with the fixed description, random
   in-memory password, and exact derived steady-state privileges.
3. Independent users reread proves exact account identity and privileges;
   transition to `USER_CREATED`.
4. Grant exactly the steady-state set plus `api-v2-auth-key-post` using the
   administrator transport.
5. Independent reread proves the exact set; transition to
   `BOOTSTRAP_PRIVILEGE_GRANTED`.
6. Construct one `BasicAuthHttpTransport` for the same origin/TLS trust and
   make its single self-service `POST /api/v2/auth/key` call with the fixed key
   description. No redirect or retry is permitted; transition to
   `KEY_GENERATED` only on a valid response.
7. Revoke `api-v2-auth-key-post` using the administrator transport.
8. Independent reread proves the exact steady-state privilege set and absence
   of the temporary privilege; transition through
   `BOOTSTRAP_PRIVILEGE_REVOKED` to `VERIFIED`.
9. Store the returned key with `config.store_api_key()`. This must exclusively
   create the approved `PFSENSE_API_KEY_FILE`, force mode `0600`, fsync, reread
   through descriptor-bound validation, and never print the value. A custody
   failure is not a successful provisioning outcome and requires the manual
   response below.
10. With the new API key loaded through `load_api_key()`, perform only the
    separately authorized read-only verification necessary to prove the
    credential belongs to the expected account and its required READ calls
    succeed. Do not exercise the alias PATCH during bootstrap Phase D.

## Existing-account `PRIVILEGES_SYNCED` exercise

This is a distinct, separately selected case; do not fall into it accidentally.
The starting account must have been deliberately prepared by the owner for this
LAB evidence and must not be shared.

The engine performs an initial read, then a final authoritative read immediately
before PATCH. It sends the union of the final pre-mutation privilege set and the
derived target set. After PATCH, an authoritative reread must prove:

- every target privilege is present;
- every privilege in the final pre-mutation snapshot remains present;
- the same enabled account ID/name remains selected; and
- `api-v2-auth-key-post` is absent.

Only then is `PRIVILEGES_SYNCED` honest. pfSense exposes no revision/CAS token,
so this proves preservation relative to the final pre-mutation snapshot, not
the absence of a change in the remaining read-to-PATCH interval. The exclusive
administrative window is therefore a mandatory precondition, not an inferred
software guarantee. Unexpected state yields `FAILED` or
`BLOCKED_EXISTING_PARTIAL`, never success or automatic retry.

## Interruption and manual response

No failed state automatically resumes, rolls back, retries, deletes an account,
or revokes an API key.

| Last proven state | Authoritative observation required | Manual response |
|---|---|---|
| `NOT_STARTED` | Reread users | If absent, no appliance cleanup. If present unexpectedly, stop for owner review. |
| `USER_CREATED` | Confirm account identity, enabled state, and full privileges | Owner decides whether to retain or explicitly delete the disposable account. The runner does neither. |
| `BOOTSTRAP_PRIVILEGE_GRANTED` | Confirm complete privileges and temporary privilege | Treat temporary elevation as present. Owner performs a separately reviewed full-list PATCH removing only `api-v2-auth-key-post`, then rereads. |
| `KEY_GENERATED` | Confirm account privileges and enumerate auth-key metadata without exposing key material | Treat the key as issued even if its response/custody is uncertain. Revoke the temporary privilege first; owner then decides whether to revoke the orphan key or recreate the disposable account. Never retry key creation blindly. |
| `BOOTSTRAP_PRIVILEGE_REVOKED` | Prove exact steady-state privileges and absence of temporary privilege | If key custody succeeded, continue final verification. If custody failed, stop for explicit orphan-key/account remediation. |
| `VERIFIED` | Repeat final account and key-file checks | Record success only if account state and secure key custody both verify. |
| `FAILED` or process interruption | Fresh users/auth-key observations; never trust the process-local transaction object | Stop. Classify actual server state using this table and obtain explicit owner approval for any cleanup mutation. |

If `PFSENSE_API_KEY_FILE` creation fails after key issuance, do not print or
copy the key through an unreviewed channel. The account/key is partial state,
not success. Preserve the secret only through an owner-approved secure custody
mechanism or remediate the orphan key/account explicitly.

## Closed orphan-key/account cleanup

Cleanup is not part of the successful bootstrap state machine and never chains
into provisioning. It uses only `security_bootstrap_recovery.py`'s two fixed
functions and `security_bootstrap_client.py`'s private transport projections:

- `revoke_failed_bootstrap_api_key()` performs two `GET /api/v2/auth/keys`
  observations, selects exactly one key whose stable integer ID, owner
  `pfsense-mcp`, and fixed key description agree, sends exactly one
  `DELETE /api/v2/auth/key` body containing only that ID through a separate
  single-use administrator `BasicAuthHttpTransport`, then rereads all key
  metadata. Upstream v2.10 marks this singular endpoint Basic-Auth-only; the
  ordinary administrator API-key transport remains read-only in this action.
  It succeeds only if the ID is absent and every unrelated key's complete
  non-secret metadata is unchanged.
- `delete_dedicated_recovery_user()` freshly derives the exact
  `write_protected` privilege set, performs two `GET /api/v2/users`
  observations, requires exactly one enabled `scope=user` account with the
  fixed name/description, exact target privileges and no `page-all`, and twice
  proves no API key is owned by that username. It sends exactly one
  `DELETE /api/v2/user` body containing only the stable user ID, then rereads
  users and keys. It succeeds only if the ID/name and owned keys are absent and
  unrelated observed user metadata is unchanged.

The exact future owner-authorized cleanup sequence is:

1. Diagnose the partial state with authoritative user and key-metadata reads.
2. Identify exactly one orphan key by owner, fixed description, stable ID and
   complete non-secret metadata. Zero, duplicate, or changed matches stop.
3. Construct one single-use administrator Basic-Auth transport for the exact
   TLS origin. Call `revoke_failed_bootstrap_api_key()` once. Never retry
   DELETE or persist the administrator password.
4. Independently require the selected ID absent and unrelated keys unchanged.
5. Re-derive the target profile and revalidate the exact disposable user,
   including `scope=user`, enabled state, fixed identity and no remaining key.
6. Call `delete_dedicated_recovery_user()` once. Never retry DELETE.
7. Independently require zero matching account/key records and unrelated users
   unchanged.
8. Stop. Cleanup success does not authorize provisioning.
9. Obtain separate owner authorization before any Exercise 1 retry.

The API provides stable integer IDs but no revision/CAS primitive. Two fresh
reads narrow, but cannot eliminate, ID reuse or concurrent-change risk between
the last read and DELETE. The exclusive administrative window is mandatory.
Any transport uncertainty or postcondition mismatch is partial success:
authoritatively reread and return for owner review, never resend automatically.

## Persistence decision

Cross-process bootstrap-transaction persistence is deferred for the first
supervised, one-shot disposable-LAB exercise. This is acceptable only because:

- one operator owns an exclusive, bounded execution window;
- the operation runs synchronously in one process;
- every mutation has an immediate independent authoritative reread;
- interruption causes a hard stop, never automatic resume;
- server-side state is freshly reobserved and manually classified; and
- administrator access and the recovery table remain available throughout.

Persistence is mandatory before bootstrap is exposed through a normal
administrative CLI, used unattended, scheduled, used concurrently, or promoted
beyond a disposable controlled LAB. Offline Slice 1 now implements the
foundation in `security_operation_journal.py`: an authenticated chained journal
and head, an operation-attributed exclusive local lock, and a pure restart
classifier. It does not reuse Tier 1's `RecoveryContract` and remains unwired.

The journal must record the send-intent boundary before every future mutation.
After interruption, only an exact pre-send checkpoint plus matching fresh
authoritative state is resumable. A send-intent or unknown-result checkpoint is
never resend authority. Stale/missing/foreign lock evidence, partial server
state, pending final verification, or corrupt/untrusted local state blocks new
bootstrap and requires the classifier's explicit result. Recovery remains a
separate owner-directed action and stops after its verified postcondition; it
never automatically continues into provisioning.

This runbook still does not authorize CLI composition. The journal integrity
key, paths, component construction, and operator command surface must be wired
only by separately reviewed later slices.

Offline CLI/runtime integration Slice 2 now fixes the component-construction
boundary in `security_admin_composition.py`. The administrative process must
receive explicit secure references for the target, TLS trust, administrator
KeyAuth and BasicAuth files, service-key custody, owner-only state directory,
journal MAC key, captured schema/version evidence, and installed package
version. It never searches for credentials or state. The account
(`pfsense-mcp`), descriptions, profile (`write_protected`), API version, and
target-derived journal/lock names are fixed.

Composition authenticates and target-checks any existing journal, inspects the
matching lock, validates source-cross-checked privilege evidence, and creates
no files, clients, requests, or mutations. Its public surface is read-only
restart status only. The fixed bootstrap/recovery/transition bindings remain
private and cannot be invoked by a command in this slice. Therefore this
runbook still does not authorize or describe a runnable command: journal-aware
mutation orchestration, explicit human confirmation, custody sequencing, and
command registration remain separate review gates.

## Final verification and stop

Before declaring the exercise complete, independently prove:

- exactly one enabled `pfsense-mcp` account exists;
- its description is the fixed owner-approved value;
- its privileges equal the freshly derived 42-privilege `write_protected` set;
- it lacks `page-all`, administrator membership, unrelated privileges, and
  `api-v2-auth-key-post`;
- the generated key is usable for approved READ requests and is stored only at
  the approved owner-only key file;
- Basic Auth credentials were not persisted and are not normal runtime config;
- bootstrap remains absent from normal CLI/application/MCP imports;
- public MCP remains 42 tools with zero default-reachable WRITE; and
- no alias mutation, Nexus access, TPM/witness mutation, release, or
  publication occurred.

Stop after evidence capture. Phase D does not authorize runtime wiring or any
subsequent phase.
