# Disposable Tier 1 integration-lab plan

Status: design only. No production appliance or credential is authorized.

## Environment

- Dedicated pfSense VM on a host-only virtual network with no route to
  production networks.
- Synthetic RFC 5737/RFC 3849 addresses, `.invalid` names, synthetic users,
  certificates, aliases, and service configuration.
- A separate API identity with only the candidate's exact test permission;
  credentials exist only in the isolated lab secret store.
- MCP runner and test controller on a second disposable VM/network namespace.
- Packet capture and hypervisor console available outside the tested control
  path so lockout is observable and recoverable.

## Provisioning and reset

1. Install a pinned pfSense and pfrest package version from verified artifacts.
2. Import a reviewed synthetic baseline configuration.
3. Capture a powered-off hypervisor snapshot and hash the exported baseline.
4. Boot, verify REST `read_only=true`, collect the generated OpenAPI document,
   and compare the exact candidate path/schema with the reviewed source.
5. Before WRITE tests, clone the VM snapshot and grant only the candidate
   permission. Destroy the clone after each scenario.

No production address, identity, certificate, key, config history, backup, or
packet capture may enter the lab or repository.

## Acceptance sequence

- Verify READ baseline and exact 41/0 production profile behavior first.
- Confirm dry-run issues no mutating request.
- Prepare one contract from one uniquely identified synthetic target.
- Confirm the snapshot/fingerprint and contract store externally.
- Execute one field-bounded mutation and observe exactly one request.
- Verify the intended field via authoritative READ and prove unrelated fields
  unchanged.
- Roll back and prove semantic equality to the pre-state.
- Restore the VM snapshot and independently compare configuration.

## Fault scenarios

Use a test proxy and process fault hooks to exercise:

- crash before durable acquisition;
- crash after EXECUTING but before send;
- connection reset during request upload;
- pfSense commits while response is dropped;
- timeout during response and during read-back;
- process restart in EXECUTING and ROLLING_BACK;
- target changed/reordered/deleted/duplicated between prepare and execute;
- conflicting operator edit after verification and before rollback;
- rollback response loss and partial compound compensation;
- unavailable/corrupt config history and corrupt/replayed local store.

The proxy records only method/path/status/timing, never credentials or bodies.
Ambiguous outcomes must enter RECONCILIATION and must not emit a second mutation.

## Snapshot and rollback verification

Application rollback is tested before hypervisor restore. Hypervisor restore is
the lab containment mechanism, not the Recovery Contract's claimed rollback.
Configuration history is evaluated only as a protected diagnostic artifact;
failure to capture it blocks mutation, and unrelated revisions prohibit global
automatic restore.

## Exit conditions

- Revoke the WRITE permission and verify upstream `read_only=true`.
- Destroy contract keys, databases, VM clones, captures, and temporary logs.
- Retain only value-free hashes, tool counts, state transitions, and test
  outcomes in acceptance evidence.
- Production activation remains a separate Owner Approval Gate.
