# The `pfsense-mcp-security` operator CLI

`pfsense-mcp-security` is a separate command-line tool from the MCP
server itself (`pfsense-mcp-server`). It never runs as part of an MCP
client session and registers no MCP tool — it is something *you*, the
operator, run in a terminal to provision, inspect, and (if you ever opt
into `write_protected`) recover the pfSense identity and local state
the server uses. This page documents its current, real behavior,
derived directly from source and from `--help` output — not historical
plans.

**If you only want the default, read-only server**, you do not need
most of this page: any existing pfSense API key works (see
[Installation](INSTALLATION.md)). Use `pfsense-mcp-security setup` if
you'd rather have a dedicated, least-privilege identity generated and
verified for you instead of reusing one.

## Normal user path

### `setup` — guided discovery and planning

```console
pfsense-mcp-security setup
```

Run with no flags, `setup` is an **interactive**, plain-language wizard:
it asks what you want (read-only visibility, or the additional
protected-WRITE capability), records your target pfSense appliance's
address, and produces a plan — a structured description of what would
need to happen to reach that target state. **`setup` on its own never
touches pfSense and never provisions anything.** It only plans.

For scripted/CI use, pass `--non-interactive` with the two required
flags:

```console
pfsense-mcp-security setup --non-interactive \
  --capability-posture read_only --anchor-assurance none
```

- `--capability-posture` is `read_only` (the default, recommended
  posture — the same one the plain PyPI install already gives you) or
  `write_protected` (see [Advanced paths](#advanced-and-recovery-paths)
  below).
- `--anchor-assurance` is `none`, `software`, or `hardware_witness` —
  only meaningful for `write_protected`; leave it `none` for the normal
  read-only path.

Add `--json` to any `setup`/`setup apply` invocation for machine-
readable output.

### `setup apply` — actually doing what the plan describes

`setup` only plans; **`setup apply` is the separate, explicit command
that acts on a plan you've already reviewed**:

```console
pfsense-mcp-security setup apply \
  --capability-posture read_only --anchor-assurance none
```

Run with no `--confirm`, this only *inspects* — it re-checks the plan
is still current and shows you the exact confirmation token a real
apply would need, without doing anything. Only passing that exact token
back via `--confirm <TOKEN>` actually acts:

```console
pfsense-mcp-security setup apply \
  --capability-posture read_only --anchor-assurance none \
  --confirm <TOKEN-FROM-THE-INSPECTION-ABOVE>
```

- For `read_only`, apply performs exactly **one** read-only connectivity
  check against your configured pfSense target — never a mutation.
- For `write_protected`, apply provisions (or verifies) the one fixed,
  dedicated, least-privilege service account this project ever creates
  — see [Advanced paths](#advanced-and-recovery-paths).

If the plan you reviewed is now stale (something about the target
changed since), apply refuses rather than silently re-planning — you
run `setup` again to get a fresh, current plan and token.

### MCP client config generation

```console
pfsense-mcp-security setup write-client-config
```

Once you have a working configuration, this prints (and, with its own
separate `--confirm`, can write/merge into a real client config file)
the exact MCP client configuration block for the target you just set
up — see [Connect your MCP client](MCP_CLIENT_CONFIGURATION.md) for the
full write/merge workflow and safety guarantees.

### `doctor` — is this host ready for a protected-WRITE ceremony?

```console
pfsense-mcp-security doctor
```

Read-only preflight check, relevant only if you're considering
`write_protected` with `hardware_witness` anchor assurance. Reports
`READY`/`NOT READY` for the local artifact-exchange paths and witness
connectivity. Never repairs or mutates anything itself.

## Advanced and recovery paths

The rest of this page covers `write_protected` — an explicit, optional
opt-in that most installations do not need. If you don't plan to let
this server change a firewall alias's description field (currently the
*only* mutation this project supports, ever), you can stop reading
here.

### `bootstrap` — the deterministic provisioning engine underneath `setup apply`

`setup apply --capability-posture write_protected` composes `bootstrap`
internally; you do not normally invoke it directly. `bootstrap` is the
non-interactive, journal-aware, locking engine that creates (or
verifies) the one fixed, least-privilege `pfsense-mcp` service account
on your target appliance. Every action it takes is configured entirely
through environment variables — see
[ADR-033](adr/ADR-033-pfsense-least-privilege-bootstrap-architecture.md)
for the full design if you want the underlying architecture.

**Restart safety**: if a prior `bootstrap`/`setup apply
write_protected` attempt was interrupted, a later run does not blindly
retry. It automatically attempts one fresh, read-only observation of
the account's actual current state; only an exact match against every
expected field resolves the restart as already-complete. Anything
short of that is surfaced as `RECOVERY_REQUIRED`, pointing you at
`recover` (below) — never silently retried, never silently assumed
fine.

### `recover` — inspecting and resolving a `RECOVERY_REQUIRED` state

```console
pfsense-mcp-security recover
```

Run with no flags, this is **read-only inspection**: it classifies the
existing incident (if any) and, if recovery is genuinely required,
prints the exact action needed, the affected object, and a
confirmation token bound to this exact target/action/object/incident.
It makes no pfSense mutation on its own.

Resolving the incident requires **both** flags together — a token from
a different target, action, object, or incident is refused before any
mutating call is made:

```console
pfsense-mcp-security recover --execute <ACTION> --confirm <TOKEN>
```

`--confirm -` reads the token from stdin instead of the command line,
useful for scripting without leaving it in shell history.

### `hardware_witness` anchor assurance

`--anchor-assurance hardware_witness` is the strongest available
posture for `write_protected`: it requires a TPM-backed, host-witnessed
anti-rollback anchor to already be provisioned and reachable (checked
by `doctor`, above) before `setup apply` will even attempt the
provisioning call. This is genuinely advanced infrastructure — most
installations that want `write_protected` at all should start with
`--anchor-assurance none` or `software` and only move to
`hardware_witness` with a real understanding of what it protects
against; see
[the Tier 1 architecture](TIER1_ARCHITECTURE.md) and
[ADR-011](adr/ADR-011-whole-store-anti-rollback-anchor.md).

## What mutates and what does not

| Command | Ever mutates pfSense? |
|---|---|
| `discover`, `plan`, `doctor` | Never. |
| `setup` (bare) | Never — plan-only. |
| `setup apply` (no `--confirm`, or stale plan) | Never — inspection only. |
| `setup apply --confirm <token>`, posture `read_only` | Never — one read-only connectivity check. |
| `setup apply --confirm <token>`, posture `write_protected` | Yes — provisions/verifies the one fixed service account. |
| `setup write-client-config` (no `--confirm`) | Never touches pfSense; prints only, does not write any file. |
| `setup write-client-config --confirm <token>` | Never touches pfSense; may write/merge one local MCP client config file. |
| `bootstrap` | Yes — the same one fixed service-account provisioning `setup apply write_protected` composes. |
| `recover` (no `--execute`) | Never — inspection only. |
| `recover --execute <action> --confirm <token>` | Yes — exactly the one named recovery action, and only after the exact token matches. |

Every mutating path above requires an explicit confirmation token
printed by a prior, separate inspection step — there is no command that
mutates on its very first invocation.

## Common first-run flow

```console
# 1. See what a read-only setup would look like (no changes made yet).
pfsense-mcp-security setup --non-interactive \
  --capability-posture read_only --anchor-assurance none --json

# 2. Apply it (first call inspects, prints a confirmation token).
pfsense-mcp-security setup apply \
  --capability-posture read_only --anchor-assurance none

# 3. Re-run with the printed token to actually verify connectivity.
pfsense-mcp-security setup apply \
  --capability-posture read_only --anchor-assurance none \
  --confirm <TOKEN>

# 4. Generate your MCP client configuration.
pfsense-mcp-security setup write-client-config
```

## Related

- [Installation](INSTALLATION.md)
- [Connect your MCP client](MCP_CLIENT_CONFIGURATION.md)
- [Security model](SECURITY_MODEL.md)
- [ADR-021 Security posture provisioning](adr/ADR-021-security-posture-provisioning.md) ·
  [ADR-033 pfSense least-privilege bootstrap architecture](adr/ADR-033-pfsense-least-privilege-bootstrap-architecture.md)
