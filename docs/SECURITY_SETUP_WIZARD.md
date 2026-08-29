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
most of this page: `pfsense-mcp-security setup` walks you through it,
and its recommended default (POST-v1.0 MANAGED READ-ONLY WIZARD
INTEGRATION mission, 2026-08-29) creates a dedicated, least-privilege
`pfsense-mcp-readonly` pfSense account for you — the pfSense credential
itself is then incapable of a WRITE operation, not only this tool's own
MCP surface. Prefer to reuse an existing pfSense API key instead? The
wizard's Account step also offers that as an explicit, equally
supported "Advanced" choice — see [Installation](INSTALLATION.md).

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

### Read-only account: managed vs. bring-your-own-key

Only meaningful for `--capability-posture read_only`. The interactive
wizard's Account step (shown right after Usage) offers two choices;
`--read-only-account-mode` takes the same two values non-interactively:

- **Managed** (`managed`, the default in the interactive wizard,
  **recommended**) — `setup apply --read-only-account-mode managed`
  provisions the dedicated, least-privilege `pfsense-mcp-readonly`
  pfSense service account (composing the same engine standalone
  `pfsense-mcp-security bootstrap --target-profile read_only` uses —
  never a second, independent provisioning path). This account holds
  exactly the 94 READ privileges this project documents and nothing
  else; even a request that bypasses this MCP server entirely and goes
  straight to pfSense's own REST API is refused, because the
  *credential itself* cannot write, not only this tool's application
  layer. See [the least-privilege matrix](PFSENSE_LEAST_PRIVILEGE_MATRIX.md#managed-read-only-service-account-pfsense-mcp-readonly).
- **Bring your own key** (`byo`, the default for every non-interactive/
  scripted invocation that omits the flag, matching every release
  before this one byte-for-byte) — reuses whatever pfSense API key
  you've already configured via `PFSENSE_API_KEY_FILE`. This project
  confirms that key can authenticate; it never inspects or verifies
  what pfSense privileges the key itself holds. If that key happens to
  hold WRITE or administrator privileges, a request that bypasses this
  MCP server can still mutate pfSense — nothing about this posture's
  BYOK path prevents that at the pfSense authorization layer.

This choice is bound into the plan's own digest and confirmation
token, not merely a presentation detail — a plan/token you reviewed
for one mode can never be reused to silently authorize an apply in the
other mode for the same target. Existing installations are never
affected by this addition: a `setup`/`setup apply` invocation that
does not pass `--read-only-account-mode` behaves exactly as it always
has (`byo`).

### Connection security (TLS) and credentials

The interactive wizard's connection-security question offers three
choices — `--tls-mode` takes the same three values non-interactively:

- **Verify TLS certificate** (`verify`, the default and recommended
  choice) — validates the appliance's certificate against your
  system's normal trust store, exactly like a browser would. Use this
  if pfSense's certificate was issued by a publicly trusted CA (or one
  your OS already trusts); nothing extra is needed.
- **Verify against a private/internal certificate authority**
  (`verify_private_ca`) — for a self-hosted or LAB pfSense using its
  own or your organization's internal CA. The wizard asks for the path
  to that CA's **public certificate only** (never a private key) —
  export it from pfSense's own Certificate Manager, or ask whoever
  manages this pfSense's certificates for it. This maps to
  `PFSENSE_TLS_MODE=auto` plus `PFSENSE_TLS_CA_FILE` pointing at that
  file.
- **Skip TLS verification** (`insecure`, advanced, not recommended) —
  disables certificate verification entirely. Treat it as a short-lived
  diagnostic step only, never a standing configuration.

Whichever you choose, `setup`'s plan-only output reminds you to
**export the matching real environment variables in your shell**
(`PFSENSE_API_URL`, `PFSENSE_IDENTITY`, `PFSENSE_API_KEY_FILE`,
`PFSENSE_TLS_MODE`, and `PFSENSE_TLS_CA_FILE` if applicable) before
running `setup apply` — `setup apply` reads your real shell
environment fresh, the same way the MCP server itself does at startup;
`setup` itself never reads or writes them. For the credential file
(`PFSENSE_API_KEY_FILE`): generate an API key in pfSense under the
REST API package's own user/key management, then save **only the key
itself** to a private, owner-only file —
[Installation](INSTALLATION.md#obtain-and-configure-a-credential-safely)
has the exact `install -m 600` recipe.

### One-time local confirmation key

`setup apply` and `setup write-client-config` also both require
`PFSENSE_SETUP_CONFIRM_KEY_FILE` — a **purely local** secret, unrelated
to pfSense: it is never sent to pfSense, is not a pfSense credential,
and never appears in any generated MCP client configuration. It exists
only so this tool can tell a plan you actually reviewed apart from a
stale, copy-pasted, or cross-target/cross-posture command — a
lightweight anti-footgun check, not an authentication mechanism.

If you don't already have one, create it once:

```console
pfsense-mcp-security setup init-confirm-key
```

This writes a fresh, cryptographically random key to a safe default
path under `~/.local/state/pfsense-mcp-server/` (owner-only
permissions, refuses to follow a symlink or overwrite an existing key)
and prints the exact `export PFSENSE_SETUP_CONFIRM_KEY_FILE=...` line
to use. Running it again later is safe — an existing key is always
left untouched, never rotated: rotating it would invalidate any
`--confirm` token you haven't redeemed yet. Pass `--path` to use a
different location instead of the default.

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

- For `read_only`+`byo` (the default), apply performs exactly **one**
  read-only connectivity check against your configured pfSense target
  — never a mutation.
- For `read_only`+`managed` (`--read-only-account-mode managed`) and
  for `write_protected`, apply provisions (or verifies) the relevant
  fixed, dedicated, least-privilege service account — `pfsense-mcp-readonly`
  or `pfsense-mcp` respectively, entirely separate accounts/journals —
  see [Advanced paths](#advanced-and-recovery-paths).

If the plan you reviewed is now stale (something about the target
changed since), apply refuses rather than silently re-planning — you
run `setup` again to get a fresh, current plan and token.

### MCP client config generation

```console
pfsense-mcp-security setup write-client-config \
  --client claude-desktop --config-path /absolute/path/to/claude_desktop_config.json \
  --capability-posture read_only --anchor-assurance none
```

`--client`, `--capability-posture`, and `--anchor-assurance` are
required (matching the values your `setup` run used). Once you have a
working configuration, this prints (and, with its own separate
`--confirm`, can write/merge into a real client config file, with an
automatic `.bak` backup first) the exact MCP client configuration block
for the target you just set up — see
[Connect your MCP client](MCP_CLIENT_CONFIGURATION.md) for the full
write/merge workflow and safety guarantees.

### `doctor` — is this host ready for a protected-WRITE ceremony?

```console
pfsense-mcp-security doctor
```

Read-only preflight check, relevant only if you're considering
`write_protected` with `hardware_witness` anchor assurance. Reports
`READY`/`NOT READY` for the local artifact-exchange paths and witness
connectivity. Never repairs or mutates anything itself.

## Advanced and recovery paths

The rest of this page mostly covers `write_protected` — an explicit,
optional opt-in that most installations do not need. If you don't plan
to let this server change a firewall alias's description field
(currently the *only* mutation `write_protected` adds, ever) and
you're not using the **managed** read-only account mode above, you can
stop reading here. If you *are* using managed read-only, `bootstrap`
and `recover` below both take `--target-profile read_only` to operate
on the `pfsense-mcp-readonly` account specifically — its own,
independent journal/lock/recovery state.

### `bootstrap` — the deterministic provisioning engine underneath `setup apply`

`setup apply --capability-posture write_protected` (and, for read-only,
`setup apply --capability-posture read_only --read-only-account-mode
managed`) compose `bootstrap` internally; you do not normally invoke it
directly. `bootstrap` is the non-interactive, journal-aware, locking
engine that creates (or verifies) the one fixed, least-privilege
service account on your target appliance — `pfsense-mcp`
(`--target-profile write_protected`, the default) or
`pfsense-mcp-readonly` (`--target-profile read_only`), entirely
separate accounts with entirely separate journal/lock/custody state.
Every action it takes is configured entirely through environment
variables — see
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
existing incident (if any) for the `write_protected` (`pfsense-mcp`)
account by default, and prints the exact action needed, the affected
object, and a confirmation token bound to this exact
target/action/object/incident. Pass `--target-profile read_only` to
inspect/recover the `pfsense-mcp-readonly` account's own incident
instead — its journal/lock state is entirely separate, so the two
profiles' incidents (if either exists at all) are never conflated. It
makes no pfSense mutation on its own.

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
| `setup init-confirm-key` | Never touches pfSense; may create one local key file (never overwrites an existing one). |
| `setup apply` (no `--confirm`, or stale plan) | Never — inspection only. |
| `setup apply --confirm <token>`, posture `read_only`, mode `byo` (default) | Never — one read-only connectivity check. |
| `setup apply --confirm <token>`, posture `read_only`, mode `managed` | Yes — provisions/verifies the dedicated `pfsense-mcp-readonly` service account. |
| `setup apply --confirm <token>`, posture `write_protected` | Yes — provisions/verifies the dedicated `pfsense-mcp` service account. |
| `setup write-client-config` (no `--confirm`) | Never touches pfSense; prints only, does not write any file. |
| `setup write-client-config --confirm <token>` | Never touches pfSense; may write/merge one local MCP client config file. |
| `bootstrap` | Yes — the same one fixed service-account provisioning `setup apply write_protected` composes. |
| `recover` (no `--execute`) | Never — inspection only. |
| `recover --execute <action> --confirm <token>` | Yes — exactly the one named recovery action, and only after the exact token matches. |

Every mutating path above requires an explicit confirmation token
printed by a prior, separate inspection step — there is no command that
mutates on its very first invocation.

## Common first-run flow

This flow shows the `byo` (bring-your-own-key) path explicitly for
clarity — it is also what every command below does if you omit
`--read-only-account-mode` entirely. Prefer the **recommended**
managed account instead? Add `--read-only-account-mode managed` to
steps 1, 3, 4, and 5 below (step 3's apply then provisions
`pfsense-mcp-readonly` instead of only checking connectivity; the same
`PFSENSE_ADMIN_*` environment standalone `bootstrap` needs is required
for that step).

```console
# 1. See what a read-only setup would look like (no changes made yet).
pfsense-mcp-security setup --non-interactive \
  --capability-posture read_only --anchor-assurance none --json

# 2. One-time only: provision the local confirmation key setup apply
#    and setup write-client-config both need (see the "One-time local
#    confirmation key" section above). Skip if you already have one.
pfsense-mcp-security setup init-confirm-key

# 3. Apply it (first call inspects, prints a confirmation token).
pfsense-mcp-security setup apply \
  --capability-posture read_only --anchor-assurance none

# 4. Re-run with the printed token to actually verify connectivity.
pfsense-mcp-security setup apply \
  --capability-posture read_only --anchor-assurance none \
  --confirm <TOKEN>

# 5. Generate your MCP client configuration (inspects first, prints a token).
pfsense-mcp-security setup write-client-config \
  --client claude-desktop --config-path /absolute/path/to/claude_desktop_config.json \
  --capability-posture read_only --anchor-assurance none
```

## Related

- [Installation](INSTALLATION.md)
- [Connect your MCP client](MCP_CLIENT_CONFIGURATION.md)
- [Security model](SECURITY_MODEL.md)
- [ADR-021 Security posture provisioning](adr/ADR-021-security-posture-provisioning.md) ·
  [ADR-033 pfSense least-privilege bootstrap architecture](adr/ADR-033-pfsense-least-privilege-bootstrap-architecture.md)
