# WRITE Tier 0 (Infrastructure-Only) Acceptance Record — v0.2.0

Status: ACCEPTED
Accepted: 2026-08-06

## Baseline

- Implementation baseline commit (pre-doc-closeout): `75a563b1d8e63394aa00d134425ddf813dc8a90e`
  ("docs: record v0.1.0 READ acceptance")
- Branch: `main`
- MCP executable: `.venv/bin/pfsense-mcp-server`
- Specification: `docs/WRITE_TIER0_SPEC.md`, approved prior to implementation
- Scope: infrastructure only — allow-listing, dry-run, snapshot/rollback,
  and a separate structured write-audit log. No real mutating pfSense
  capability (no `create_firewall_alias`, no `set_dhcp_static_mapping`,
  nothing) is built in Tier 0.

## Verification methodology

Performed in a fresh Claude Code process, mirroring the v0.1.0 acceptance
rhythm (`docs/ACCEPTANCE_v0.1.0.md`):

1. Confirmed HEAD commit and branch.
2. Enumerated live `mcp__pfsense__*` tools via the already-connected MCP
   session.
3. Verified `AuditorProfile` and `EngineerProfile` registration behavior
   in-process (no network), using stub MCP/client/transport objects that
   raise if ever invoked.
4. Spawned the actual `.venv/bin/pfsense-mcp-server` production binary as
   two independent fresh subprocesses — one with no `PFSENSE_PROFILE` set
   (default), one with `PFSENSE_PROFILE=engineer` — and enumerated tools
   over the raw MCP protocol (`initialize` → `tools/list`), independent of
   the already-connected session.
5. Ran `make quick`, `make validate`, the full pytest suite, and the live
   pytest suite (`PFSENSE_RUN_LIVE_TESTS=true pytest -m live`) against the
   production pfSense instance.
6. Inspected the server's own log file for both fresh-subprocess startups
   to confirm capability sets and the absence of any HTTP request under
   the Engineer profile.

## Auditor profile results

- Live tool enumeration (both the connected session and a fresh
  subprocess): **41 tools**, all `pfsense_get_*`, zero write-named
  (`_set_`/`_create_`/`_delete_`/`_update_`).
- In-process registration against `AuditorProfile.capabilities` (32 READ
  capabilities): 41 tools registered, 0 write.
- Server log on fresh-subprocess startup:
  `startup_ok identity=api-mcp-admin profile=auditor capabilities=<33 *_READ capabilities> ...`

## Engineer profile results

- `EngineerProfile.capabilities == frozenset()` — no capabilities.
- In-process `ToolRegistry.register_all()` under Engineer capabilities:
  **0** tools registered, verified against a client stub that raises on
  any method call (never invoked).
- Live fresh-subprocess enumeration (`PFSENSE_PROFILE=engineer`):
  **0** tools returned via `tools/list`.
- `WriteEndpoints` (the mutation allow-list): **zero** entries.
- No `*_WRITE` capability is active in `SUPPORTED_CAPABILITIES_THIS_BUILD`,
  `AuditorProfile`, or `EngineerProfile`.
- A direct attempt to execute a `MutationPlan` against `WriteApiClient`
  with an empty allow-list was refused with `WriteNotAllowedError`
  **before any `Transport.request()` call** — verified with a transport
  stub configured to raise if ever touched; it was never triggered.
- All Tier 0 write-infrastructure modules (`write_api_client`,
  `pfsense_write_client`, `recovery`, `rollback`, `write_audit`) imported
  cleanly with zero network activity.
- Server log on fresh-subprocess startup:
  `startup_ok identity=api-mcp-admin profile=engineer capabilities= ...`
  — no `tool_invoked` or `rest_api_client` log lines followed, confirming
  zero HTTP requests were issued to pfSense under this profile.

## `make quick` results

**9/9 stages passed**: ruff formatting, ruff lint, incremental mypy, full
pytest suite, GET-only static enforcement, `tools/write/` import-absence
check, full repository security scan, write allow-list emptiness, write-
capability inactivity.

## `make validate` results

**16/16 stages passed**: syntax/import validation, formatting/linting,
static type checking, full pytest suite, live-test skip confirmation,
endpoint-registry verification, Auditor-profile registration, GET-only
enforcement, `tools/write/` import-absence, secret/identifying-data scan,
fixture safety validation, query-parameter safety validation (21 params
verified), write-infrastructure test verification, write allow-list
emptiness, write-capability inactivity, and a read-only git working-tree
report.

## pytest results

Full suite: **1070 passed, 42 skipped** (skips are the live-gated tests,
run separately below). No failures, no errors.

## Live verification results

- `PFSENSE_RUN_LIVE_TESTS=true pytest -m live` against the production
  pfSense instance (`https://pfsense.example.invalid`): **42/42 passed**, including
  the new `tests/test_live_write_allow_list_empty.py`, which independently
  confirms pfSense's own REST API configuration still reports
  `read_only: true` — a pfSense-side backstop behind the client-side
  gates.
- Fresh-process tool-count verification (§ Verification methodology,
  step 4):

  | Profile | Tool count | Write-named tools |
  |---|---|---|
  | default (no `PFSENSE_PROFILE`) | 41 | 0 |
  | `PFSENSE_PROFILE=engineer` | 0 | 0 |

- No mutating HTTP request was made to pfSense during any part of this
  verification — every network call observed in server logs was a `GET`
  against an already-accepted READ endpoint.

## Confirmation: Tier 0 is infrastructure only

No real mutating pfSense capability exists anywhere in the diff.
`WriteEndpoints` is empty, `tools/write/` remains empty and unimported,
and `PfSenseWriteClient`/`WriteApiClient` expose only generic
`dry_run`/`prepare_recovery_contract`/`execute`/`rollback` plumbing with
zero domain-specific mutating methods. `ToolRegistry.register_all_write()`
is a documented, empty extension point.

## Confirmation: zero mutating capabilities are exposed

Under both shipped profiles (`auditor`, `engineer`), across both the
in-process registration path and live fresh-subprocess enumeration, zero
write-capable MCP tools are registered or reachable. The write allow-list
is empty and independently verified by two static checkers
(`write_allow_list_check.py`, `write_capability_check.py`), both of which
pass in `make quick` and `make validate`.

## Confirmation: no pfSense state changed

Every live interaction during this verification was a `GET` request
through the existing, already-accepted READ path (`RestApiClient` /
`PfSenseClient`). The Engineer-profile fresh subprocess issued zero HTTP
requests of any kind. pfSense's own REST API configuration independently
reports `read_only: true`, confirmed live via
`test_live_write_allow_list_empty.py`. No `POST`/`PUT`/`PATCH`/`DELETE`
call was made or was even reachable — `WriteApiClient` is the only
component capable of issuing one, and its allow-list gate refuses before
any such call regardless of endpoint symbol.

## Closure

Tier 0 (WRITE infrastructure) is accepted as built to spec and fully
inert: no mutating pfSense capability is implemented, registered, or
reachable under either profile. This closes the Tier 0 phase defined in
`docs/WRITE_TIER0_SPEC.md`. Tier 1 (the first real, individually
authorized write capability) does not begin as part of this closeout.
