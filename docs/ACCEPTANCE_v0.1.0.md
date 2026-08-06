# READ-Only Acceptance Record — v0.1.0

Status: ACCEPTED AND FROZEN
Accepted: 2026-08-06

## Baseline

- Commit: `51e86a22a72eee63aff65dd7e9ad6de6df688a38`
- Tag: `v0.1.0`
- Branch: `main`
- MCP executable: `.venv/bin/pfsense-mcp-server`

## Verification method

Performed in a fresh Claude Code process against a freshly started
`pfsense-mcp-server` MCP subprocess (started after the Claude process),
to rule out stale tool schemas or cached state.

Pre-flight checks (all passed):

- HEAD commit matched baseline
- Branch was `main`
- MCP executable path matched
- MCP subprocess start time was after the Claude process start time
- 41 `mcp__pfsense__*` tools enumerated via live schema fetch

## Live acceptance test

All 41 registered `mcp__pfsense__pfsense_get_*` tools were invoked live,
once each, with default arguments, against the production pfSense
instance.

Result: **41/41 succeeded.** Zero MCP/tool errors. All responses were
well-formed and schema-consistent. No mutating operation was performed —
every invoked tool is a `get_*` (read) tool, and pfSense's own REST API
configuration independently reports `read_only: true`
(`get_system_restapi_settings`).

Categories exercised: system/status, network/interfaces, firewall
(rules, aliases, NAT, states, shaping), DHCP/DNS, users/auth, services,
diagnostics.

## Operational findings (pfSense-side, not MCP defects)

These were observed via read-only queries against the live pfSense box.
They describe the state of pfSense itself, not a defect in this MCP
server or its tools. No corrective action was taken; pfSense was not
modified.

1. **Expired legacy certificate in the certificate store.** The
   original self-signed `webConfigurator` certificate
   (`refid 61372116e5fc7`, "webConfigurator default (61372116e5fc7)")
   expired 2026-07-02. A replacement certificate
   (`refid 683cad54e59a6`, valid until 2035-05-30) already exists and
   is bound as the active DNS Resolver SSL certificate. The expired
   cert is not in active use but remains present in the store.
2. **Package update available.** `pfSense-pkg-Status_Traffic_Totals`
   is at `2.3.5_2`; `2.3.5_3` is available.

Both are informational and left for the pfSense administrator to
action directly on the box, outside this project's scope.

## Closure

The v0.1.0 READ-only platform (34 capabilities, 41 tools) is accepted
as functionally complete and frozen at the above baseline. No further
READ-capability work or mutating (WRITE) tool implementation proceeds
without separate, explicit authorization.

## Known documentation gap (not addressed by this closeout)

`docs/READ_BACKLOG.md`'s "Coverage summary" table undercounts completed
work (shows 4 completed capabilities; `capabilities.py` currently
supports 34). This mismatch predates this acceptance review and is
tracked here for visibility; reconciling the full 51-row backlog table
against the current implementation is a separate follow-up, not
required for the v0.1.0 READ freeze.
