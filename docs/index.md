# pfsense-mcp-server

A security-focused local MCP server exposing strongly typed READ tools for
pfSense, plus the design documentation for its inert v0.3.0 Tier 1
WRITE-safety framework — the architecture, threat model, and specifications
that must exist and be reviewed *before* any mutating capability is ever
authorized.

This site is a browsable, organized view of the technical documentation
under `docs/`. It does not repeat the project's practical getting-started
material — that lives in the repository's own README, which stays
authoritative for installation, configuration, and quick-start instructions:

- [README — installation, configuration, quick start](https://github.com/night4me/pfsense-mcp-server#readme)
- [CONTRIBUTING — how to propose a change](https://github.com/night4me/pfsense-mcp-server/blob/main/CONTRIBUTING.md)
- [SECURITY — how to report a vulnerability](https://github.com/night4me/pfsense-mcp-server/blob/main/SECURITY.md)
- [Client setup examples](https://github.com/night4me/pfsense-mcp-server/blob/main/examples/README.md)

## What is on this site

- **Architecture** — how the production READ path is built, the Tier 1
  Recovery Contract safety model, and the (still entirely inert) WRITE
  Tier 0 infrastructure.
- **Security** — the threat model, security model, abuse-case catalog, and
  the risk study behind every writable pfSense endpoint class this project
  has inventoried and *not yet* authorized.
- **API reference** — the full MCP tool catalog this server currently
  registers (41 READ tools, zero WRITE tools).
- **Roadmap and planning** — the public roadmap and the detailed,
  phase-gated v0.3.0 Tier 1 implementation plan, including every
  Architecture Decision Record that gates a piece of it.
- **Tier 1 subsystem specifications** — implementation-ready designs for
  the encryption, key lifecycle, anti-rollback, confirmation,
  reconciliation, rate-limiting, and sealed-executor subsystems that make
  up the Recovery Contract safety framework.
- **Release and operations** — how a release actually gets built, checked,
  and published, and this project's dependency/supply-chain policy.
- **Acceptance records** — the point-in-time verification evidence recorded
  at each past release.

## Project status

The production server is READ-only: 41 tools, zero WRITE tools, an empty
WRITE endpoint allow-list. v0.2.2 is the current immutable, published
release. v0.3.0 development continues the Tier 1 safety framework — every
new module remains structurally unreachable from production until an
explicit, separately authorized activation decision is made. See the
[public roadmap](ROADMAP.md) and [v0.3.0 milestone](V0.3.0_MILESTONE.md)
for what "done" looks like for this phase.
