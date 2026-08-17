# Codex Project Takeover Guide (superseded)

**This in-repo document is superseded and no longer maintained.** It
was written 2026-08-11 at the conclusion of an early implementation
slice (`HANDOFF_SHA` = `48a93862f95981c7c97b47ae94cc8467196b92c5`,
2288 tests, Tier 1 execution-authorization work in progress). The
project has moved substantially since then — v0.4.0/v0.4.1/v0.4.2
shipped, the first live WRITE capability was verified (`ADR-026`), an
offline Nexus research track ran to completion (`ADR-030`–`032`), and
ADR-033's privilege-derivation and provisioning-engine work landed —
so nothing in the original body of this file (SHA, test counts, slice
status) should be treated as current. It is intentionally not linked
from this site's navigation.

**The current, authoritative Codex handover lives outside this
repository**, in the project's external `reports-ai/` directory
(a local, Git-ignored symlink — see `reports-ai/AI_CONTEXT.md`'s own
"External AI handoff reports" note for why it is kept external):

- `reports-ai/CODEX_TAKEOVER.md` — the full handover document.
- `reports-ai/CODEX_START_PROMPT.md` — a short, copy-paste-ready
  starting prompt.
- `reports-ai/latest.md` — current project status at a glance.
- `reports-ai/AI_CONTEXT.md` — durable architecture/roadmap context.
- `reports-ai/NEXT_TASKS.md` — the current outstanding-work queue.

If you are a fresh agent and do not have access to `reports-ai/`, ask
the project owner for it before relying on anything below this notice
— those files are the ones kept current after every phase, this one is
not.

This page is left in place (rather than deleted) only because
[`ADR-025`](adr/ADR-025-authorization-recovery-contract-binding.md)
links to it as further reading, so the link keeps resolving — its
retained presence here is a historical courtesy, not a claim that its
original content remains architecturally relevant.
