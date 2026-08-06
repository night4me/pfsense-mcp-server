# pfSense MCP Server

This repository implements a security-focused MCP server for pfSense. Its
current production capability profile is READ-only. Tier 0 WRITE
infrastructure exists but remains inert: no WRITE tools register, the WRITE
endpoint allow-list is empty, and WRITE capabilities are inactive.

## Architecture and security

- Preserve the existing capability-gated architecture and current GET-only
  production behavior.
- Do not activate WRITE capabilities or add MCP tools unless explicitly
  requested and approved.
- Never weaken the security model. Secrets must not appear in MCP schemas,
  model outputs, logs, exceptions, fixtures, or documentation.
- Treat backward compatibility as important unless a security fix requires a
  breaking change.
- Refer to `README.md` for architecture and usage and
  `docs/SECURITY_MODEL.md` for the detailed trust and data model.

## Development workflow

Before starting any new work session, read these files in order:

1. `AGENTS.md`
2. `reports-ai/AI_CONTEXT.md`
3. `reports-ai/latest.md`
4. `reports-ai/NEXT_TASKS.md`

Treat them as the authoritative project context. Do not base decisions only on
Git history. `reports-ai` is a local, Git-ignored symbolic link to the
authoritative external directory `~/reports/`.
Read `reports-ai/CHANGELOG_AI.md` or files under `reports-ai/sessions/` only
when additional historical context is required.

For substantial tasks:

1. Inspect the codebase first.
2. Produce and maintain a short implementation plan.
3. Make incremental, minimal changes.
4. Run appropriate verification before reporting completion.
5. Never claim verification that was not executed.

The standard verification set is Ruff format/check, mypy, pytest,
`make quick`, and `make validate`. Explain when a narrower set is appropriate.
Prefer focused diffs, strong typing, consistent style, and no unnecessary
refactoring.

## Approval boundaries

Explicit approval is required before:

- any live pfSense call or production mutation;
- use of production credentials;
- commit, tag, push, release creation or modification;
- branch deletion, force push, history rewriting, or other destructive Git
  operation.

Use `MockTransport` and approved fixtures whenever possible. Never expose
credentials or identifying production data.

## Reporting

Keep terminal output concise. For larger tasks, write the detailed report to
`reports-ai/latest.md` and summarize only completion,
verification, compatibility impact, remaining risks, and approval status in
the conversation.

After every substantial work session, maintain the external handoff documents
through `reports-ai/` (authoritative target: `~/reports/`):
overwrite `latest.md` with a top-level Quick status section, append exactly one
session entry to `CHANGELOG_AI.md`, update `NEXT_TASKS.md`, update
`AI_CONTEXT.md` only when long-term project knowledge changes, and add one
timestamped Markdown file under `sessions/` when appropriate. These AI reports
are shared operational context and must not be added to the Git repository.
Keep them concise, technical, factual, free of reasoning transcripts, secrets,
and identifying production details.

When a release milestone is complete, also create or update
`reports-ai/RELEASE_REPORT.md` with the milestone goal, implemented and
security changes, compatibility impact, verified test results, known
limitations, and recommended next phase. Do not create a release report before
the milestone is actually complete.

If an architectural or security-impacting action is uncertain, stop and ask
before proceeding.
