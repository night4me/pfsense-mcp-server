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
`~/reports/latest.md` and summarize only completion,
verification, compatibility impact, remaining risks, and approval status in
the conversation.

If an architectural or security-impacting action is uncertain, stop and ask
before proceeding.
