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
Git history. `reports-ai` is a local, Git-ignored symbolic link to an
external, maintainer-controlled directory outside this repository. Its own
`reports-ai/README.md` is the full entry point for that directory's structure,
authority, and update responsibilities — read it once per session alongside
the four files above; this section states only the minimum required order.
Read `reports-ai/CHANGELOG_AI.md` or files under `reports-ai/handoff/` only
when additional historical context is required. Durable architecture
decisions and specifications live under versioned `docs/adr/` and
`docs/tier1/specs/` in this Git repository, never under `reports-ai/` — see
`reports-ai/README.md` for why that split is deliberate.

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

### Long-running validation

`pytest`, `make quick`, `make validate`, `make release-check`,
`min-deps-check`, and `reproducible-build` are allowed to finish naturally.
Do not wrap them in an arbitrary shell `timeout` unless the repository
itself already requires one (network-facing steps only — see
`.github/workflows/publish.yml`'s `timeout-minutes`). Do not infer failure
from elapsed wall-clock time alone, and do not treat the loss of an
interactive orchestration wrapper's output as proof the underlying process
died. If a command may outlive the current session, run it detached with
persistent stdout/stderr logging (e.g. `nohup <cmd> > /tmp/<name>.log 2>&1 &
disown`, retaining the PID via `echo $!`), and recover/inspect that PID and
log on return rather than starting a duplicate run. Never rerun an expensive
validation merely because output was lost if the original process may still
be running — only rerun after proving the previous process terminated and
its result cannot be recovered.

### Test parallelism

The default test suite (`make quick`'s `[4/11]` stage, `make validate`'s
`[4/20]` stage) runs under `pytest-xdist` (`-n 6 --dist=loadscope`) plus a
small serial pass for the handful of tests that cannot safely collect in
parallel — see `XDIST_SERIAL_ONLY` in the `Makefile`. Do not add a test to
that serial list to silence a flake without first root-causing whether it is
a genuine collection-order/shared-state hazard (as the two current entries
are) or an actual production concurrency defect, in which case stop and
report rather than reaching for the serial list as a workaround.

## File ownership invariant

Codex itself must run as the normal repository operator, `tomfrode:tomfrode`,
for all normal development work. Running Codex through `sudo` or otherwise as
`root` is prohibited. Git operations, edits, tests, builds, `gh` commands,
documentation work, and external report updates must all run as `tomfrode`.
Use `sudo` only for a narrowly scoped privileged command when genuinely
required; never use it to run Codex or an ordinary development workflow.

- Before starting normal development work and before finalizing any task, run:

  ```bash
  test "$(id -un)" = "tomfrode"
  test "$(id -gn)" = "tomfrode"
  ```

  A failure is a blocking condition: stop and restart Codex as `tomfrode`
  rather than continuing through a root-run agent.

All repository files and directories, and all files and directories under the
external reports target `/home/tomfrode/reports`, must remain owned by the
normal repository operator, `tomfrode:tomfrode`. Agents must never leave
source, tests, documentation, generated tracked artifacts, repository
directories, or external handoff/report files owned by `root` or another
account. The repository's `reports-ai` symlink does not exempt its external
target from this invariant.

- Before editing, verify that the applicable root and every target file are
  owned by and writable by `tomfrode`. Before writing an external handoff,
  verify `/home/tomfrode/reports` and the target report path the same way.
  Repair an ownership mismatch before editing; it is a blocking preflight
  condition.
- Do not perform normal repository editing as `root`, and do not create new
  repository or report files from a root shell.
- Elevated/root execution is permitted only for genuinely privileged
  external-system operations, never ordinary repository editing.
- After any privileged command that may affect either authorized root, recheck
  ownership. Do not use `chmod` to mask an ownership problem, and preserve
  existing permission modes unless a separate permission defect is proven.
  Do not follow or alter unrelated symlink targets outside the repository and
  `/home/tomfrode/reports`.
- Before finalizing any task, run:

  ```bash
  find . -xdev \( ! -user tomfrode -o ! -group tomfrode \) -print
  find /home/tomfrode/reports -xdev \( ! -user tomfrode -o ! -group tomfrode \) -print
  ```

  Any unintended output from either check is a blocking finalization failure and must be
  repaired or reported rather than handed off as a successful repository.

## Approval boundaries

Explicit approval is required before:

- any live pfSense call or production mutation;
- use of production credentials;
- tag, release creation or modification;
- branch deletion, force push, history rewriting, or other destructive Git
  operation;
- repository visibility changes, or enabling/disabling GitHub Pages.

Ordinary commits and pushes to `main` operate under the standing delegation
terms recorded in `reports-ai/AI_CONTEXT.md`'s "Push authorization" section
(current validation/safety preconditions) together with the publication-
awareness gate below — not a blanket per-push approval requirement.

### Publication-awareness gate (owner-adopted 2026-08-09)

The repository is public. Ordinary technical development pushes to `main`
remain delegated under the existing validation and safety rules (clean tree,
`make quick`/`make validate` green, no credentials/`reports-ai/` content,
WRITE stays inactive — see `reports-ai/AI_CONTEXT.md`).

**Changes whose primary effect is public-facing communication require a
brief owner visibility check before push.** This includes, at minimum:

- `README.md`;
- public docs prose under `docs/`;
- `CHANGELOG.md`;
- release notes;
- GitHub-visible repository metadata (About description, topics, Pages
  presentation/content);
- any other change whose main purpose is how the project is presented
  publicly.

This is **not** a full implementation-approval gate — it is a
publication-awareness gate: the owner sees what is about to ship before it
does, not a request to re-approve the underlying engineering work.

Technical changes that incidentally require small documentation updates may
still be pushed under standing engineering delegation when the
documentation is strictly necessary to keep code and docs synchronized,
provided the change does not materially alter public positioning, claims,
promises, or security messaging.

**This gate does not authorize, and must never be reinterpreted as
authorizing**: releases, tags, PyPI publication, repository visibility
changes, GitHub Pages enable/disable actions, force-push/history rewriting,
WRITE activation, live pfSense calls, or production credential use. All of
those remain separately owner-controlled, exactly as stated elsewhere in
this section.

For every production release, the permanent **Owner Approval Gate** is immediately
before creation of the immutable version tag. Complete the full release
preflight and present the exact commit, CI, CodeQL, release-check, artifact,
OIDC configuration, MCP inventory, and WRITE-inactivity evidence. Then ask
exactly: "Approve creation of immutable tag vX.Y.Z and production release?"
Do not create or move the tag, push it, create the GitHub Release, or allow the
PyPI workflow to execute until the owner explicitly approves. After approval,
re-verify that local HEAD and `origin/main` still equal the approved SHA before
the first irreversible action. The mandatory GitHub environment `pypi` remains
part of the Trusted Publisher identity; it is not the human approval mechanism.

Use `MockTransport` and approved fixtures whenever possible. Never expose
credentials or identifying production data.

## Reporting

Keep terminal output concise. For larger tasks, write the detailed report to
`reports-ai/latest.md` and summarize only completion,
verification, compatibility impact, remaining risks, and approval status in
the conversation.

After every substantial work session, maintain the external handoff documents
through `reports-ai/` (its symlink target, described above):
overwrite `latest.md` with a top-level Quick status section, append exactly one
session entry to `CHANGELOG_AI.md`, update `NEXT_TASKS.md`, update
`AI_CONTEXT.md` only when long-term project knowledge changes, and add one
timestamped Markdown file under `handoff/` when appropriate. These AI reports
are shared operational context and must not be added to the Git repository.
Keep them concise, technical, factual, free of reasoning transcripts, secrets,
and identifying production details.

When a release milestone is complete, also create or update
`reports-ai/releases/RELEASE_REPORT.md` with the milestone goal, implemented
and security changes, compatibility impact, verified test results, known
limitations, and recommended next phase. Do not create a release report before
the milestone is actually complete.

If an architectural or security-impacting action is uncertain, stop and ask
before proceeding.
