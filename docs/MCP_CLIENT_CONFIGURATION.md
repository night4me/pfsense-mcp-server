# Connect your MCP client

There are two ways to get `pfsense-mcp-server` into your MCP client's
configuration: let `pfsense-mcp-security` generate it for you (the
recommended path once you have a working server configuration), or
copy one of the static per-client examples and edit it by hand.

## MCP client config generation

Once your server configuration works (see [Installation](INSTALLATION.md)
and the [setup wizard](SECURITY_SETUP_WIZARD.md)), generate the exact
client configuration block for the target you configured:

```console
pfsense-mcp-security setup write-client-config \
  --client claude-desktop --config-path /absolute/path/to/claude_desktop_config.json \
  --capability-posture read_only --anchor-assurance none
```

`--client` (`claude-desktop` or `codex` — `codex` also covers the
ChatGPT desktop app, which shares Codex CLI's own config file),
`--capability-posture`, and `--anchor-assurance` are required and must
match the values your `setup`/`setup apply` run used. `--config-path` is
required for `claude-desktop` (no built-in default); optional for
`codex` (defaults to `~/.codex/config.toml`).

**Inspection-only by default.** With no `--confirm`, this only prints
the proposed diff and a confirmation token — it never touches any file
on disk. Copy the printed block into your MCP client's own
configuration by hand, or use the write/merge mode below.

### Write/merge mode

```console
pfsense-mcp-security setup write-client-config \
  --client claude-desktop --config-path /absolute/path/to/claude_desktop_config.json \
  --capability-posture read_only --anchor-assurance none \
  --confirm <TOKEN-FROM-THE-INSPECTION-ABOVE>
```

Passing the exact confirmation token a prior inspection printed (this
is a *separate* token from any pfSense-side setup/apply confirmation —
never reused across the two) enables **write/merge mode**. You can
additionally pass `--plan-digest <DIGEST-FROM-THE-INSPECTION-ABOVE>` —
optional, but recommended: if the underlying pfSense-side plan has
changed since you inspected it, this makes the command refuse rather
than proceed against stale state.

- **Merge-only, never a whole-file replacement.** This project's own
  test suite proves this directly (not merely documents it): an
  existing client config file's other entries, and any unrelated JSON/
  TOML content in the same file, survive unchanged — only the
  `pfsense` MCP server entry itself is added or updated.
- **An automatic backup is made first.** If the destination file
  already exists, it is copied to `<path>.bak` (exclusive create — the
  command refuses if a `.bak` from a prior interrupted attempt is
  already present, rather than overwriting it) before the real file is
  written.
- **Atomic write with read-back verification.** After writing, the
  command reads the file back and confirms it matches exactly; if not,
  the original is restored (or the new file removed, if none existed
  before) — no lasting change is made on a verification mismatch.
- **Malformed existing config is refused, not repaired.** If the
  destination file already exists but isn't valid JSON/TOML for that
  client, or the target path is a symlink or not owned by the current
  user, the command refuses and makes no change — it does not attempt
  to guess or fix a broken or unsafe file for you.
- **Confirmation is required for every write** — there is no `--force`
  or "always write" flag; every invocation that would touch a real file
  needs its own fresh token from a prior inspection, exactly like
  `setup apply`'s own confirmation model. The confirmation is also
  bound to the exact client, config path, and current on-disk file
  content at inspection time — a file that changed since inspection is
  refused, even with a valid token.

## Manual, per-client examples

If you'd rather edit client configuration by hand, or your client isn't
covered by the generator above, see
[`examples/README.md`](https://github.com/night4me/pfsense-mcp-server/blob/main/examples/README.md)
on GitHub for copy/paste-ready guides covering Claude Desktop, Claude
Code, Codex CLI, ChatGPT desktop (via the Codex host), Cursor, VS Code,
and Continue.

## Common security rules (either path)

- Use absolute paths to the executable and key file.
- Keep the API-key file outside this project's own directory, with
  owner-only permissions.
- Never put the API-key *value* in client configuration — only the
  `PFSENSE_API_KEY_FILE` path.
- Keep TLS verification in `strict` mode unless a private CA requires
  `auto`.
- Anyone who can control your local MCP client can invoke every
  registered READ tool — see [the security model](SECURITY_MODEL.md).
- The default profile registers 95 READ tools + 2 guidance tools, 0
  WRITE tools. Selecting `write_protected` is a separate, deliberate
  opt-in — see [the setup
  wizard](SECURITY_SETUP_WIZARD.md#advanced-and-recovery-paths) and
  [the security model](SECURITY_MODEL.md) before choosing it.

## Related

- [Installation](INSTALLATION.md)
- [Security setup wizard](SECURITY_SETUP_WIZARD.md)
- [Configuration reference](CONFIGURATION.md)
