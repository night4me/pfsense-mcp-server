# MCP client examples

These guides configure supported MCP clients to launch the local
`pfsense-mcp-server` process over stdio. Start with the project's
[installation and credential instructions](../README.md#quick-start).

| Client | Local stdio support | Guide |
|---|---:|---|
| Claude Desktop | Yes | [Claude Desktop](claude-desktop.md) |
| OpenAI Codex CLI | Yes | [Codex CLI](codex-cli.md) |
| ChatGPT desktop app | Yes, through the Codex host | [ChatGPT](chatgpt.md) |
| Cursor | Yes | [Cursor](cursor.md) |
| Visual Studio Code | Yes | [VS Code](vscode.md) |
| Continue | Yes | [Continue](continue-dev.md) |

## Common security rules

- Use absolute paths to the executable and key file.
- Keep the API-key file outside the repository with owner-only permissions.
- Never put the API-key value in client configuration; provide only
  `PFSENSE_API_KEY_FILE`.
- Keep TLS verification in `strict` mode unless a private CA requires `auto`.
- Treat anyone who can control the local MCP client as able to invoke every
  registered READ tool. See the [security model](../docs/SECURITY_MODEL.md).
- Expect 95 READ tools and no WRITE tools from the current production profile.

The examples use `/absolute/path/to/...` placeholders. Replace every placeholder
before starting the client. Client interfaces and configuration formats can
change; consult the linked vendor documentation when a guide differs from the
installed client version.

To expose a smaller exact subset, add this optional environment variable to any
stdio configuration:

```text
PFSENSE_ALLOWED_TOOLS=pfsense_get_system_status,pfsense_get_interfaces
```

The value can only remove tools from the selected capability profile. Unknown
names and malformed lists fail closed. Omit it to keep all 95 Auditor tools.

## READ-only vs. `write_protected`

Every guide above configures the **default (`auditor`) profile** —
READ-only, 95 tools, 0 WRITE. This is the profile every new installation
gets and the one this project recommends for normal use.

A second profile, `write_protected`, exists and is documented here for
completeness — **selecting it is a deliberate, explicit opt-in, not
something any example above does for you:**

```text
PFSENSE_PROFILE=write_protected
```

Add this single environment variable to any client configuration above
(alongside the existing `PFSENSE_API_URL`/`PFSENSE_IDENTITY`/
`PFSENSE_API_KEY_FILE` variables) to select it. It is **not** the
default — a client configured without this variable behaves exactly as
every guide above describes, with zero WRITE exposure.

**What `write_protected` does and does not do.** Selecting this profile
grants the `ALIAS_WRITE` capability, which makes exactly one MCP tool
reachable, `set_firewall_alias_description_v1` (change a single existing
firewall alias's description field only — nothing else, and only if the
production runtime also constructs successfully, which itself requires
the full Tier 1 security material: pinned authorities, a provisioned
encrypted store, and TPM witness connectivity to be configured — a
deployment without that material still gets 0 WRITE tools even under
`write_protected`). Reaching this tool at all is **not** the same as
being able to use it: every individual mutation still requires a
separate, real signing ceremony the operator personally drives —
generating a fresh authorization, having it independently signed
off-host, generating a confirmation, having that independently signed
off-host, and only then executing — none of which any MCP client, AI
model, or automated process can perform on its own. See
[the security model](../docs/SECURITY_MODEL.md)'s "Recovery and WRITE
status" section and
[ADR-026](../docs/adr/ADR-026-first-write-capability-adapter.md) for the
complete ceremony and its live evidence.

If you don't intend to personally run that ceremony, there is no reason
to select `write_protected` — the default profile already covers every
read/inspect use case this project supports.
