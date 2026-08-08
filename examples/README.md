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
- Expect 41 READ tools and no WRITE tools from the current production profile.

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
names and malformed lists fail closed. Omit it to keep all 41 Auditor tools.
