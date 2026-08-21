# Claude Desktop

Claude Desktop supports local MCP servers. Its current preferred distribution
format is a Desktop Extension; this repository does not yet publish one. The
developer-defined local-server configuration below runs the installed entry
point directly.

## Installation

Install the project in a virtual environment as described in the
[README](../README.md#quick-start). In Claude Desktop, ensure local developer
MCP servers are permitted by your account or organization policy.

## Configuration

Open Claude Desktop's developer MCP configuration and add this server to the
top-level `mcpServers` object:

```json
{
  "mcpServers": {
    "pfsense": {
      "command": "/absolute/path/to/pfsense-mcp-server/.venv/bin/pfsense-mcp-server",
      "env": {
        "PFSENSE_API_URL": "https://pfsense.example.invalid",
        "PFSENSE_IDENTITY": "api-mcp-admin",
        "PFSENSE_API_KEY_FILE": "/absolute/private/path/pfsense-api.key",
        "PFSENSE_TLS_MODE": "strict"
      }
    }
  }
}
```

Restart Claude Desktop after saving the configuration. Anthropic's
[local MCP server guide][claude-local] describes the current settings and
enterprise controls.

## Expected behaviour

Claude Desktop starts the process on demand and displays the pfSense tools. The
auditor profile exposes 84 READ tools and no WRITE tools. Tool invocations can
query the configured appliance but cannot mutate it.

## Troubleshooting

- If the server is absent, restart Claude Desktop and verify local developer MCP
  servers are allowed.
- If startup fails, use absolute paths and confirm the entry point is executable.
- If configuration is rejected, check the HTTPS URL, key-file ownership and
  permissions, and TLS mode without displaying the key.
- Review Claude Desktop's MCP logs, but never paste logs containing appliance
  details into a public issue.

[claude-local]: https://support.anthropic.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop
