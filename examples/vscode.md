# Visual Studio Code

VS Code supports local stdio MCP servers in workspace or user-profile
configuration.

## Installation

Install the project using the [README](../README.md#quick-start). Use user-level
configuration for private appliance settings, or keep a placeholder-only
`.vscode/mcp.json` in a workspace.

## Configuration

Add the following to `mcp.json`:

```json
{
  "servers": {
    "pfsense": {
      "type": "stdio",
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

VS Code documents workspace and profile locations in its
[MCP configuration reference][vscode-mcp].

## Expected behaviour

Start the server from VS Code's MCP controls. The current auditor profile
registers 95 READ tools, 1 guidance tool, and zero WRITE tools. VS Code may ask before a model can
invoke a tool, depending on the selected approval settings.

## Troubleshooting

- Confirm the configuration uses `servers`, not another client's `mcpServers`
  key.
- Check the MCP server output channel for sanitized startup errors.
- Verify the executable and key-file paths are absolute and accessible to the
  VS Code process.
- Do not put the key value in `env`; this server deliberately accepts a key-file
  path instead.

[vscode-mcp]: https://code.visualstudio.com/docs/agents/reference/mcp-configuration
