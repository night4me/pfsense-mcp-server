# Continue

Continue supports local stdio MCP servers in Agent mode.

## Installation

Install the project using the [README](../README.md#quick-start). Open the
Continue configuration used by your IDE. The YAML format below can be included
in the main `config.yaml` or adapted to a standalone block under
`.continue/mcpServers/` with the metadata required by Continue.

## Configuration

```yaml
mcpServers:
  - name: pfSense
    type: stdio
    command: /absolute/path/to/pfsense-mcp-server/.venv/bin/pfsense-mcp-server
    env:
      PFSENSE_API_URL: https://pfsense.example.invalid
      PFSENSE_IDENTITY: api-mcp-admin
      PFSENSE_API_KEY_FILE: /absolute/private/path/pfsense-api.key
      PFSENSE_TLS_MODE: strict
```

See Continue's [MCP configuration guide][continue-mcp] for current file
locations and standalone-block requirements.

## Expected behaviour

In Agent mode, Continue loads the `pfSense` server and discovers 95 READ
tools plus 2 guidance tools. No WRITE tool is available. Tool approval
behaviour depends on the Continue version and local agent settings.

## Troubleshooting

- MCP tools are available in Agent mode, not every Continue interaction mode.
- Validate YAML indentation and use absolute paths.
- Reload the IDE after changing configuration.
- Inspect only sanitized errors and file metadata when diagnosing credential
  loading; never copy the key into configuration or logs.

[continue-mcp]: https://docs.continue.dev/customize/deep-dives/mcp
