# Getting started

Four steps, in order. Most users only need the first three.

## 1. Install

```console
pip install pfsense-mcp-server
```

Requires Python 3.11, 3.12, or 3.13, and a pfSense appliance with the
REST API package (`pfrest`/`pfSense-pkg-RESTAPI`, API v2) installed and
enabled. See [Compatibility](COMPATIBILITY.md) for exactly which
pfSense editions/releases are directly verified.

## 2. Run the guided setup

```console
pfsense-mcp-security setup
```

This is a short, interactive wizard: it asks for your firewall's
address, which safety level you want (read-only is the default and
recommended choice — see [Security model](SECURITY_MODEL.md) for what
each level means), and how to verify the connection. It never changes
anything by itself — it only produces a plan for you to review. Full
detail on every question it asks: [Security setup wizard](SECURITY_SETUP_WIZARD.md).

## 3. Connect your AI client

The wizard's last step prints the exact configuration block for your
MCP client. You can also generate it directly, with a preview and
explicit confirmation before anything is written:

```console
pfsense-mcp-security setup write-client-config \
  --client claude-desktop --config-path /absolute/path/to/claude_desktop_config.json \
  --capability-posture read_only --anchor-assurance none
```

Full detail, every supported client, and manual configuration if you'd
rather not use the generator: [Connect your MCP client](MCP_CLIENT_CONFIGURATION.md).

## 4. First use

Once your client shows the server connected (97 tools registered — 95
READ + 2 guidance), ask it something concrete:

- *"What's my pfSense version and which packages are installed?"*
- *"List my VLANs and which interface each one rides on."*
- *"Is my WAN gateway up right now?"*
- *"Which certificates expire soon?"*

If nothing responds, or the connection fails, `pfsense-mcp-security
doctor` diagnoses protected-change readiness (not applicable if you
chose read-only); TLS/connectivity/authentication problems show up
directly in your MCP client's own connection error, covered in the
"Something not working?" section below.

## Something not working?

- **Certificate/TLS errors** — see [Security setup wizard](SECURITY_SETUP_WIZARD.md)'s
  TLS section. Never disable certificate verification as a shortcut;
  the wizard's `auto`/CA-file path handles a self-signed appliance
  certificate safely.
- **Authentication errors** — confirm the API key file path in your
  MCP client's configuration matches what `setup` printed, and that
  the file's first line is the key with no extra whitespace.
- **Missing privileges** — `pfsense-mcp-security discover` reports
  exactly what the configured identity can and cannot do today.
- **MCP client doesn't see the server at all** — re-run
  `pfsense-mcp-security setup write-client-config` and compare its
  output against what's actually in your client's config file; a stale
  or hand-edited path is the most common cause.

Full configuration reference, every environment variable, and every
error this server can produce: [Configuration reference](CONFIGURATION.md).
