# Installation

A complete, from-scratch path to a running `pfsense-mcp-server`. If
you've done this before and just need the copy/paste commands, see the
[README's Quick start](https://github.com/night4me/pfsense-mcp-server#quick-start)
section instead — this page explains the same steps in more depth.

## Prerequisites

- **Python 3.11, 3.12, or 3.13.** No other Python version is tested or
  supported.
- **A pfSense appliance with the REST API package installed and
  enabled** — `pfrest` / `pfSense-pkg-RESTAPI`, API v2. This project's
  typed response models are pinned against the **v2.10** schema; see
  [Compatibility](COMPATIBILITY.md) for exactly which pfSense
  editions/releases and REST API package combinations have been
  directly verified, versus merely expected to work.
- **An existing pfSense user with an API key** — this project never
  creates one for you automatically at server-launch time. If you'd
  rather have a *dedicated, least-privilege* service account created
  and verified for you instead of reusing an existing credential, see
  [the security setup wizard](SECURITY_SETUP_WIZARD.md), which
  automates exactly that.

## Install from PyPI

```console
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install pfsense-mcp-server==0.8.0
```

Pinning the exact version (`==0.8.0`) is recommended for anything other
than a quick local trial — this project follows semantic versioning, so
a pin protects you from an unreviewed minor/major upgrade landing in
your MCP client's own environment. To always take the latest release
instead, drop the pin:

```console
.venv/bin/python -m pip install --upgrade pfsense-mcp-server
```

`pfsense-mcp-server` is published with
[PEP 740](https://peps.python.org/pep-0740/) digital attestations,
verifiable back to this repository and the exact release commit that
built them — there is no long-lived PyPI upload token involved in
publishing it.

A dedicated virtual environment (as shown above), rather than a
system-wide or user-wide install, is recommended: it keeps this
project's own dependency floors from interacting with anything else on
your machine, and gives you one unambiguous path
(`.venv/bin/pfsense-mcp-server`) to put in an MCP client's launch
configuration.

## Obtain and configure a credential safely

1. In pfSense, under the REST API package's own user/key management,
   generate an API key for the identity you intend to use (or use
   [the setup wizard](SECURITY_SETUP_WIZARD.md) to provision a fresh,
   dedicated, least-privilege identity instead of reusing an existing
   one).
2. Save **only the key itself** to a file *outside* this project's
   directory, with owner-only permissions:

   ```console
   install -m 600 /dev/null /absolute/private/path/pfsense-api.key
   # paste the key as the file's first (and only) line
   ```

   The server reads **only the first line** of this file at startup —
   never an environment variable, never a command-line argument, never
   anything logged. The file must be a regular file (not a symlink)
   owned by the user running the server, with no group/other
   permission bits, or the server refuses to start. See
   [the security model](SECURITY_MODEL.md) for the full credential-
   handling design.

## TLS verification

Leave `PFSENSE_TLS_MODE` at its default, `strict` — this validates the
appliance's certificate against your system's normal trust store,
exactly like a browser would. Only change this if pfSense presents a
self-signed or internal-CA certificate:

- **Internal/private CA**: set `PFSENSE_TLS_MODE=auto` and
  `PFSENSE_TLS_CA_FILE` to a readable CA bundle path. This is the
  correct fix for "certificate verify failed" against a real internal
  CA — never disable verification to work around it.
- **`PFSENSE_TLS_MODE=insecure`** disables certificate verification
  entirely. It is never a default and must be set explicitly. Treat it
  as a short-lived diagnostic step only (e.g. confirming the rest of
  your configuration is correct before fixing TLS properly), never a
  standing production configuration — an attacker on your network path
  could otherwise impersonate the appliance undetected.

## First start

Launch the server directly to confirm configuration before pointing an
MCP client at it:

```console
PFSENSE_API_URL=https://pfsense.example.invalid \
PFSENSE_IDENTITY=api-mcp-admin \
PFSENSE_API_KEY_FILE=/absolute/private/path/pfsense-api.key \
PFSENSE_TLS_MODE=strict \
.venv/bin/pfsense-mcp-server
```

A correctly configured server waits silently on stdin for MCP protocol
messages — it does not print a banner. `Ctrl-C` to stop it. If
configuration is invalid, it prints a `configuration error` naming the
problem and exits immediately (fail-closed — it never falls back to an
insecure default). See [Configuration reference](CONFIGURATION.md) for
every environment variable and the full troubleshooting table.

## Verification

Once a real MCP client (see
[Connect your MCP client](MCP_CLIENT_CONFIGURATION.md)) is configured
and connected, confirm it reports:

- **96 total tools**: 95 pfSense READ tools + 1 documentation guidance
  tool (`pfsense_get_official_guidance`). (A `v0.9.0` release candidate
  adds a second guidance tool, `pfsense_get_api_guidance` — 97 total —
  but is not yet published; see `CHANGELOG.md` for the current
  published-vs-candidate state before assuming a count higher than 96.)
- **0 WRITE tools** — this is the default (`auditor`) profile, and the
  one this project recommends for normal use.

Then try asking it something simple and read-only, e.g. *"What pfSense
version is this appliance running?"* — see the
[README's example prompts](https://github.com/night4me/pfsense-mcp-server#what-it-does)
for more.

## Upgrading

```console
.venv/bin/python -m pip install --upgrade pfsense-mcp-server
```

Check `CHANGELOG.md` for the exact delta between your installed
version and the new one before upgrading anything you depend on —
every release states plainly whether the public MCP tool contract
changed. Restart your MCP client (or the server process, if launched
directly) after upgrading for the new version to take effect.

## Uninstalling

```console
.venv/bin/python -m pip uninstall pfsense-mcp-server
```

Then remove the virtual environment directory and the MCP client
configuration entry that launched it. This project never writes
outside its own virtual environment, your explicitly-configured
credential file path, and (only if you explicitly use
[`setup write-client-config`](SECURITY_SETUP_WIZARD.md#mcp-client-config-generation))
the one MCP client configuration file you point it at — there is no
other local state to clean up.

## Troubleshooting

See [Configuration reference](CONFIGURATION.md)'s troubleshooting
table for the full list of symptoms and fixes.

## Related

- [Compatibility](COMPATIBILITY.md) — exact pfSense edition/version and
  REST API package evidence.
- [Security setup wizard](SECURITY_SETUP_WIZARD.md) — provision a
  dedicated, least-privilege pfSense identity instead of reusing an
  existing one.
- [Connect your MCP client](MCP_CLIENT_CONFIGURATION.md).
- [Configuration reference](CONFIGURATION.md).
