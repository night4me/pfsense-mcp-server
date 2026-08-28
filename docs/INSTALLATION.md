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

Every method below installs `pfsense-mcp-server` into its own isolated
environment rather than your system's shared Python packages — this
matters concretely on modern Debian/Ubuntu (23.04+, including 24.04
LTS): the system Python is "externally managed"
([PEP 668](https://peps.python.org/pep-0668/)), so a plain `pip install
pfsense-mcp-server` run against it is refused outright. Passing
`--break-system-packages` to force it, or using `sudo pip install`, are
both deliberately **not** recommended here — either risks conflicting
with a package your OS itself depends on. Isolation also keeps this
project's own dependency floors from interacting with anything else on
your machine, regardless of platform.

### Recommended: `pipx`

[`pipx`](https://pipx.pypa.io/) is the standard, PyPA-recommended way to
install a Python command-line application: it creates a dedicated
environment for it automatically and puts its entry-point commands on
your `PATH`.

```console
sudo apt install pipx      # Debian/Ubuntu; see pipx's own docs for other platforms
pipx ensurepath             # adds pipx's bin directory to PATH -- reopen your terminal after
pipx install pfsense-mcp-server==0.9.0
```

Pinning the exact version (`==0.9.0`) is recommended for anything other
than a quick local trial — this project follows semantic versioning, so
a pin protects you from an unreviewed minor/major upgrade landing in
your MCP client's own environment. To always take the latest release
instead, drop the pin (`pipx install pfsense-mcp-server`).

This installs the `pfsense-mcp-server` and `pfsense-mcp-security`
commands to `~/.local/bin/` (pipx's default location) — use
`~/.local/bin/pfsense-mcp-server` as the absolute command path in your
MCP client's configuration (see
[Connect your MCP client](MCP_CLIENT_CONFIGURATION.md)), or confirm the
exact path yourself with `pipx list` or `which pfsense-mcp-server`.

### Alternative: virtual environment + `pip`

If you'd rather manage a project-local virtual environment directly —
for example, to keep it alongside other tooling in a specific
directory, or on a platform where `pipx` isn't packaged:

```console
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install pfsense-mcp-server==0.9.0
```

To always take the latest release instead of a pinned version:

```console
.venv/bin/python -m pip install --upgrade pfsense-mcp-server
```

This gives you one unambiguous path
(`.venv/bin/pfsense-mcp-server`) to put in an MCP client's launch
configuration — an absolute path to wherever you created `.venv`.

### Alternative: `uv tool install`

If you already use [`uv`](https://docs.astral.sh/uv/), it offers the
same isolation as `pipx`, generally installing faster:

```console
uv tool install pfsense-mcp-server==0.9.0
```

`uv` installs to the same `~/.local/bin/` location `pipx` does by
default.

### Verifying what you installed

`pfsense-mcp-server` is published with
[PEP 740](https://peps.python.org/pep-0740/) digital attestations,
verifiable back to this repository and the exact release commit that
built them — there is no long-lived PyPI upload token involved in
publishing it. This applies no matter which method above you used, since
all three ultimately fetch the same signed artifact from PyPI.

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
pfsense-mcp-server
```

(`pipx`/`uv tool install` put `pfsense-mcp-server` directly on your
`PATH`; if you used the venv + `pip` alternative, run
`.venv/bin/pfsense-mcp-server` instead.)

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

- **97 total tools**: 95 pfSense READ tools + 2 documentation guidance
  tools (`pfsense_get_official_guidance`, `pfsense_get_api_guidance`).
- **0 WRITE tools** — this is the default (`auditor`) profile, and the
  one this project recommends for normal use.

Then try asking it something simple and read-only, e.g. *"What pfSense
version is this appliance running?"* — see the
[README's example prompts](https://github.com/night4me/pfsense-mcp-server#what-it-does)
for more.

## Upgrading

```console
pipx upgrade pfsense-mcp-server
```

Used the venv + `pip` alternative instead?
`.venv/bin/python -m pip install --upgrade pfsense-mcp-server`. Used
`uv tool install`? `uv tool upgrade pfsense-mcp-server`.

Check `CHANGELOG.md` for the exact delta between your installed
version and the new one before upgrading anything you depend on —
every release states plainly whether the public MCP tool contract
changed. Restart your MCP client (or the server process, if launched
directly) after upgrading for the new version to take effect.

## Uninstalling

```console
pipx uninstall pfsense-mcp-server
```

Used the venv + `pip` alternative instead? Remove the virtual
environment directory (no separate uninstall command is needed). Used
`uv tool install`? `uv tool uninstall pfsense-mcp-server`. In every
case, also remove the MCP client configuration entry that launched it.
This project never writes outside its own installed environment, your
explicitly-configured credential file path, and (only if you explicitly
use
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
