# TPM host-witness daemon

Implements the Proxmox-host side of `ADR-011`'s decided anti-rollback
anchor backend — see
[`docs/tier1/specs/anti_rollback_tpm_host_witness.md`](../docs/tier1/specs/anti_rollback_tpm_host_witness.md)
for the full accepted design this code implements.

**Not part of the `pfsense_mcp` package.** This directory is never
included in the wheel or sdist (`pyproject.toml`'s `packages`/`include`
lists never reference it — the same packaging-exclusion pattern already
used for `lab/`), and is never imported by anything under
`src/pfsense_mcp/` (enforced by
`witness_daemon/tests/test_isolation.py`). It runs as a **separate
process, on a separate machine** (the Proxmox host, not the guest VM
that runs `pfsense-mcp-server`).

## Running the tests

Excluded from the default pytest collection, exactly like `lab/`:

```console
pytest witness_daemon/
```

Tests use only synthetic/mock TPM behavior (a fake `TpmClient`, and a
monkeypatched `subprocess.run` for `tpm_cli.py`'s own tests) — nothing
here ever shells out to a real `tpm2_nv*` command or touches a real TPM.

## Running the daemon

```console
python -m witness_daemon
```

Requires the seven `WITNESS_*` environment variables documented in
`config.py`'s module docstring, and `tpm2-tools` on `PATH`. See
`systemd/pfsense-mcp-tpm-witness.service` for a reference (not
installed/enabled by this repository) systemd unit implementing the
accepted spec's full hardening requirements. `Ctrl+C` shuts the process
down cleanly (`main.py` closes the listening socket and exits 0 rather
than propagating `KeyboardInterrupt`).

## Connecting from the guest

`TpmHostWitnessAnchor` (`pfsense_mcp.tier1.anti_rollback_tpm_witness`)
takes an already-configured `httpx.Client` — it never builds its own
trust materials. The pattern below is **confirmed working against real
hardware** (2026-08-10 real-Proxmox-host verification, `httpx==0.28.1`):

```python
import ssl

import httpx

from pfsense_mcp.tier1.anti_rollback_tpm_witness import TpmHostWitnessAnchor

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations(cafile="/path/to/server.crt")  # the daemon's own pinned certificate
ssl_context.load_cert_chain(certfile="/path/to/client.crt", keyfile="/path/to/client.key")

client = httpx.Client(verify=ssl_context, trust_env=False, timeout=10.0)
anchor = TpmHostWitnessAnchor(client=client, base_url="https://<daemon-host>:<port>")
value = anchor.read()
```

`trust_env=False` matters here specifically: httpx's default (`trust_env=True`)
makes the client honor ambient environment variables such as
`HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` and `~/.netrc`. For this internal,
pinned-mTLS-only channel, an unrelated proxy variable happening to be
set in the caller's environment could silently route the connection
through an intermediary the daemon was never designed to be reached
through (breaking the direct end-to-end TLS assumption the pinned
certificates rely on) — `trust_env=False` makes the connection's
behavior depend only on what this code explicitly configures, never on
ambient shell state. This was part of the exact configuration confirmed
working during real-hardware verification (2026-08-10, `httpx==0.28.1`);
it is not optional for this use case, not merely a preference.

**Do not use** `httpx.Client(cert=(cert, key), verify="/path/to/ca.crt")`
for this — that shorthand was found unreliable for client-certificate
configuration during real-hardware verification on `httpx>=0.28`. Build
the `ssl.SSLContext` explicitly as shown, matching `PROTOCOL_TLS_CLIENT`'s
own default `verify_mode=CERT_REQUIRED`/`check_hostname=True` (never
relax either). The server's certificate must carry an `IP:`-type
`subjectAltName` matching whatever address `base_url` connects to —
`httpx`/the stdlib `ssl` module verify against SAN entries only, never
the certificate's `CN`.

## What this is not

- Not a general TPM management tool — it exposes exactly two operations
  (`read`, `advance`) against exactly one, fixed-at-startup NV handle.
- Not reachable from, and never holds any dependency on,
  `pfsense_mcp.rest_api_client`/`transport`/`tools`/`write_api_client`/
  `pfsense_client` — it has no relationship to pfSense at all.
- Not deployed, enabled, or started by anything in this repository or
  its CI — deployment is a separate, host-local, operator action.
