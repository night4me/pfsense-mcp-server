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
accepted spec's full hardening requirements.

## What this is not

- Not a general TPM management tool — it exposes exactly two operations
  (`read`, `advance`) against exactly one, fixed-at-startup NV handle.
- Not reachable from, and never holds any dependency on,
  `pfsense_mcp.rest_api_client`/`transport`/`tools`/`write_api_client`/
  `pfsense_client` — it has no relationship to pfSense at all.
- Not deployed, enabled, or started by anything in this repository or
  its CI — deployment is a separate, host-local, operator action.
