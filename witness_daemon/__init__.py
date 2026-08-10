"""Proxmox-host-side TPM witness daemon (ADR-011's decided `AntiRollbackAnchor`
backend, docs/tier1/specs/anti_rollback_tpm_host_witness.md).

Not part of the `pfsense_mcp` package and never shipped in its wheel or
sdist (`pyproject.toml`'s `packages`/`include` lists never reference this
directory -- mirrors `lab/`'s own packaging exclusion exactly). This is a
completely separate deployable: it runs on the Proxmox host, not the
guest, holds the TPM NV index's own authorization secret (which the
guest must never receive), and is reached by the guest's
`pfsense_mcp.tier1.anti_rollback_tpm_witness.TpmHostWitnessAnchor` only
through the narrow two-operation HTTPS(mTLS) protocol the accepted spec
defines.

Implements exactly `GET /anchor/read` and `POST /anchor/advance` --
nothing else. No generic TPM command execution, no arbitrary NV handle
selection, no shell endpoint: every TPM invocation always targets the
one handle fixed in `WitnessDaemonConfig` at daemon startup, never a
caller-supplied value.
"""
