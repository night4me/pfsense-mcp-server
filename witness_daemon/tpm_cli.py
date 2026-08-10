"""Subprocess wrappers around tpm2-tools -- the only place in this
daemon that talks to the physical TPM.

No function here accepts a caller-supplied NV handle: `Tpm2ToolsClient`
is constructed once, at daemon startup, with the one handle
`WitnessDaemonConfig` fixes; every subsequent `read_counter()`/
`increment_counter()` call always targets that same handle. This is the
structural half of "the daemon cannot touch arbitrary NV handles" (the
other half is `config.py`'s range validation).

Every `tpm2_nv*` invocation uses a fixed argv list (`shell=False`,
never string-interpolated) and passes the index's authorization secret
only as `-P file:<path>` -- tpm2-tools itself opens and reads that file;
this module never reads the secret's contents into Python memory or
places it in argv, matching this task's own instruction and the
already-accepted design's "Secret generation and storage" section
(anti_rollback_tpm_host_witness.md), which independently found and fixed
the same class of exposure in an earlier draft's provisioning commands.

Read output format: `tpm2_nvread` writes the requested NV counter's raw
bytes to whatever `-o` names -- no `--print-yaml`/text parsing is used
here, deliberately: this project's own research into tpm2-tools' exact
`--print-yaml` output shape for a counter index was inconclusive against
primary sources (see the real-hardware verification report this module
ships alongside), whereas TPM2 NV counters are unambiguously specified
as 8-byte big-endian unsigned integers -- a fact the TPM2 spec itself
guarantees, not tpm2-tools' own text formatting. This keeps parsing
correctness independent of any particular tpm2-tools version's cosmetic
output changes.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path

from .errors import TpmIncrementAmbiguousError, TpmIncrementRejectedError, TpmUnavailableError

_READ_TIMEOUT_SECONDS = 10
_INCREMENT_TIMEOUT_SECONDS = 10
_COUNTER_SIZE_BYTES = 8


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise TpmUnavailableError(f"Required TPM tool not found on PATH: {name}")
    return path


class Tpm2ToolsClient:
    """Talks to the physical TPM exclusively through tpm2-tools
    subprocess invocations against one fixed, configured NV handle."""

    def __init__(self, *, nv_handle: str, auth_credential_path: Path) -> None:
        self._nv_handle = nv_handle
        self._auth_credential_path = auth_credential_path

    def read_counter(self) -> int:
        """Reads the configured counter's current value. Never mutates
        TPM state. Raises `TpmUnavailableError` on any tool-missing,
        process, timeout, or malformed-output failure."""

        tool = _require_tool("tpm2_nvread")
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "nvread.bin"
            argv = [
                tool,
                "-C",
                self._nv_handle,
                "-P",
                f"file:{self._auth_credential_path}",
                "-s",
                str(_COUNTER_SIZE_BYTES),
                "-o",
                str(out_path),
                self._nv_handle,
            ]
            try:
                result = subprocess.run(argv, capture_output=True, timeout=_READ_TIMEOUT_SECONDS, check=False)  # nosec B603
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise TpmUnavailableError("tpm2_nvread could not be executed.") from exc
            if result.returncode != 0:
                raise TpmUnavailableError("tpm2_nvread reported a failure reading the configured NV counter.")
            try:
                raw = out_path.read_bytes()
            except OSError as exc:
                raise TpmUnavailableError("tpm2_nvread output could not be read.") from exc
        if len(raw) != _COUNTER_SIZE_BYTES:
            raise TpmUnavailableError("tpm2_nvread returned an unexpected data length for a counter index.")
        return int.from_bytes(raw, byteorder="big", signed=False)

    def increment_counter(self) -> None:
        """Issues exactly one `TPM2_NV_Increment` against the configured
        counter. Never retried by this method itself -- callers (see
        `service.py`) decide how to respond to
        `TpmIncrementAmbiguousError` vs. `TpmIncrementRejectedError`, and
        must never call this a second time for the same logical
        `advance()` attempt."""

        tool = _require_tool("tpm2_nvincrement")
        argv = [tool, "-C", self._nv_handle, "-P", f"file:{self._auth_credential_path}", self._nv_handle]
        try:
            result = subprocess.run(argv, capture_output=True, timeout=_INCREMENT_TIMEOUT_SECONDS, check=False)  # nosec B603
        except subprocess.TimeoutExpired as exc:
            raise TpmIncrementAmbiguousError("tpm2_nvincrement timed out; outcome unknown.") from exc
        except OSError as exc:
            raise TpmIncrementAmbiguousError("tpm2_nvincrement could not be executed; outcome unknown.") from exc
        if result.returncode != 0:
            raise TpmIncrementRejectedError("tpm2_nvincrement was rejected by the TPM.")
