from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from witness_daemon.errors import TpmIncrementAmbiguousError, TpmIncrementRejectedError, TpmUnavailableError
from witness_daemon.tpm_cli import Tpm2ToolsClient

_HANDLE = "0x01500000"
_AUTH_PATH = Path("/run/credentials/witness/nv-index-auth")


def _client() -> Tpm2ToolsClient:
    return Tpm2ToolsClient(nv_handle=_HANDLE, auth_credential_path=_AUTH_PATH)


class _FakeCompletedProcess:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode
        self.stdout = b""
        self.stderr = b""


def _writes_bytes(data: bytes):
    """Returns a fake `subprocess.run` that writes `data` to the `-o`
    argument's target path before returning success -- simulates
    tpm2_nvread's real behavior without ever invoking it."""

    def _fake_run(argv, **kwargs):
        out_index = argv.index("-o") + 1
        Path(argv[out_index]).write_bytes(data)
        return _FakeCompletedProcess(0)

    return _fake_run


def test_read_counter_success():
    with (
        patch("witness_daemon.tpm_cli.shutil.which", return_value="/usr/bin/tpm2_nvread"),
        patch("witness_daemon.tpm_cli.subprocess.run", side_effect=_writes_bytes((2).to_bytes(8, "big"))),
    ):
        assert _client().read_counter() == 2


def test_read_counter_large_value_success():
    with (
        patch("witness_daemon.tpm_cli.shutil.which", return_value="/usr/bin/tpm2_nvread"),
        patch(
            "witness_daemon.tpm_cli.subprocess.run",
            side_effect=_writes_bytes((8675309).to_bytes(8, "big")),
        ),
    ):
        assert _client().read_counter() == 8675309


def test_read_counter_malformed_output_length_raises_unavailable():
    with (
        patch("witness_daemon.tpm_cli.shutil.which", return_value="/usr/bin/tpm2_nvread"),
        patch("witness_daemon.tpm_cli.subprocess.run", side_effect=_writes_bytes(b"\x00\x01\x02")),
        pytest.raises(TpmUnavailableError, match="unexpected data length"),
    ):
        _client().read_counter()


def test_read_counter_tool_missing_raises_unavailable():
    with (
        patch("witness_daemon.tpm_cli.shutil.which", return_value=None),
        pytest.raises(TpmUnavailableError, match="not found on PATH"),
    ):
        _client().read_counter()


def test_read_counter_nonzero_exit_raises_unavailable():
    with (
        patch("witness_daemon.tpm_cli.shutil.which", return_value="/usr/bin/tpm2_nvread"),
        patch("witness_daemon.tpm_cli.subprocess.run", return_value=_FakeCompletedProcess(1)),
        pytest.raises(TpmUnavailableError, match="failure reading"),
    ):
        _client().read_counter()


def test_read_counter_process_error_raises_unavailable():
    with (
        patch("witness_daemon.tpm_cli.shutil.which", return_value="/usr/bin/tpm2_nvread"),
        patch("witness_daemon.tpm_cli.subprocess.run", side_effect=OSError("boom")),
        pytest.raises(TpmUnavailableError, match="could not be executed"),
    ):
        _client().read_counter()


def test_read_counter_timeout_raises_unavailable():
    with (
        patch("witness_daemon.tpm_cli.shutil.which", return_value="/usr/bin/tpm2_nvread"),
        patch(
            "witness_daemon.tpm_cli.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="tpm2_nvread", timeout=10),
        ),
        pytest.raises(TpmUnavailableError, match="could not be executed"),
    ):
        _client().read_counter()


def test_increment_counter_success():
    with (
        patch("witness_daemon.tpm_cli.shutil.which", return_value="/usr/bin/tpm2_nvincrement"),
        patch("witness_daemon.tpm_cli.subprocess.run", return_value=_FakeCompletedProcess(0)) as run,
    ):
        _client().increment_counter()
        run.assert_called_once()


def test_increment_counter_rejected_by_tpm():
    with (
        patch("witness_daemon.tpm_cli.shutil.which", return_value="/usr/bin/tpm2_nvincrement"),
        patch("witness_daemon.tpm_cli.subprocess.run", return_value=_FakeCompletedProcess(1)),
        pytest.raises(TpmIncrementRejectedError),
    ):
        _client().increment_counter()


def test_increment_counter_timeout_is_ambiguous_not_rejected():
    with (
        patch("witness_daemon.tpm_cli.shutil.which", return_value="/usr/bin/tpm2_nvincrement"),
        patch(
            "witness_daemon.tpm_cli.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="tpm2_nvincrement", timeout=10),
        ),
        pytest.raises(TpmIncrementAmbiguousError),
    ):
        _client().increment_counter()


def test_increment_counter_os_error_is_ambiguous_not_rejected():
    with (
        patch("witness_daemon.tpm_cli.shutil.which", return_value="/usr/bin/tpm2_nvincrement"),
        patch("witness_daemon.tpm_cli.subprocess.run", side_effect=OSError("boom")),
        pytest.raises(TpmIncrementAmbiguousError),
    ):
        _client().increment_counter()


def test_secret_never_appears_as_a_literal_argv_value():
    """The secret's contents are never known to this module at all -- only
    its file path is ever placed in argv, always `file:`-prefixed."""

    captured_argv: list[str] = []

    def _capture(argv, **kwargs):
        captured_argv.extend(argv)
        if "-o" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes((2).to_bytes(8, "big"))
        return _FakeCompletedProcess(0)

    with (
        patch("witness_daemon.tpm_cli.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"),
        patch("witness_daemon.tpm_cli.subprocess.run", side_effect=_capture),
    ):
        client = _client()
        client.read_counter()
        client.increment_counter()

    assert f"file:{_AUTH_PATH}" in captured_argv
    # The literal path string is the only thing referencing the secret;
    # no argument is a bare, un-prefixed path or arbitrary token that
    # could be mistaken for secret material itself.
    assert all(
        arg == f"file:{_AUTH_PATH}" or str(_AUTH_PATH) not in arg or arg.startswith("file:") for arg in captured_argv
    )


def test_read_and_increment_never_accept_a_caller_supplied_handle():
    """Structural proof: neither public method takes a handle parameter
    at all -- the constructor is the only place `nv_handle` can ever be
    set, closing off any possibility of a per-call override."""

    import inspect

    read_params = inspect.signature(Tpm2ToolsClient.read_counter).parameters
    increment_params = inspect.signature(Tpm2ToolsClient.increment_counter).parameters
    assert set(read_params) == {"self"}
    assert set(increment_params) == {"self"}
