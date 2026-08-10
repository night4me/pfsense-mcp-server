from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from witness_daemon import main as main_module
from witness_daemon.errors import WitnessConfigurationError

_REPO_ROOT = Path(__file__).parents[2]


def test_main_reports_configuration_error_and_exits_nonzero(monkeypatch, capsys):
    def _raise():
        raise WitnessConfigurationError("missing stuff")

    monkeypatch.setattr(main_module, "load_witness_daemon_config", _raise)

    exit_code = main_module.main()
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "configuration error" in captured.err


def test_main_handles_keyboard_interrupt_cleanly_and_closes_the_socket(monkeypatch, capsys):
    class _FakeConfig:
        bind_host = "127.0.0.1"
        bind_port = 0
        nv_handle = "0x01500000"

    class _FakeServer:
        def __init__(self) -> None:
            self.closed = False

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            self.closed = True

    fake_server = _FakeServer()
    monkeypatch.setattr(main_module, "load_witness_daemon_config", lambda: _FakeConfig())
    monkeypatch.setattr(main_module, "build_server", lambda config: fake_server)

    exit_code = main_module.main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert fake_server.closed is True
    assert "shutting down" in captured.out.lower()


def test_main_closes_the_socket_even_on_a_normal_return(monkeypatch):
    """serve_forever() only returns via shutdown()/an exception in real
    use, but the finally-block must close the socket regardless of how
    it returns -- not only on the KeyboardInterrupt path."""

    class _FakeConfig:
        bind_host = "127.0.0.1"
        bind_port = 0
        nv_handle = "0x01500000"

    class _FakeServer:
        def __init__(self) -> None:
            self.closed = False

        def serve_forever(self) -> None:
            return None

        def server_close(self) -> None:
            self.closed = True

    fake_server = _FakeServer()
    monkeypatch.setattr(main_module, "load_witness_daemon_config", lambda: _FakeConfig())
    monkeypatch.setattr(main_module, "build_server", lambda config: fake_server)

    exit_code = main_module.main()

    assert exit_code == 0
    assert fake_server.closed is True


def test_dunder_main_makes_python_dash_m_witness_daemon_work():
    """End-to-end regression test for the real defect found during Phase
    2 real-hardware verification (2026-08-10): `python -m witness_daemon`
    previously failed outright with 'No module named
    witness_daemon.__main__' because no __main__.py existed. No
    WITNESS_* variables are set, so this must fail closed on
    configuration -- proving the module actually runs (reaches main()'s
    own error path), not merely that the process starts."""

    env = {key: value for key, value in os.environ.items() if not key.startswith("WITNESS_")}
    result = subprocess.run(  # nosec B603 B607
        [sys.executable, "-m", "witness_daemon"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )

    assert result.returncode == 1
    assert "configuration error" in result.stderr
