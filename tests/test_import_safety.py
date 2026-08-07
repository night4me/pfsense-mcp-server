from __future__ import annotations

import os
import subprocess
import sys


def test_package_and_server_modules_import_without_configuration_or_output(tmp_path):
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("PFSENSE_") and name not in {"PYTHONSTARTUP", "PYTHONINSPECT"}
    }

    result = subprocess.run(
        [sys.executable, "-c", "import pfsense_mcp; import pfsense_mcp.server"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert list(tmp_path.iterdir()) == []
