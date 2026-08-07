from __future__ import annotations

import io
import tarfile
import zipfile

import pytest
from verify_distribution import (
    DistributionVerificationError,
    validate_member_name,
    verify_sdist,
    verify_wheel,
)


@pytest.mark.parametrize(
    "name",
    ["../escape", "/absolute", "project/.env", "project/private/key.txt", "project/token.key", "project/debug.log"],
)
def test_member_policy_rejects_unsafe_or_private_paths(name):
    with pytest.raises(DistributionVerificationError):
        validate_member_name(name)


def test_member_policy_allows_security_regression_test_name():
    validate_member_name("project/tests/test_credential_non_disclosure.py")


def test_valid_wheel_is_accepted(tmp_path):
    wheel = tmp_path / "pfsense_mcp_server-0.2.2-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("pfsense_mcp/__init__.py", "")
        archive.writestr("pfsense_mcp/py.typed", "")
        archive.writestr("pfsense_mcp/server.py", "")
        archive.writestr("pfsense_mcp_server-0.2.2.dist-info/METADATA", "")
        archive.writestr("pfsense_mcp_server-0.2.2.dist-info/RECORD", "")
        archive.writestr(
            "pfsense_mcp_server-0.2.2.dist-info/entry_points.txt",
            "[console_scripts]\npfsense-mcp-server = pfsense_mcp.server:main\n",
        )
    verify_wheel(wheel)


def test_wheel_without_entry_point_is_rejected(tmp_path):
    wheel = tmp_path / "pfsense_mcp_server-0.2.2-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("pfsense_mcp/__init__.py", "")
        archive.writestr("pfsense_mcp/py.typed", "")
        archive.writestr("pfsense_mcp/server.py", "")
        archive.writestr("pfsense_mcp_server-0.2.2.dist-info/METADATA", "")
        archive.writestr("pfsense_mcp_server-0.2.2.dist-info/RECORD", "")
    with pytest.raises(DistributionVerificationError, match="entry point"):
        verify_wheel(wheel)


def test_valid_sdist_is_accepted(tmp_path):
    sdist = tmp_path / "pfsense_mcp_server-0.2.2.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for name in (
            "pfsense_mcp_server-0.2.2/LICENSE",
            "pfsense_mcp_server-0.2.2/pyproject.toml",
            "pfsense_mcp_server-0.2.2/README.md",
            "pfsense_mcp_server-0.2.2/docs/PYPI_RELEASE.md",
            "pfsense_mcp_server-0.2.2/src/pfsense_mcp/server.py",
        ):
            payload = b"synthetic"
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    verify_sdist(sdist)


def test_sdist_symlink_is_rejected(tmp_path):
    sdist = tmp_path / "pfsense_mcp_server-0.2.2.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        info = tarfile.TarInfo("pfsense_mcp_server-0.2.2/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "target"
        archive.addfile(info)
    with pytest.raises(DistributionVerificationError, match="member type"):
        verify_sdist(sdist)
