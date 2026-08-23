from __future__ import annotations

import io
import tarfile
import zipfile

import pytest
from verify_distribution import (
    DistributionVerificationError,
    _validate_member_content,
    validate_member_name,
    verify_sdist,
    verify_wheel,
)


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "project/.env",
        "project/.env.local",
        "project/private/key.txt",
        "project/reports-ai/latest.md",
        "project/token.key",
        "project/debug.log",
        "project/.coverage",
        "project/AGENTS.md",
        "project/.ssh/config",
        "project/id_rsa",
        "project/state.sqlite3",
        "project/cache.db",
        "project/config.bak",
        "project/secrets.yaml",
    ],
)
def test_member_policy_rejects_unsafe_or_private_paths(name):
    with pytest.raises(DistributionVerificationError):
        validate_member_name(name)


def test_member_policy_allows_security_regression_test_name():
    validate_member_name("project/tests/test_credential_non_disclosure.py")


@pytest.mark.parametrize("path", [b"/home/operator/project", b"/Users/operator/project"])
def test_member_content_rejects_machine_specific_home_paths(path):
    with pytest.raises(DistributionVerificationError, match="machine-specific home path"):
        _validate_member_content("project/metadata.txt", path)


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


def test_wheel_with_private_key_material_is_rejected(tmp_path):
    wheel = tmp_path / "pfsense_mcp_server-0.2.2-py3-none-any.whl"
    marker = b"-----BEGIN " + b"PRIVATE KEY-----\nsynthetic\n"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("pfsense_mcp/private_material.txt", marker)

    with pytest.raises(DistributionVerificationError, match="private-key material"):
        verify_wheel(wheel)


def test_valid_sdist_is_accepted(tmp_path):
    sdist = tmp_path / "pfsense_mcp_server-0.2.2.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for name in (
            "pfsense_mcp_server-0.2.2/LICENSE",
            "pfsense_mcp_server-0.2.2/pyproject.toml",
            "pfsense_mcp_server-0.2.2/README.md",
            "pfsense_mcp_server-0.2.2/docs/ACCEPTANCE_v0.7.2.md",
            "pfsense_mcp_server-0.2.2/docs/PYPI_RELEASE.md",
            "pfsense_mcp_server-0.2.2/docs/RECOVERY_CONTRACT_SPEC.md",
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


def test_sdist_with_private_key_material_is_rejected(tmp_path):
    sdist = tmp_path / "pfsense_mcp_server-0.2.2.tar.gz"
    marker = b"-----BEGIN " + b"RSA PRIVATE KEY-----\nsynthetic\n"
    with tarfile.open(sdist, "w:gz") as archive:
        info = tarfile.TarInfo("pfsense_mcp_server-0.2.2/material.txt")
        info.size = len(marker)
        archive.addfile(info, io.BytesIO(marker))

    with pytest.raises(DistributionVerificationError, match="private-key material"):
        verify_sdist(sdist)
