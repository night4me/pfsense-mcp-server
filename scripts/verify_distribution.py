#!/usr/bin/env python3
"""Fail closed when distribution archives contain unsafe or incomplete members."""

from __future__ import annotations

import argparse
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


class DistributionVerificationError(ValueError):
    """A built distribution violates the release artifact policy."""


_FORBIDDEN_COMPONENTS = {
    ".claude",
    ".env",
    ".fixture_proposals",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".validate",
    "__pycache__",
    "private",
    "reports",
}
_FORBIDDEN_SUFFIXES = {".key", ".p12", ".pfx", ".log", ".pyc"}
_APPROVED_SECURITY_TEST = "test_credential_non_disclosure.py"


def validate_member_name(raw_name: str) -> PurePosixPath:
    """Validate one archive member name without extracting it."""
    path = PurePosixPath(raw_name)
    if not raw_name or path.is_absolute() or ".." in path.parts:
        raise DistributionVerificationError(f"unsafe archive member path: {raw_name!r}")
    lowered_parts = tuple(part.lower() for part in path.parts)
    if any(part in _FORBIDDEN_COMPONENTS for part in lowered_parts):
        raise DistributionVerificationError(f"private or generated path in distribution: {raw_name!r}")
    filename = lowered_parts[-1]
    if PurePosixPath(filename).suffix in _FORBIDDEN_SUFFIXES:
        raise DistributionVerificationError(f"prohibited file type in distribution: {raw_name!r}")
    if filename != _APPROVED_SECURITY_TEST and ("secret" in filename or "credential" in filename):
        raise DistributionVerificationError(f"credential-like filename in distribution: {raw_name!r}")
    return path


def _require_suffixes(names: set[str], suffixes: tuple[str, ...], artifact: Path) -> None:
    for suffix in suffixes:
        if not any(name.endswith(suffix) for name in names):
            raise DistributionVerificationError(f"{artifact.name} is missing required member ending in {suffix!r}")


def verify_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names: set[str] = set()
        entry_points: bytes | None = None
        for info in archive.infolist():
            member = validate_member_name(info.filename)
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                raise DistributionVerificationError(f"symbolic link in wheel: {info.filename!r}")
            normalized = str(member)
            names.add(normalized)
            if normalized.endswith(".dist-info/entry_points.txt"):
                entry_points = archive.read(info)
        _require_suffixes(
            names,
            ("pfsense_mcp/__init__.py", "pfsense_mcp/server.py", ".dist-info/METADATA", ".dist-info/RECORD"),
            path,
        )
        expected = b"pfsense-mcp-server = pfsense_mcp.server:main"
        if entry_points is None or expected not in entry_points:
            raise DistributionVerificationError(f"{path.name} does not declare the expected console entry point")


def verify_sdist(path: Path) -> None:
    with tarfile.open(path, mode="r:gz") as archive:
        names: set[str] = set()
        for info in archive.getmembers():
            validate_member_name(info.name)
            if not (info.isfile() or info.isdir()):
                raise DistributionVerificationError(f"unsupported member type in sdist: {info.name!r}")
            names.add(info.name)
        _require_suffixes(names, ("/pyproject.toml", "/README.md", "/src/pfsense_mcp/server.py"), path)


def verify_distribution(directory: Path) -> tuple[Path, Path]:
    wheels = sorted(directory.glob("pfsense_mcp_server-*.whl"))
    sdists = sorted(directory.glob("pfsense_mcp_server-*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise DistributionVerificationError(
            f"expected exactly one wheel and one sdist in {directory} (found {len(wheels)} wheel, {len(sdists)} sdist)"
        )
    verify_wheel(wheels[0])
    verify_sdist(sdists[0])
    return wheels[0], sdists[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="directory containing one wheel and one sdist")
    args = parser.parse_args(argv)
    try:
        wheel, sdist = verify_distribution(args.directory)
    except (DistributionVerificationError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"verify_distribution: ERROR {exc}\n")
    print(f"verify_distribution: OK ({wheel.name}, {sdist.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
