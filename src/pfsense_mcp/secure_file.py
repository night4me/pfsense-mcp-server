"""Shared descriptor-bound secure file loading.

Single implementation of O_NOFOLLOW-open + fstat()-validated regular,
owner-only file access, factored out so it has exactly one definition
instead of being reimplemented per caller. Used by `pfsense_mcp.config`
for the pfSense API key and by `pfsense_mcp.tier1.key_lifecycle` for
Tier 1 key material. Each caller supplies its own error type via
`on_error` so messages stay domain-appropriate without duplicating the
underlying descriptor logic.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from errno import ELOOP
from pathlib import Path


def open_nofollow(path: Path, *, on_error: Callable[[str], Exception]) -> int:
    """Open `path` read-only, refusing to follow a symlink at the final
    path component. Raises `on_error(message)` on any failure, including
    on platforms without `os.O_NOFOLLOW`."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise on_error("Secure file loading is unsupported on this platform")

    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        if exc.errno == ELOOP:
            raise on_error(f"File must not be a symbolic link: {path}") from None
        raise on_error(f"File could not be opened: {path}") from None


def validate_descriptor(
    path: Path,
    descriptor: int,
    *,
    max_bytes: int,
    on_error: Callable[[str], Exception],
) -> None:
    """Validate an already-open descriptor: regular file, owned by the
    current effective user, no group/other permission bits, bounded
    size. Raises `on_error(message)` on any violation."""

    try:
        metadata = os.fstat(descriptor)
    except OSError:
        raise on_error(f"File metadata could not be read: {path}") from None

    if not stat.S_ISREG(metadata.st_mode):
        raise on_error(f"File is not a regular file: {path}")
    if metadata.st_uid != os.geteuid():
        raise on_error(f"File must be owned by the current user: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise on_error(f"File must not grant permissions to group or other users: {path}")
    if metadata.st_size > max_bytes:
        raise on_error(f"File exceeds the maximum allowed size: {path}")
