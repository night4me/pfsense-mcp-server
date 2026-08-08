from __future__ import annotations

import os

import pytest

from pfsense_mcp.secure_file import open_nofollow, validate_descriptor


class _Boom(Exception):
    pass


def _on_error(message: str) -> Exception:
    return _Boom(message)


def test_open_nofollow_opens_a_regular_file(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"data")
    os.chmod(target, 0o600)

    descriptor = open_nofollow(target, on_error=_on_error)
    try:
        assert os.read(descriptor, 16) == b"data"
    finally:
        os.close(descriptor)


def test_open_nofollow_refuses_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"data")
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(_Boom, match="symbolic link"):
        open_nofollow(link, on_error=_on_error)


def test_open_nofollow_reports_missing_file(tmp_path):
    with pytest.raises(_Boom, match="could not be opened"):
        open_nofollow(tmp_path / "missing", on_error=_on_error)


def test_open_nofollow_unsupported_platform(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.write_bytes(b"data")
    monkeypatch.delattr(os, "O_NOFOLLOW")

    with pytest.raises(_Boom, match="unsupported on this platform"):
        open_nofollow(target, on_error=_on_error)


def test_validate_descriptor_accepts_regular_owner_only_file(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"data")
    os.chmod(target, 0o600)

    descriptor = os.open(target, os.O_RDONLY)
    try:
        validate_descriptor(target, descriptor, max_bytes=1024, on_error=_on_error)
    finally:
        os.close(descriptor)


def test_validate_descriptor_rejects_group_or_other_permissions(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"data")
    os.chmod(target, 0o640)

    descriptor = os.open(target, os.O_RDONLY)
    try:
        with pytest.raises(_Boom, match="group or other"):
            validate_descriptor(target, descriptor, max_bytes=1024, on_error=_on_error)
    finally:
        os.close(descriptor)


def test_validate_descriptor_rejects_oversized_file(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"x" * 32)
    os.chmod(target, 0o600)

    descriptor = os.open(target, os.O_RDONLY)
    try:
        with pytest.raises(_Boom, match="maximum allowed size"):
            validate_descriptor(target, descriptor, max_bytes=16, on_error=_on_error)
    finally:
        os.close(descriptor)


def test_validate_descriptor_rejects_non_regular_file(tmp_path):
    directory = tmp_path / "dir"
    directory.mkdir()

    descriptor = os.open(directory, os.O_RDONLY)
    try:
        with pytest.raises(_Boom, match="regular file"):
            validate_descriptor(directory, descriptor, max_bytes=1024, on_error=_on_error)
    finally:
        os.close(descriptor)
