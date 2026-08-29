"""`pfsense-mcp-security setup init-confirm-key` -- v1.0.0 clean-room
finding (2026-08-29): guided, secure local provisioning of the one
persistent local secret both `setup apply` and `setup
write-client-config` require (`PFSENSE_SETUP_CONFIRM_KEY_FILE`) but
that the wizard's own completion screen never explained how to obtain.
This was a known, explicitly-deferred gap -- see
`reports-ai/SETUP_WIZARD_SLICE2_2026-08-23.md`'s "Autonomous Decision
2": key generation was rejected *for that slice* only because it was
"a distinct, separately reviewable concern," never because automatic
generation was itself judged unsafe. This module is that separate
review.

**What this key is, and is not.** It is a purely local HMAC integrity
key. `security_setup_apply_confirmation.py`/`security_client_config_write.py`
use it to bind a `setup apply`/`setup write-client-config` confirmation
token to the exact plan/target/posture (and, for write-client-config,
file state) an operator has already reviewed via a prior inspection
call -- its only job is to make it hard for a stale, copy-pasted, or
cross-target/cross-posture command to reach even the first live
network call or local file write (see
`security_setup_apply_confirmation.py`'s own docstring: "not a
substitute for authentication/authorization"). It is **never** sent to
pfSense, is not a pfSense credential, and never appears in any
generated MCP client configuration. It **is**, however, treated with
the exact same secure-file rigor as a real credential (owner-only, no
symlink, exclusive creation) -- see below for why that still matters.

**Why secrecy of this key still matters.** The plan digest it signs is
not itself secret -- it is printed by `setup`, and every value it is
computed from (target origin/identity/posture/anchor) is either
operator-supplied or otherwise discoverable. If this key were
predictable, world-readable, or a fixed default, anyone with local
read access (or knowledge of a hardcoded value) could compute a
"confirmation" token for a plan they were never shown by this tool's
own inspection step, defeating the entire point of the two-call
inspect-then-confirm ceremony. This is why `create_confirm_key()`
below applies the same discipline `config.store_api_key()` already
established for the pfSense API key: exclusive (`O_CREAT|O_EXCL`)
creation, `O_NOFOLLOW`, explicit `0600`, and never overwriting
existing material.

**One persistent key, reused across both commands.** It must be the
same value across the inspection call that issues a token and the
later call that verifies it, and `security_client_config_write.py`'s
own docstring documents deliberately reusing this same file rather
than inventing a second local secret. `create_confirm_key()` is
therefore idempotent by design: an existing key is always left
untouched and reported as `ALREADY_EXISTS`, never rotated or
overwritten -- rotating it would invalidate every `--confirm` token an
operator has not yet redeemed.

**Never auto-invoked.** Neither `setup apply` nor `setup
write-client-config` ever calls this module -- both remain pure
orchestration over an operator-provisioned key exactly as before this
change. This module exists only so an operator has a safe, guided way
to provision that key themselves, once, without inventing an arbitrary
path or hand-generating weaker material.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

#: 256-bit key, hex-encoded (64 ASCII characters): a full-length
#: HMAC-SHA256 key, plain text so it is safe to display or copy without
#: risk of terminal corruption from raw binary content -- unlike the
#: shorter `secrets.token_hex(16)` correlation IDs
#: `security_bootstrap_orchestration.py`/`security_recovery_orchestration.py`
#: generate for an unrelated, non-cryptographic purpose, this is
#: full-length because it is genuinely used as a MAC key.
_CONFIRM_KEY_BYTES = 32
_MAX_CONFIRM_KEY_BYTES = 4096  # matches security_setup_apply.py's own read-side bound

#: Reuses this project's own established default local-state directory
#: convention (`logging_setup.DEFAULT_LOG_DIR`) rather than inventing a
#: new one -- so an operator following only this tool's own guidance
#: never has to invent an arbitrary absolute path.
DEFAULT_CONFIRM_KEY_FILE = Path.home() / ".local" / "state" / "pfsense-mcp-server" / "setup-confirm.key"


class InitConfirmKeyOutcome(str, Enum):
    CREATED = "created"
    ALREADY_EXISTS = "already_exists"
    BLOCKED_UNSAFE_PATH = "blocked_unsafe_path"
    FAILED = "failed"


@dataclass(frozen=True)
class InitConfirmKeyResult:
    outcome: InitConfirmKeyOutcome
    path: Path
    detail: str


class _ConfirmKeyCreationError(Exception):
    """Raised only internally; never escapes `create_confirm_key()`."""


def create_confirm_key(path: Path | None = None) -> InitConfirmKeyResult:
    """Idempotent and safe to call unconditionally: an existing key at
    `path` (or `DEFAULT_CONFIRM_KEY_FILE`) is always left untouched and
    reported as `ALREADY_EXISTS` -- this function never overwrites,
    rotates, reads, or returns the value of an existing key. Only ever
    creates a *fresh*, cryptographically random key via
    `secrets.token_hex()`; there is no fallback to any fixed or default
    key value, and the generated value is never included in the
    returned `InitConfirmKeyResult` or logged anywhere."""

    target = (path if path is not None else DEFAULT_CONFIRM_KEY_FILE).expanduser()

    if target.is_symlink():
        return InitConfirmKeyResult(
            InitConfirmKeyOutcome.BLOCKED_UNSAFE_PATH,
            target,
            f"Refusing to create a confirmation key at a symbolic link: {target}",
        )
    if target.exists():
        return InitConfirmKeyResult(
            InitConfirmKeyOutcome.ALREADY_EXISTS,
            target,
            f"A confirmation key already exists at {target} -- left untouched.",
        )

    try:
        _create_parent_directory(target.parent)
        _create_key_file(target)
    except _ConfirmKeyCreationError as exc:
        return InitConfirmKeyResult(InitConfirmKeyOutcome.FAILED, target, str(exc))

    return InitConfirmKeyResult(InitConfirmKeyOutcome.CREATED, target, f"Created a new confirmation key at {target}")


def _create_parent_directory(parent: Path) -> None:
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # `Path.mkdir(mode=...)` is subject to umask, so a restrictive
        # secrets directory is not guaranteed by the mode argument alone
        # -- set it explicitly afterward, mirroring `store_api_key()`'s
        # own defensive `os.fchmod()` after `os.open(..., 0o600)`.
        os.chmod(parent, 0o700)
    except OSError:
        raise _ConfirmKeyCreationError(f"Could not create the parent directory: {parent}") from None


def _create_key_file(target: Path) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise _ConfirmKeyCreationError("Secure key-file creation is unsupported on this platform")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | nofollow | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    value = (secrets.token_hex(_CONFIRM_KEY_BYTES) + "\n").encode("ascii")

    parent_descriptor: int | None = None
    descriptor: int | None = None
    created = False
    created_identity: tuple[int, int] | None = None
    complete = False
    try:
        try:
            parent_descriptor = os.open(target.parent, directory_flags)
            descriptor = os.open(target.name, flags, 0o600, dir_fd=parent_descriptor)
            created = True
        except OSError:
            raise _ConfirmKeyCreationError(f"Key file could not be created exclusively: {target}") from None

        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise _ConfirmKeyCreationError(f"Key file creation produced an unsafe artifact: {target}")
        created_identity = (metadata.st_dev, metadata.st_ino)

        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                raise _ConfirmKeyCreationError(f"Key file could not be written: {target}")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.fsync(parent_descriptor)
        complete = True
    except _ConfirmKeyCreationError:
        raise
    except OSError:
        raise _ConfirmKeyCreationError(f"Key file could not be stored safely: {target}") from None
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if created and not complete and created_identity is not None and parent_descriptor is not None:
            # Never unlink a path that another process substituted after
            # creation -- same discipline as `config.store_api_key()`.
            with contextlib.suppress(OSError):
                current = os.stat(target.name, dir_fd=parent_descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == created_identity:
                    os.unlink(target.name, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
        if parent_descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(parent_descriptor)
