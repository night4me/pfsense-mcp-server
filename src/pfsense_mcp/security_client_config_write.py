"""`pfsense-mcp-security setup write-client-config` -- the optional,
separately-gated MCP client configuration *write* path (design report
§14's second half; original session owner decision 8: "print-only
remains default... any future optional merge-write must be distinct,
explicitly confirmed, merge-only, never whole-file replacement").

Composes the exact same env values `security_cli.py`'s own
`_mcp_client_env_vars()`/`_mcp_client_config_snippet()`/
`_mcp_client_config_toml()` (Slice 6) already compute -- this module
never derives a different snippet, it only writes the same one to
disk, safely.

**Two supported clients, exactly the ones this repository's own
`examples/*.md` document a real config path/format for** -- never an
invented path:

- `codex` (Codex CLI, shared with the ChatGPT desktop app per
  `examples/chatgpt.md`'s own text): TOML, default path
  `~/.codex/config.toml` (`examples/codex-cli.md`'s own documented
  path). An explicit `--config-path` overrides it.
- `claude-desktop`: JSON. `examples/claude-desktop.md` never pins down
  one exact OS-specific path, so this client has **no default** --
  `--config-path` is always required. Inventing one would violate this
  run's own explicit "do not invent a config-file location... without
  source evidence" instruction.

**Never a whole-file replacement.** For both formats, only the
`pfsense` server entry is added or updated; every other key (other MCP
servers, unrelated top-level settings, for TOML: unrelated tables and
their comments) is preserved byte-for-byte (TOML) or structurally
(JSON, via parse-modify-reserialize, which cannot preserve comments --
JSON has none -- or original whitespace, but does preserve every other
key and its relative position). A **malformed existing file is always
refused, never overwritten** -- this module has no half-way "best
effort" repair mode.

**Confirmation, distinct from every pfSense-side confirmation.** Reuses
the exact same plan-bound-HMAC-token *mechanism*
`security_setup_apply_confirmation.py` established (domain-separated
HMAC-SHA256 over canonical JSON, constant-time comparison), with its
own distinct domain constant, keyed by the same local
`PFSENSE_SETUP_CONFIRM_KEY_FILE` operators already provision for
`setup apply` -- reusing the established local-secret convention, not
inventing a second one. The binding covers `client_type`,
`config_path`, `plan_digest`, and digests of both the *existing* file
content (or a fixed sentinel if absent) and the *exact proposed* new
content -- so a token issued for one client/path/plan/existing-state
combination is refused for any other, and a file that changed on disk
between inspection and apply is caught the same way a stale pfSense
plan is (the binding no longer matches, so the token no longer
matches -- no separate "stale" outcome needed, mirroring
`setup apply`'s own established precedent).

**Backup, atomic write, and validated rollback.** An existing target
file is first copied to `<path>.bak` via exclusive creation (refuses
if a backup already exists -- never silently overwrites a leftover
from an interrupted prior attempt). The new content is written to a
temporary file in the same directory, fsynced, and renamed over the
target (atomic on POSIX). The result is then read back and re-parsed;
if it does not exactly match the intended content, the backup is
restored atomically and the outcome is reported distinctly -- this
module never leaves a half-written or unverified file in place.

**Never a network call.** This module never imports `factory`,
`config.load_config`, `pfsense_client`, or any transport -- it has no
way to contact pfSense even by accident.

**Never a second general MCP WRITE capability.** This module writes
only a local application-configuration file on the *operator's own
machine* (their Claude Desktop/Codex/ChatGPT configuration) -- it never
touches pfSense state, the MCP server's own runtime, or the MCP tool
registry.
"""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import hmac
import json
import os
import stat
import tomllib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .secure_file import open_nofollow

_TOKEN_DOMAIN = b"pfsense-mcp-setup-client-config-write-confirm-v1\x00"
_MAX_EXISTING_CONFIG_BYTES = 4 * 1024 * 1024
_MAX_CONFIRM_KEY_BYTES = 4096
_ABSENT_CONTENT_DIGEST = "absent"

_CODEX_DEFAULT_PATH = "~/.codex/config.toml"


class ClientType(str, Enum):
    CODEX = "codex"
    CLAUDE_DESKTOP = "claude-desktop"


class WriteOutcome(str, Enum):
    """Exhaustive, CLI-mappable result category -- mirrors every other
    `setup`-family orchestration module's own discipline: no outcome is
    ever collapsed into a generic "failed"."""

    INSPECT_CURRENT = "inspect_current"
    WRITE_COMPLETED = "write_completed"
    CONFIRM_TOKEN_INVALID = "confirm_token_invalid"  # nosec B105 -- an outcome enum value, not a credential
    BLOCKED_CONFIGURATION_ERROR = "blocked_configuration_error"
    BLOCKED_MALFORMED_EXISTING_CONFIG = "blocked_malformed_existing_config"
    BLOCKED_PATH_UNSAFE = "blocked_path_unsafe"
    WRITE_VALIDATION_FAILED_ROLLED_BACK = "write_validation_failed_rolled_back"


class ClientConfigWriteError(Exception):
    """Raised only internally by this module's own local file
    handling; never escapes `run_client_config_write_from_environment()`."""


@dataclass(frozen=True)
class ClientConfigWriteBinding:
    client_type: str
    config_path: str
    plan_digest: str
    existing_content_digest: str
    proposed_content_digest: str


@dataclass(frozen=True)
class WriteResult:
    outcome: WriteOutcome
    detail: str
    client_type: str | None = None
    config_path: str | None = None
    confirmation_token: str | None = None
    diff: str | None = None
    backup_path: str | None = None


def _content_digest(content: bytes | None) -> str:
    if content is None:
        return _ABSENT_CONTENT_DIGEST
    return hashlib.sha256(content).hexdigest()


def _canonical_payload(binding: ClientConfigWriteBinding) -> bytes:
    payload = {
        "client_type": binding.client_type,
        "config_path": binding.config_path,
        "plan_digest": binding.plan_digest,
        "existing_content_digest": binding.existing_content_digest,
        "proposed_content_digest": binding.proposed_content_digest,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def derive_confirmation_token(binding: ClientConfigWriteBinding, *, integrity_key: bytes) -> str:
    return hmac.new(integrity_key, _TOKEN_DOMAIN + _canonical_payload(binding), hashlib.sha256).hexdigest()


def confirmation_token_matches(
    candidate: str | None, binding: ClientConfigWriteBinding, *, integrity_key: bytes
) -> bool:
    if not isinstance(candidate, str) or not candidate:
        return False
    expected = derive_confirmation_token(binding, integrity_key=integrity_key)
    # `hmac.compare_digest()` rejects `str` arguments containing
    # non-ASCII characters outright (`TypeError`, not a clean
    # mismatch) -- `candidate` is untrusted operator input and must
    # never crash the comparison. Bytes-like arguments have no such
    # restriction and remain constant-time for equal-length inputs;
    # `surrogateescape` round-trips argv values that contain invalid
    # UTF-8 byte sequences instead of raising a fresh encoding error.
    return hmac.compare_digest(candidate.encode("utf-8", errors="surrogateescape"), expected.encode("ascii"))


def resolve_config_path(client: ClientType, override: str | None) -> Path:
    """Never invents a path this repository's own docs do not name.
    `claude-desktop` has no documented default -- `override` is always
    required for it. `codex`'s documented default is used only when
    `override` is not supplied."""

    if override is not None:
        path = Path(override).expanduser()
        if not path.is_absolute():
            raise ClientConfigWriteError(f"--config-path must be an absolute path: {override}")
        return path
    if client is ClientType.CODEX:
        return Path(_CODEX_DEFAULT_PATH).expanduser()
    raise ClientConfigWriteError(
        "claude-desktop has no documented default config path in this project's own examples -- "
        "pass --config-path explicitly."
    )


def _read_existing(path: Path) -> bytes | None:
    """Local disk read only, symlink-refusing, bounded-size. Returns
    `None` if the path does not exist at all -- that is a legitimate,
    common case (first-time config creation), not an error."""

    if path.is_symlink():
        raise ClientConfigWriteError(f"Config path must not be a symbolic link: {path}")
    if not path.exists():
        return None
    descriptor = open_nofollow(path, on_error=ClientConfigWriteError)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ClientConfigWriteError(f"Config path is not a regular file: {path}")
        if metadata.st_uid != os.geteuid():
            raise ClientConfigWriteError(f"Config file must be owned by the current user: {path}")
        if metadata.st_size > _MAX_EXISTING_CONFIG_BYTES:
            raise ClientConfigWriteError(f"Config file exceeds the maximum supported size: {path}")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError:
        raise ClientConfigWriteError(f"Config file could not be read securely: {path}") from None
    finally:
        os.close(descriptor)


def _merge_json(existing: bytes | None, *, command: str, env_vars: dict[str, str]) -> bytes:
    if existing is None:
        parsed: dict[str, object] = {}
    else:
        try:
            parsed = json.loads(existing)
        except (ValueError, UnicodeDecodeError):
            raise ClientConfigWriteError(
                "Existing Claude Desktop config is not valid JSON -- refusing to touch it"
            ) from None
        if not isinstance(parsed, dict):
            raise ClientConfigWriteError(
                "Existing Claude Desktop config's top level is not a JSON object -- refusing to touch it"
            )
    servers = parsed.get("mcpServers")
    if servers is None:
        servers = {}
        parsed["mcpServers"] = servers
    elif not isinstance(servers, dict):
        raise ClientConfigWriteError(
            "Existing Claude Desktop config's own 'mcpServers' is not a JSON object -- refusing to touch it"
        )
    servers["pfsense"] = {"command": command, "env": env_vars}
    return (json.dumps(parsed, indent=2) + "\n").encode()


def _toml_escape_string(value: str) -> str:
    escapes = {"\\": "\\\\", '"': '\\"', "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}
    result = []
    for character in value:
        if character in escapes:
            result.append(escapes[character])
        elif ord(character) < 0x20 or ord(character) == 0x7F:
            result.append(f"\\u{ord(character):04x}")
        else:
            result.append(character)
    return "".join(result)


def _toml_stanza_lines(*, command: str, env_vars: dict[str, str]) -> list[str]:
    lines = [
        "[mcp_servers.pfsense]",
        f'command = "{_toml_escape_string(command)}"',
        "required = true",
        "",
        "[mcp_servers.pfsense.env]",
    ]
    lines.extend(f'{key} = "{_toml_escape_string(value)}"' for key, value in env_vars.items())
    return lines


def _find_table_span(lines: list[str], header: str) -> tuple[int, int] | None:
    """Returns `(start, end)` (end exclusive) of the table body
    starting at a line exactly equal to `header`, ending at the next
    line that starts a new table (`[`) or at EOF. Returns `None` if
    `header` is not present. Text-based, not a general TOML writer --
    correct specifically for locating a table this module itself fully
    owns and always writes in this exact single-line-header shape."""

    for index, line in enumerate(lines):
        if line.strip() == header:
            end = index + 1
            while end < len(lines) and not lines[end].lstrip().startswith("["):
                end += 1
            return index, end
    return None


def _merge_toml(existing: bytes | None, *, command: str, env_vars: dict[str, str]) -> bytes:
    stanza = _toml_stanza_lines(command=command, env_vars=env_vars)
    if existing is None:
        return ("\n".join(stanza) + "\n").encode()

    try:
        text = existing.decode("utf-8")
    except UnicodeDecodeError:
        raise ClientConfigWriteError(
            "Existing Codex/ChatGPT config is not valid UTF-8 -- refusing to touch it"
        ) from None

    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ClientConfigWriteError(
            f"Existing Codex/ChatGPT config is not valid TOML -- refusing to touch it: {exc}"
        ) from None

    lines = text.split("\n")
    server_span = _find_table_span(lines, "[mcp_servers.pfsense]")
    env_span = _find_table_span(lines, "[mcp_servers.pfsense.env]")

    if server_span is None and env_span is None:
        # Nothing of ours exists yet -- append, preserving a trailing
        # blank-line separator only if the file is non-empty and does
        # not already end with one.
        prefix = text if text.endswith("\n") else text + "\n"
        if prefix.strip() and not prefix.endswith("\n\n"):
            prefix += "\n"
        return (prefix + "\n".join(stanza) + "\n").encode()

    # Remove both existing spans (env span first if it comes after the
    # server span, to keep earlier indices valid), then insert the new
    # canonical stanza at the position of whichever span came first.
    spans = [span for span in (server_span, env_span) if span is not None]
    spans.sort(key=lambda span: span[0])
    insert_at = spans[0][0]
    for start, end in sorted(spans, key=lambda span: span[0], reverse=True):
        del lines[start:end]

    tail = lines[insert_at:]
    if tail and tail[0].strip():
        # Something else (another table, a comment) follows immediately
        # where our stanza used to end -- restore a blank-line separator
        # so the result reads the same as any hand-edited TOML file
        # would, rather than jamming two tables together.
        tail = ["", *tail]
    result_lines = lines[:insert_at] + stanza + tail
    result_text = "\n".join(result_lines)
    if not result_text.endswith("\n"):
        result_text += "\n"
    return result_text.encode()


def _compute_proposed_content(
    client: ClientType, existing: bytes | None, *, command: str, env_vars: dict[str, str]
) -> bytes:
    if client is ClientType.CLAUDE_DESKTOP:
        return _merge_json(existing, command=command, env_vars=env_vars)
    return _merge_toml(existing, command=command, env_vars=env_vars)


def _load_confirm_key(env: dict[str, str] | None) -> bytes:
    source = env if env is not None else os.environ
    raw_path = source.get("PFSENSE_SETUP_CONFIRM_KEY_FILE")
    if not raw_path or not raw_path.strip():
        raise ClientConfigWriteError("Missing required environment variable: PFSENSE_SETUP_CONFIRM_KEY_FILE")
    path = Path(raw_path).expanduser()
    descriptor = open_nofollow(path, on_error=ClientConfigWriteError)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ClientConfigWriteError(f"Setup-apply confirmation key is not a regular file: {path}")
        if metadata.st_size > _MAX_CONFIRM_KEY_BYTES:
            raise ClientConfigWriteError(f"Setup-apply confirmation key exceeds the maximum supported size: {path}")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
        value = b"".join(chunks)
    except OSError:
        raise ClientConfigWriteError(f"Setup-apply confirmation key could not be read securely: {path}") from None
    finally:
        os.close(descriptor)
    if not value.strip():
        raise ClientConfigWriteError(f"Setup-apply confirmation key is empty: {path}")
    return value.strip()


def _write_atomic_with_backup(path: Path, content: bytes) -> str | None:
    """Backs up an existing file (exclusive create of `<path>.bak`,
    refusing if one already exists) then writes `content` to a
    temporary file in the same directory and renames it over `path`
    (atomic on POSIX). Returns the backup path as a string, or `None`
    if there was nothing to back up (first-time creation)."""

    backup_path: str | None = None
    if path.exists():
        backup = path.with_name(path.name + ".bak")
        backup_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            backup_descriptor = os.open(backup, backup_flags, 0o600)
        except OSError as exc:
            raise ClientConfigWriteError(
                f"Could not create backup at {backup} (a backup from a prior interrupted attempt may already "
                "exist -- move or remove it by hand before retrying)"
            ) from exc
        try:
            existing_bytes = path.read_bytes()
            os.write(backup_descriptor, existing_bytes)
            os.fsync(backup_descriptor)
        finally:
            os.close(backup_descriptor)
        backup_path = str(backup)

    temp_path = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temp_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        temp_descriptor = os.open(temp_path, temp_flags, 0o600)
    except OSError as exc:
        raise ClientConfigWriteError(f"Could not create temporary file for atomic write: {temp_path}") from exc
    try:
        offset = 0
        while offset < len(content):
            written = os.write(temp_descriptor, content[offset:])
            if written <= 0:
                raise ClientConfigWriteError(f"Could not write temporary file: {temp_path}")
            offset += written
        os.fsync(temp_descriptor)
    finally:
        os.close(temp_descriptor)
    os.replace(temp_path, path)
    return backup_path


def _restore_backup(path: Path, backup_path: str | None) -> None:
    if backup_path is None:
        with contextlib.suppress(OSError):
            path.unlink()
        return
    os.replace(backup_path, path)


def run_client_config_write_from_environment(
    env: dict[str, str] | None,
    *,
    client: str,
    config_path_override: str | None,
    command: str,
    env_vars: dict[str, str],
    plan_digest: str,
    confirm_token: str | None,
) -> WriteResult:
    """Pure orchestration over already-reviewed primitives. Order of
    operations is deliberate and fail-closed: resolve and safety-check
    the path, read and validate any existing content, compute the
    exact proposed new content, derive the binding from what is
    genuinely on disk right now -- all *before* the confirmation token
    is even loaded or considered, so a caller who supplies a token for
    stale/different disk state is refused by the binding mismatch
    itself, not by a separate staleness check."""

    try:
        client_type = ClientType(client)
    except ValueError as exc:
        return WriteResult(WriteOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc))

    try:
        path = resolve_config_path(client_type, config_path_override)
    except ClientConfigWriteError as exc:
        return WriteResult(WriteOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc))

    try:
        existing = _read_existing(path)
    except ClientConfigWriteError as exc:
        outcome = (
            WriteOutcome.BLOCKED_PATH_UNSAFE
            if "symbolic link" in str(exc) or "regular file" in str(exc) or "owned by" in str(exc)
            else WriteOutcome.BLOCKED_CONFIGURATION_ERROR
        )
        return WriteResult(outcome, str(exc), client_type=client_type.value, config_path=str(path))

    try:
        proposed = _compute_proposed_content(client_type, existing, command=command, env_vars=env_vars)
    except ClientConfigWriteError as exc:
        return WriteResult(
            WriteOutcome.BLOCKED_MALFORMED_EXISTING_CONFIG,
            str(exc),
            client_type=client_type.value,
            config_path=str(path),
        )

    binding = ClientConfigWriteBinding(
        client_type=client_type.value,
        config_path=str(path),
        plan_digest=plan_digest,
        existing_content_digest=_content_digest(existing),
        proposed_content_digest=_content_digest(proposed),
    )

    try:
        integrity_key = _load_confirm_key(env)
    except ClientConfigWriteError as exc:
        return WriteResult(
            WriteOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc), client_type=client_type.value, config_path=str(path)
        )

    expected_token = derive_confirmation_token(binding, integrity_key=integrity_key)

    if confirm_token is None:
        diff = "".join(
            difflib.unified_diff(
                (existing.decode("utf-8", errors="replace") if existing is not None else "").splitlines(keepends=True),
                proposed.decode("utf-8", errors="replace").splitlines(keepends=True),
                fromfile=f"{path} (current)",
                tofile=f"{path} (proposed)",
            )
        )
        return WriteResult(
            WriteOutcome.INSPECT_CURRENT,
            "Proposed change is ready. Re-run with --confirm <TOKEN> (shown below) to write it.",
            client_type=client_type.value,
            config_path=str(path),
            confirmation_token=expected_token,
            diff=diff,
        )

    if not confirmation_token_matches(confirm_token, binding, integrity_key=integrity_key):
        return WriteResult(
            WriteOutcome.CONFIRM_TOKEN_INVALID,
            "The supplied --confirm token does not match this exact client/path/plan/current-file-state. "
            "Refused before any file was touched. If the file changed since inspection, re-inspect first.",
            client_type=client_type.value,
            config_path=str(path),
        )

    try:
        backup_path = _write_atomic_with_backup(path, proposed)
    except ClientConfigWriteError as exc:
        return WriteResult(
            WriteOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc), client_type=client_type.value, config_path=str(path)
        )

    try:
        written = path.read_bytes()
    except OSError:
        written = b""
    if written != proposed:
        _restore_backup(path, backup_path)
        return WriteResult(
            WriteOutcome.WRITE_VALIDATION_FAILED_ROLLED_BACK,
            "The written file did not read back as intended -- restored the original (or removed the new "
            "file, if none existed before) and made no lasting change.",
            client_type=client_type.value,
            config_path=str(path),
            backup_path=backup_path,
        )

    return WriteResult(
        WriteOutcome.WRITE_COMPLETED,
        f"Wrote the pfsense entry to {path}." + (f" Original backed up at {backup_path}." if backup_path else ""),
        client_type=client_type.value,
        config_path=str(path),
        backup_path=backup_path,
    )
