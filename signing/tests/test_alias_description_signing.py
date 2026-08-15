"""Adversarial and functional tests for `signing.alias_description_signing`
-- the off-host, operator-only `sign-confirmation` command.

Run explicitly: `pytest signing/` (excluded from the default suite by
`pyproject.toml`'s `addopts`, matching `lab/`/`witness_daemon/`'s own
established precedent for separate, off-host deployables).
"""

from __future__ import annotations

import inspect
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from pfsense_mcp.tier1.artifact_exchange import PendingConfirmationRequest
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM, Ed25519ConfirmationVerifier
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority
from pfsense_mcp.tier1.errors import ArtifactExchangeError
from signing.alias_description_signing import (
    SigningError,
    main,
    render_confirmation_review,
    sign_confirmation_command,
    sign_pending_confirmation,
)

NOW = datetime.now(timezone.utc).replace(microsecond=0)
_INTEGRITY_KEY_HEX = "ab" * 32


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def _pending(**changes: object) -> PendingConfirmationRequest:
    values: dict[str, object] = {
        "operation": "set_firewall_alias_description_v1",
        "contract_id": "contract-001",
        "operation_id": "operation-001",
        "alias_name": "LAB_ALIAS_TEST",
        "previous_description": "before",
        "requested_description": "after",
        "target_identity_digest": "a" * 64,
        "target_fingerprint": "b" * 64,
        "intent_digest": "c" * 64,
        "expires_at": NOW + timedelta(minutes=5),
        "expected_authority_id": "confirm-owner-1",
        "expected_algorithm": ACCEPTED_ALGORITHM,
    }
    values.update(changes)
    return PendingConfirmationRequest(**values)  # type: ignore[arg-type]


def _authority(authority_id: str = "confirm-owner-1") -> tuple[Ed25519PrivateKey, PinnedAuthority]:
    private, public = _keypair()
    return private, PinnedAuthority(authority_id=authority_id, public_key=public)


def _secure_write(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    os.chmod(path, 0o600)


def _authority_file(path: Path, authority: PinnedAuthority) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _secure_write(
        path,
        json.dumps({"authority_id": authority.authority_id, "public_key_hex": authority.public_key.hex()}).encode(),
    )


def _private_key_file(path: Path, private_key: Ed25519PrivateKey) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = private_key.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
    )
    _secure_write(path, raw)


def _integrity_key_file(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _secure_write(
        path, json.dumps({"key_id": "signing-integrity", "epoch": 0, "material_hex": _INTEGRITY_KEY_HEX}).encode()
    )


def _integrity_key_bytes() -> bytes:
    return bytes.fromhex(_INTEGRITY_KEY_HEX)


def _pending_bytes(pending: PendingConfirmationRequest) -> bytes:
    from pfsense_mcp.tier1.artifact_exchange import pending_confirmation_request_to_bytes

    return pending_confirmation_request_to_bytes(pending, integrity_key=_integrity_key_bytes())


# --------------------------------------------------------------------------
# sign_pending_confirmation() -- pure signing logic
# --------------------------------------------------------------------------


def test_sign_pending_confirmation_valid_produces_verifiable_evidence():
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)

    evidence = sign_pending_confirmation(pending=pending, private_key=private, authority=authority, now=NOW)

    assert isinstance(evidence, ConfirmationEvidence)
    assert evidence.contract_id == pending.contract_id
    assert evidence.operation_id == pending.operation_id
    assert evidence.target_identity_digest == pending.target_identity_digest
    assert evidence.target_fingerprint == pending.target_fingerprint
    assert evidence.intent_digest == pending.intent_digest
    assert evidence.expires_at == pending.expires_at
    assert evidence.authority_id == authority.authority_id
    assert Ed25519ConfirmationVerifier((authority,)).verify(evidence)


def test_sign_pending_confirmation_wrong_authority_refused():
    private, authority = _authority()
    pending = _pending(expected_authority_id="a-different-authority")

    with pytest.raises(SigningError, match="own pinned authority"):
        sign_pending_confirmation(pending=pending, private_key=private, authority=authority, now=NOW)


def test_sign_pending_confirmation_unsupported_algorithm_refused():
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id, expected_algorithm="ed25519-v2")

    with pytest.raises(SigningError, match="unsupported algorithm"):
        sign_pending_confirmation(pending=pending, private_key=private, authority=authority, now=NOW)


def test_sign_pending_confirmation_expired_refused():
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id, expires_at=NOW - timedelta(seconds=1))

    with pytest.raises(SigningError, match="expired"):
        sign_pending_confirmation(pending=pending, private_key=private, authority=authority, now=NOW)


def test_sign_pending_confirmation_naive_now_refused():
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)

    with pytest.raises(SigningError, match="UTC"):
        sign_pending_confirmation(pending=pending, private_key=private, authority=authority, now=datetime.now())


def test_sign_pending_confirmation_wrong_key_fails_self_verification():
    _matching_private, authority = _authority()
    wrong_private, _wrong_public = _keypair()
    pending = _pending(expected_authority_id=authority.authority_id)

    with pytest.raises(SigningError, match="self-verification"):
        sign_pending_confirmation(pending=pending, private_key=wrong_private, authority=authority, now=NOW)


def test_sign_pending_confirmation_cannot_substitute_contract_or_digest_fields():
    """Structural: the function accepts only `pending`/`private_key`/
    `authority`/`now` -- there is no parameter shaped like contract_id,
    operation_id, or any digest a caller could substitute."""

    signature = inspect.signature(sign_pending_confirmation)
    assert set(signature.parameters) == {"pending", "private_key", "authority", "now"}


def test_sign_pending_confirmation_operation_mismatch_is_defended_in_depth():
    """PendingConfirmationRequest.__post_init__ already refuses a
    non-accepted operation at construction time (tested in
    tests/tier1/test_artifact_exchange.py) -- this proves
    sign_pending_confirmation() also carries its own redundant check,
    never relying solely on the upstream type's own validation."""

    source = inspect.getsource(sign_pending_confirmation)
    assert "pending.operation != SEMANTIC_UNIT" in source


def test_render_confirmation_review_contains_required_semantic_fields():
    pending = _pending()
    review = render_confirmation_review(pending)
    for expected in (
        pending.operation,
        pending.contract_id,
        pending.operation_id,
        pending.alias_name,
        pending.previous_description,
        pending.requested_description,
        pending.target_identity_digest,
        pending.target_fingerprint,
        pending.intent_digest,
        pending.expected_authority_id,
    ):
        assert expected in review


def test_render_confirmation_review_never_dumps_raw_object():
    """No secrets/keys can appear in the review since PendingConfirmationRequest
    itself never carries any -- structural guard against a future field
    addition being rendered via repr()/vars() instead of explicit fields."""

    review = render_confirmation_review(_pending())
    assert "PendingConfirmationRequest(" not in review


# --------------------------------------------------------------------------
# sign_confirmation_command() / main() -- full CLI workflow
# --------------------------------------------------------------------------


def _set_env(
    monkeypatch,
    tmp_path: Path,
    *,
    pending: PendingConfirmationRequest,
    authority: PinnedAuthority,
    private_key: Ed25519PrivateKey,
) -> Path:
    pending_file = tmp_path / "pending.json"
    integrity_key_file = tmp_path / "integrity.json"
    authority_file = tmp_path / "authority.json"
    private_key_file = tmp_path / "private.key"
    output_file = tmp_path / "signed.json"

    _secure_write(pending_file, _pending_bytes(pending))
    _integrity_key_file(integrity_key_file)
    _authority_file(authority_file, authority)
    _private_key_file(private_key_file, private_key)

    monkeypatch.setenv("PFSENSE_SIGNING_CONFIRMATION_PENDING_FILE", str(pending_file))
    monkeypatch.setenv("PFSENSE_SIGNING_CONFIRMATION_PENDING_INTEGRITY_KEY_FILE", str(integrity_key_file))
    monkeypatch.setenv("PFSENSE_SIGNING_CONFIRMATION_AUTHORITY_FILE", str(authority_file))
    monkeypatch.setenv("PFSENSE_SIGNING_CONFIRMATION_PRIVATE_KEY_FILE", str(private_key_file))
    monkeypatch.setenv("PFSENSE_SIGNING_CONFIRMATION_OUTPUT_FILE", str(output_file))
    return output_file


def test_sign_confirmation_command_end_to_end_with_approval(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    exit_code = sign_confirmation_command()

    assert exit_code == 0
    assert output_file.exists()
    from pfsense_mcp.tier1.artifact_exchange import load_signed_confirmation_evidence

    evidence = load_signed_confirmation_evidence(output_file)
    assert Ed25519ConfirmationVerifier((authority,)).verify(evidence)
    assert evidence.contract_id == pending.contract_id


def test_sign_confirmation_command_refused_without_explicit_approval(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")

    exit_code = sign_confirmation_command()

    assert exit_code == 1
    assert not output_file.exists()


def test_sign_confirmation_command_refused_on_empty_input(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    monkeypatch.setattr("builtins.input", lambda _prompt: "")

    exit_code = sign_confirmation_command()

    assert exit_code == 1
    assert not output_file.exists()


def test_sign_confirmation_command_malformed_pending_refused(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    _secure_write(Path(os.environ["PFSENSE_SIGNING_CONFIRMATION_PENDING_FILE"]), b"not json")
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("must never prompt for a malformed artifact"))

    with pytest.raises(ArtifactExchangeError):
        sign_confirmation_command()
    assert not output_file.exists()


def test_sign_confirmation_command_tampered_pending_refused(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    pending_path = Path(os.environ["PFSENSE_SIGNING_CONFIRMATION_PENDING_FILE"])
    raw = json.loads(pending_path.read_text())
    raw["requested_description"] = "an attacker-edited description"
    pending_path.unlink()
    _secure_write(pending_path, json.dumps(raw).encode())
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("must never prompt for a tampered artifact"))

    with pytest.raises(ArtifactExchangeError, match="integrity"):
        sign_confirmation_command()
    assert not output_file.exists()


def test_sign_confirmation_command_unsupported_schema_refused(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    pending_path = Path(os.environ["PFSENSE_SIGNING_CONFIRMATION_PENDING_FILE"])
    raw = json.loads(pending_path.read_text())
    raw["schema_version"] = 999
    pending_path.unlink()
    _secure_write(pending_path, json.dumps(raw).encode())
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("must never prompt for an unsupported schema"))

    with pytest.raises(ArtifactExchangeError, match="malformed"):
        sign_confirmation_command()
    assert not output_file.exists()


def test_sign_confirmation_command_existing_output_not_overwritten(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    _secure_write(output_file, b'{"unrelated": "leftover-artifact"}')
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    with pytest.raises(ArtifactExchangeError, match="could not be created"):
        sign_confirmation_command()
    assert output_file.read_bytes() == b'{"unrelated": "leftover-artifact"}'


def test_sign_confirmation_command_altered_signed_artifact_fails_verification(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    sign_confirmation_command()

    from pfsense_mcp.tier1.artifact_exchange import load_signed_confirmation_evidence

    raw = json.loads(output_file.read_text())
    raw["contract_id"] = "a-different-contract-id"
    output_file.unlink()
    _secure_write(output_file, json.dumps(raw).encode())

    tampered = load_signed_confirmation_evidence(output_file)
    assert not Ed25519ConfirmationVerifier((authority,)).verify(tampered)


def test_main_dispatches_to_sign_confirmation(tmp_path, monkeypatch):
    private, authority = _authority()
    pending = _pending(expected_authority_id=authority.authority_id)
    output_file = _set_env(monkeypatch, tmp_path, pending=pending, authority=authority, private_key=private)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    exit_code = main(["sign-confirmation"])

    assert exit_code == 0
    assert output_file.exists()


def test_main_rejects_unknown_command():
    with pytest.raises(SystemExit):
        main(["sign-authorization"])


def test_main_catches_and_reports_signing_errors_cleanly(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("PFSENSE_SIGNING_CONFIRMATION_PENDING_FILE", raising=False)

    exit_code = main(["sign-confirmation"])

    assert exit_code == 1
    assert "Refused:" in capsys.readouterr().out


# --------------------------------------------------------------------------
# Isolation
# --------------------------------------------------------------------------


def _code_only_source(module) -> str:
    """`inspect.getsource()` minus the module's own leading docstring --
    isolates actual code (imports, calls, string literals used as CLI
    flags) from explanatory prose that legitimately *names* things this
    module must never do, so a structural check does not false-positive
    on its own documentation."""

    import ast

    tree = ast.parse(inspect.getsource(module))
    body = (
        tree.body[1:]
        if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant)
        else tree.body
    )
    return "\n".join(ast.unparse(node) for node in body)


def test_no_automatic_signing_flag_exists():
    """Structural: no argparse flag anywhere in this module's actual code
    can bypass the interactive input() approval gate."""

    import signing.alias_description_signing as module

    code = _code_only_source(module)
    for forbidden in ("--yes", "--force", "--auto", "--no-confirm", "--non-interactive"):
        assert forbidden not in code


def test_module_never_imports_pfsense_network_transport():
    import ast

    import signing.alias_description_signing as module

    tree = ast.parse(inspect.getsource(module))
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported_names.add(node.module or "")
            imported_names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported_names.update(alias.name for alias in node.names)
    forbidden = {
        "httpx",
        "WriteApiClient",
        "PfSenseClient",
        "rest_api_client",
        "build_pfsense_client",
        "build_write_client",
    }
    assert imported_names.isdisjoint(forbidden)


def test_module_never_imports_or_references_production_runtime():
    import ast

    import signing.alias_description_signing as module

    tree = ast.parse(inspect.getsource(module))
    imported_modules = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any("production_runtime" in name for name in imported_modules)


def test_module_loads_no_private_signing_key_material_it_does_not_own():
    """The only private-key-shaped symbol this module ever references is
    its own Ed25519PrivateKey usage for signing -- never a symmetric
    production encryption/consumption key beyond the one integrity key
    it needs to verify the pending artifact's MAC."""

    import signing.alias_description_signing as module

    source = inspect.getsource(module)
    assert "KeyPurpose.ENCRYPTION" not in source
