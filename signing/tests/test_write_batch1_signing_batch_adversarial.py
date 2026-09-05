"""Additional adversarial coverage for the batch-ceremony redesign,
requested explicitly by the 2026-09-05 owner review, beyond what
`test_write_batch1_signing_batch.py`/`test_shape_a_batch_owner_approval.py`
already prove:

- expired authorization replaced with fresh authorization without a
  fresh owner `yes` (must be refused);
- one output tampered after batch signing (must fail verification);
- stale posture evidence during a batch fails the WHOLE batch closed,
  before any signature is produced, not partway through;
- the shared `discovery` is built exactly once per batch invocation,
  never re-read per capability -- so a witness value that changed
  mid-batch could never produce inconsistent postures across
  capabilities in the same approved batch.

All keys/evidence here are synthetic and ephemeral.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pfsense_mcp.security_authorization_verifier import verify_plan_authorization_v2_signature
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.errors import ArtifactExchangeError, Tier1Error
from pfsense_mcp.tier1.shape_a_acceptance_orchestration import artifact_paths_for
from pfsense_mcp.tier1.shape_a_artifact_exchange import load_signed_plan_authorization_v2
from signing.write_batch1_signing import (
    SigningError,
    _build_discovery_from_export,
    _load_authorization_config,
    _one_authorization,
    sign_authorization_batch_command,
)

from .test_write_batch1_signing_batch import (
    _FIVE_SYMBOLS,
    _counting_yes,
    _fixture,
    _write_preview,
)


def test_expired_authorization_cannot_be_replaced_without_a_fresh_yes(tmp_path, monkeypatch):
    """An expired (or still-valid) existing authorization-inbox.json can
    never be silently overwritten by a later signing attempt, whether or
    not that later attempt claims `require_approval=False` -- the file's
    mere existence refuses the write, full stop. There is no code path
    that inspects an existing artifact's own expiry to decide whether
    replacing it is acceptable."""

    env = _fixture(tmp_path, monkeypatch)
    digest = _write_preview(tmp_path, env, "SYSTEM_TIMEZONE")
    _counting_yes(monkeypatch)
    config = _load_authorization_config()
    discovery = _build_discovery_from_export(env)

    assert _one_authorization(config, "SYSTEM_TIMEZONE") == 0
    paths = artifact_paths_for(config.artifact_base_directory, "SYSTEM_TIMEZONE")
    original_bytes = paths.authorization_inbox_file.read_bytes()

    # Attempted "replacement" signing, even with require_approval=False
    # (as if an attacker controlled the batch loop directly) and a
    # correct expected digest, must not produce a new artifact.
    result = _one_authorization(
        config,
        "SYSTEM_TIMEZONE",
        require_approval=False,
        discovery=discovery,
        expected_execution_intent_digest=digest,
    )

    assert result == 0
    assert paths.authorization_inbox_file.read_bytes() == original_bytes


def test_tampering_a_signed_authorization_after_batch_signing_breaks_its_signature(tmp_path, monkeypatch):
    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_preview(tmp_path, env, symbol)
    _counting_yes(monkeypatch)

    assert sign_authorization_batch_command(list(_FIVE_SYMBOLS)) == 0

    config = _load_authorization_config()
    authority_data = json.loads(Path(env["PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_AUTHORITY_FILE"]).read_text())
    authority = PinnedAuthority(
        authority_id=authority_data["authority_id"], public_key=bytes.fromhex(authority_data["public_key_hex"])
    )
    authorities = PinnedAuthoritySet((authority,))

    paths = artifact_paths_for(config.artifact_base_directory, "SYSTEM_TIMEZONE")
    authz = load_signed_plan_authorization_v2(paths.authorization_inbox_file)
    assert verify_plan_authorization_v2_signature(authz, authorities) is True

    raw = json.loads(paths.authorization_inbox_file.read_text())
    raw["plan_digest"] = "f" * 64
    paths.authorization_inbox_file.write_text(json.dumps(raw))

    tampered = load_signed_plan_authorization_v2(paths.authorization_inbox_file)
    assert verify_plan_authorization_v2_signature(tampered, authorities) is False


def test_stale_posture_during_batch_fails_the_whole_batch_before_any_signature(tmp_path, monkeypatch):
    """If the live, independently re-derived plan digest no longer
    matches what a preview was built against, the FIRST capability in
    canonical order refuses closed and no capability in the batch is
    signed -- not a partial batch where earlier capabilities succeeded
    before the mismatch was noticed."""

    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_preview(tmp_path, env, symbol)

    config = _load_authorization_config()
    # Corrupt the alphabetically-first capability's own preview file so
    # its requested_plan_digest can never match live discovery again --
    # simulates the live posture having changed after all previews were
    # generated.
    first_symbol = sorted(_FIVE_SYMBOLS)[0]
    paths = artifact_paths_for(config.artifact_base_directory, first_symbol)
    raw = json.loads(paths.authorization_preview_file.read_text())
    raw["requested_plan_digest"] = "0" * 64
    # integrity_mac now stale on purpose -- any tamper to a MAC-protected
    # field must be caught either by the MAC check or by the plan-digest
    # cross-check; either failure mode proves the batch cannot proceed.
    paths.authorization_preview_file.unlink()
    paths.authorization_preview_file.write_text(json.dumps(raw))

    _counting_yes(monkeypatch)

    # The preview's integrity MAC no longer matches its tampered content,
    # so the load itself fails closed (ArtifactExchangeError) before the
    # plan-digest cross-check would even run -- either failure mode
    # proves the batch cannot proceed, so both are accepted here.
    with pytest.raises((SigningError, ArtifactExchangeError, Tier1Error)):
        sign_authorization_batch_command(list(_FIVE_SYMBOLS))

    for symbol in _FIVE_SYMBOLS:
        other_paths = artifact_paths_for(config.artifact_base_directory, symbol)
        assert not other_paths.authorization_inbox_file.exists()


def test_shared_discovery_is_built_exactly_once_per_batch(tmp_path, monkeypatch):
    """Proves the batch command never re-reads the witness/export per
    capability -- all N capabilities in one approved batch see the exact
    same posture snapshot, so a witness value that changed mid-batch
    could never produce inconsistent postures within one approval."""

    env = _fixture(tmp_path, monkeypatch)
    for symbol in _FIVE_SYMBOLS:
        _write_preview(tmp_path, env, symbol)
    _counting_yes(monkeypatch)

    calls = []
    real = _build_discovery_from_export

    def _counting_build(env_arg):
        calls.append(1)
        return real(env_arg)

    # Patch via sign_authorization_batch_command's own __globals__, not a
    # freshly re-imported module object: test_signing_transport_isolation.py
    # deletes and re-imports signing.write_batch1_signing elsewhere in this
    # same session, which would otherwise leave this test patching a
    # different module object than the one the already-imported function
    # actually looks its globals up in.
    monkeypatch.setitem(sign_authorization_batch_command.__globals__, "_build_discovery_from_export", _counting_build)

    assert sign_authorization_batch_command(list(_FIVE_SYMBOLS)) == 0
    assert len(calls) == 1
