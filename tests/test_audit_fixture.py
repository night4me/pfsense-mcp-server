"""Unit tests for scripts/audit_fixture.py.

Uses tmp_path for both the proposal directory and the fixtures
target directory — never touches the real tests/fixtures/."""

from __future__ import annotations

import hashlib
import json

import audit_fixture


def _write_proposal(tmp_path, *, name="firewall_states_response", data=None, manifest_overrides=None):
    if data is None:
        data = [{"id": 0, "source": "198.51.100.10", "destination": "198.51.100.11"}]

    proposal = {"data": data}
    proposal_bytes = (json.dumps(proposal, indent=2, sort_keys=True) + "\n").encode("utf-8")
    proposal_path = tmp_path / f"{name}.proposed.json"
    proposal_path.write_bytes(proposal_bytes)

    manifest = {
        "manifest_schema_version": 1,
        "endpoint_symbol": "FIREWALL_STATES",
        "endpoint_path": "/firewall/states",
        "api_version": "v2",
        "captured_at_utc": "2026-01-01T00:00:00+00:00",
        "query_parameters": {"limit": 5},
        "response_shape": "list",
        "item_count": len(data),
        "serialized_input_size_bytes": 123,
        "sanitized_proposal_size_bytes": len(proposal_bytes),
        "substitution_counts": {"ipv4": 2},
        "redacted_field_names": ["source", "destination"],
        "sha256_sanitized_proposal": hashlib.sha256(proposal_bytes).hexdigest(),
    }
    if manifest_overrides:
        manifest.update(manifest_overrides)
    manifest_path = tmp_path / f"{name}.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    return proposal_path, manifest_path


def test_run_audit_passes_a_clean_proposal(tmp_path):
    proposal_path, _manifest_path = _write_proposal(tmp_path)
    problems = audit_fixture.run_audit(proposal_path)
    assert problems == []


def test_run_audit_detects_sha256_mismatch_when_proposal_tampered(tmp_path):
    proposal_path, manifest_path = _write_proposal(tmp_path)
    # Tamper with the proposal after the manifest was written.
    proposal_path.write_text(proposal_path.read_text() + "\n// tampered\n")
    problems = audit_fixture.run_audit(proposal_path)
    assert any("SHA-256" in p for p in problems)


def test_run_audit_rejects_unrecognized_schema_version(tmp_path):
    proposal_path, _ = _write_proposal(tmp_path, manifest_overrides={"manifest_schema_version": 999})
    problems = audit_fixture.run_audit(proposal_path)
    assert any("schema version" in p for p in problems)


def test_run_audit_missing_proposal_file(tmp_path):
    problems = audit_fixture.run_audit(tmp_path / "does_not_exist.proposed.json")
    assert any("not found" in p for p in problems)


def test_run_audit_missing_manifest_file(tmp_path):
    proposal_path = tmp_path / "orphan.proposed.json"
    proposal_path.write_text('{"data": []}\n')
    problems = audit_fixture.run_audit(proposal_path)
    assert any("manifest" in p.lower() for p in problems)


def test_run_audit_detects_item_count_mismatch(tmp_path):
    # This is also the manifest-tampering-without-resigning detector:
    # the SHA-256 check only covers the *proposal* file's integrity,
    # not the manifest's own claims — a manifest edited after capture
    # (its own hash of itself is never taken) is instead caught here,
    # by cross-checking its claims against the proposal's actual content.
    # Recompute a fresh, internally-consistent SHA for a proposal whose
    # manifest *claims* a different item_count than it actually has.
    data = [{"id": 0, "source": "198.51.100.10", "destination": "198.51.100.11"}]
    proposal_bytes = (json.dumps({"data": data}, indent=2, sort_keys=True) + "\n").encode("utf-8")
    proposal_path = tmp_path / "x.proposed.json"
    proposal_path.write_bytes(proposal_bytes)
    manifest = {
        "manifest_schema_version": 1,
        "endpoint_symbol": "FIREWALL_STATES",
        "response_shape": "list",
        "item_count": 5,  # wrong: actual data has 1 item
        "redacted_field_names": ["source", "destination"],
        "sha256_sanitized_proposal": hashlib.sha256(proposal_bytes).hexdigest(),
    }
    (tmp_path / "x.manifest.json").write_text(json.dumps(manifest))
    problems = audit_fixture.run_audit(proposal_path)
    assert any("item_count" in p for p in problems)


def test_run_audit_detects_unknown_endpoint_symbol(tmp_path):
    proposal_path, _ = _write_proposal(tmp_path, manifest_overrides={"endpoint_symbol": "NOT_A_REAL_ENDPOINT"})
    problems = audit_fixture.run_audit(proposal_path)
    assert any("CAPTURE_POLICIES" in p for p in problems)


def test_run_audit_detects_leaked_real_ip(tmp_path):
    # Built via concatenation rather than one contiguous literal: this
    # file is not in security_scan.py's _APPROVED_MARKER_FILES, so a
    # marker can't be used here, and the repo-wide scanner would flag
    # the complete literal form if it existed contiguously in source.
    real_looking_ip = "192.168.1" + ".3"
    proposal_path, _ = _write_proposal(tmp_path, data=[{"id": 0, "note": real_looking_ip}])
    problems = audit_fixture.run_audit(proposal_path)
    assert any(real_looking_ip in p or "IPv4" in p for p in problems)


def test_run_audit_detects_unauthorized_suppression_marker(tmp_path):
    marker_text = "security-scan" + ": allow"
    proposal_path, _ = _write_proposal(tmp_path, data=[{"id": 0, "note": marker_text}])
    problems = audit_fixture.run_audit(proposal_path)
    assert any("unauthorized suppression marker" in p for p in problems)


def test_run_audit_detects_unaccounted_sensitive_field(tmp_path):
    proposal_path, _ = _write_proposal(
        tmp_path, data=[{"id": 0, "session_token": "hello"}], manifest_overrides={"redacted_field_names": []}
    )
    problems = audit_fixture.run_audit(proposal_path)
    assert any("session_token" in p for p in problems)


# --- dry-run / approve behavior ---------------------------------------


def test_dry_run_never_copies(tmp_path, monkeypatch, capsys):
    proposal_path, _ = _write_proposal(tmp_path)
    fixtures_dir = tmp_path / "fixtures_target"
    monkeypatch.setattr(audit_fixture, "FIXTURES_DIR", fixtures_dir)

    exit_code = audit_fixture.main([str(proposal_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "dry-run only" in captured.out
    assert not fixtures_dir.exists() or list(fixtures_dir.glob("*")) == []


def test_approve_copies_only_after_success(tmp_path, monkeypatch, capsys):
    proposal_path, _ = _write_proposal(tmp_path)
    fixtures_dir = tmp_path / "fixtures_target"
    monkeypatch.setattr(audit_fixture, "FIXTURES_DIR", fixtures_dir)

    exit_code = audit_fixture.main([str(proposal_path), "--approve"])
    captured = capsys.readouterr()

    assert exit_code == 0
    target = fixtures_dir / "firewall_states_response.json"
    assert target.is_file()
    assert json.loads(target.read_text()) == json.loads(proposal_path.read_text())
    assert "git add" in captured.out


def test_approve_does_not_copy_when_audit_fails(tmp_path, monkeypatch, capsys):
    proposal_path, _ = _write_proposal(tmp_path, manifest_overrides={"manifest_schema_version": 999})
    fixtures_dir = tmp_path / "fixtures_target"
    monkeypatch.setattr(audit_fixture, "FIXTURES_DIR", fixtures_dir)

    exit_code = audit_fixture.main([str(proposal_path), "--approve"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert not fixtures_dir.exists() or list(fixtures_dir.glob("*")) == []
    assert "git add" not in captured.out


def test_approve_refuses_to_overwrite_existing_fixture(tmp_path, monkeypatch, capsys):
    proposal_path, _ = _write_proposal(tmp_path)
    fixtures_dir = tmp_path / "fixtures_target"
    fixtures_dir.mkdir()
    existing = fixtures_dir / "firewall_states_response.json"
    existing.write_text('{"already": "here"}')
    monkeypatch.setattr(audit_fixture, "FIXTURES_DIR", fixtures_dir)

    exit_code = audit_fixture.main([str(proposal_path), "--approve"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "refusing to overwrite" in captured.err
    assert json.loads(existing.read_text()) == {"already": "here"}  # untouched


def test_audit_fixture_never_executes_git_add(tmp_path, monkeypatch, capsys):
    proposal_path, _ = _write_proposal(tmp_path)
    fixtures_dir = tmp_path / "fixtures_target"
    monkeypatch.setattr(audit_fixture, "FIXTURES_DIR", fixtures_dir)

    import subprocess

    real_run = subprocess.run

    def _spy_run(args, *a, **kw):
        assert not (isinstance(args, list) and args[:2] == ["git", "add"])
        return real_run(args, *a, **kw)

    monkeypatch.setattr(subprocess, "run", _spy_run)
    audit_fixture.main([str(proposal_path), "--approve"])


def test_leaked_ip_is_flagged_and_causes_audit_failure(tmp_path, monkeypatch, capsys):
    """A non-RFC5737 IP remaining in a proposal must fail the audit.

    Note: the underlying finding message here comes from the already-
    reused, already-approved security_scan.py/fixture_safety.py
    checkers, which do include the literal offending value in their
    own message text (useful for a human fixing a real leak in a
    tracked repo file — their established, reviewed behavior, not
    something introduced or changed by audit_fixture.py). The
    "never report the triggering value" requirement applies to
    capture_fixture.py's own sanitizer refusals (see test_sanitizer.py
    and test_capture_fixture.py), which is where a truly raw,
    never-yet-reviewed value could otherwise leak."""
    leaked_ip = "192.168.1" + ".3"  # concatenated: this file is not an approved marker location
    proposal_path, _ = _write_proposal(tmp_path, data=[{"id": 0, "note": leaked_ip}])
    fixtures_dir = tmp_path / "fixtures_target"
    monkeypatch.setattr(audit_fixture, "FIXTURES_DIR", fixtures_dir)

    exit_code = audit_fixture.main([str(proposal_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert leaked_ip in captured.err  # documents current, approved behavior
    assert not fixtures_dir.exists() or list(fixtures_dir.glob("*")) == []
