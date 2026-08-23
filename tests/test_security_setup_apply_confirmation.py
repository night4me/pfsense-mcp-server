"""Unit tests for security_setup_apply_confirmation.py -- pure,
deterministic, no transport/network/filesystem dependency. Mirrors
tests/test_security_recovery_confirmation.py's structure, adapted for
the plan-bound (rather than incident-bound) binding fields."""

from __future__ import annotations

from pfsense_mcp.security_setup_apply_confirmation import (
    ApplyConfirmationBinding,
    confirmation_token_matches,
    derive_confirmation_token,
)

_KEY = b"k" * 32
_OTHER_KEY = b"j" * 32


def _binding(**overrides: object) -> ApplyConfirmationBinding:
    defaults: dict[str, object] = {
        "plan_digest": "a" * 64,
        "target_origin": "https://pfsense.example",
        "target_identity": "admin",
        "capability_posture": "read_only",
        "anchor_assurance": "none",
    }
    defaults.update(overrides)
    return ApplyConfirmationBinding(**defaults)  # type: ignore[arg-type]


def test_derive_is_deterministic():
    binding = _binding()
    assert derive_confirmation_token(binding, integrity_key=_KEY) == derive_confirmation_token(
        binding, integrity_key=_KEY
    )


def test_matches_the_token_it_derives():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    assert confirmation_token_matches(token, binding, integrity_key=_KEY)


def test_rejects_wrong_key():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    assert not confirmation_token_matches(token, binding, integrity_key=_OTHER_KEY)


def test_rejects_cross_plan_digest_token():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    other = _binding(plan_digest="b" * 64)
    assert not confirmation_token_matches(token, other, integrity_key=_KEY)


def test_rejects_cross_target_origin_token():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    other = _binding(target_origin="https://other.example")
    assert not confirmation_token_matches(token, other, integrity_key=_KEY)


def test_rejects_cross_target_identity_token():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    other = _binding(target_identity="someone-else")
    assert not confirmation_token_matches(token, other, integrity_key=_KEY)


def test_rejects_cross_capability_posture_token():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    other = _binding(capability_posture="write_protected")
    assert not confirmation_token_matches(token, other, integrity_key=_KEY)


def test_rejects_cross_anchor_assurance_token():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    other = _binding(anchor_assurance="hardware_witness")
    assert not confirmation_token_matches(token, other, integrity_key=_KEY)


def test_rejects_none_target_origin_mismatched_with_a_value():
    # A token bound to an unset target_origin (bare `setup apply`
    # without --target-origin) must not match a binding that later
    # supplies one, or vice versa.
    binding = _binding(target_origin=None)
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    other = _binding(target_origin="https://pfsense.example")
    assert not confirmation_token_matches(token, other, integrity_key=_KEY)


def test_rejects_none_candidate():
    binding = _binding()
    assert not confirmation_token_matches(None, binding, integrity_key=_KEY)  # type: ignore[arg-type]


def test_rejects_empty_string_candidate():
    binding = _binding()
    assert not confirmation_token_matches("", binding, integrity_key=_KEY)


def test_rejects_non_string_candidate():
    binding = _binding()
    assert not confirmation_token_matches(1234, binding, integrity_key=_KEY)  # type: ignore[arg-type]


def test_rejects_truncated_token():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    assert not confirmation_token_matches(token[:-1], binding, integrity_key=_KEY)


def test_rejects_token_with_trailing_whitespace():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    assert not confirmation_token_matches(token + "\n", binding, integrity_key=_KEY)


def test_domain_separation_from_recovery_confirmation():
    """A token derived for setup-apply must never be accepted by (or
    collide with) the recovery-confirmation domain, and vice versa --
    proven by checking the two modules use distinct HMAC domain
    prefixes, since both otherwise share the exact same construction
    shape (domain-separated HMAC-SHA256 over canonical JSON)."""

    from pfsense_mcp import security_recovery_confirmation, security_setup_apply_confirmation

    assert security_setup_apply_confirmation._TOKEN_DOMAIN != security_recovery_confirmation._TOKEN_DOMAIN
