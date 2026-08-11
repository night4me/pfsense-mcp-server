import ast
from pathlib import Path

import pytest

from lab.config import LabConfigError, load_lab_config, load_lab_key_material

_MODULE_PATH = Path(__file__).parents[1] / "config.py"


def _base_env(key_file) -> dict[str, str]:
    return {
        "PFSENSE_LAB_API_URL": "https://alias-candidate.lab.invalid",
        "PFSENSE_LAB_IDENTITY": "lab-mcp-test",
        "PFSENSE_LAB_API_KEY_FILE": str(key_file),
        "PFSENSE_LAB_CANDIDATE": "LAB_FIREWALL_ALIAS",
        "PFSENSE_LAB_ATTESTATION_FILE": str(key_file) + ".attestation.json",
    }


def test_valid_lab_hostname_is_accepted(tmp_path):
    config = load_lab_config(_base_env(tmp_path / "key"))
    assert config.base_url == "https://alias-candidate.lab.invalid"
    assert config.candidate == "LAB_FIREWALL_ALIAS"


@pytest.mark.parametrize(
    "base_url",
    [
        "https://198.51.100.7",
        "https://192.0.2.1:8443",
        "https://203.0.113.42",
    ],
)
def test_valid_rfc5737_address_is_accepted(tmp_path, base_url):
    env = _base_env(tmp_path / "key")
    env["PFSENSE_LAB_API_URL"] = base_url
    config = load_lab_config(env)
    assert config.base_url == base_url


@pytest.mark.parametrize(
    "base_url",
    [
        "https://pfsense.example.invalid",
        "https://127.0.0.1",
        "https://production.internal.example.com",
        "http://alias-candidate.lab.invalid",  # not https
        "https://alias-candidate.lab.invalid.evil.com",
        "https://not-lab-invalid.com",
        "https://192.0.2.999",
        "https://192.0.2.1:99999",
    ],
)
def test_non_lab_hosts_are_refused(tmp_path, base_url):
    env = _base_env(tmp_path / "key")
    env["PFSENSE_LAB_API_URL"] = base_url
    with pytest.raises(LabConfigError, match="allow-list"):
        load_lab_config(env)


@pytest.mark.parametrize(
    "missing_var",
    [
        "PFSENSE_LAB_API_URL",
        "PFSENSE_LAB_IDENTITY",
        "PFSENSE_LAB_API_KEY_FILE",
        "PFSENSE_LAB_CANDIDATE",
        "PFSENSE_LAB_ATTESTATION_FILE",
    ],
)
def test_missing_lab_variable_fails_closed(tmp_path, missing_var):
    env = _base_env(tmp_path / "key")
    del env[missing_var]
    with pytest.raises(LabConfigError, match=missing_var):
        load_lab_config(env)


def test_setting_only_production_variables_is_refused(tmp_path):
    """I2: production-shaped env vars alone must never satisfy the lab
    loader -- this is the behavioral half of the isolation proof; the
    static half is test_lab_config_never_references_production_names
    below."""

    env = {
        "PFSENSE_API_URL": "https://pfsense.example.invalid",
        "PFSENSE_IDENTITY": "api-mcp-admin",
        "PFSENSE_API_KEY_FILE": str(tmp_path / "key"),
    }
    with pytest.raises(LabConfigError):
        load_lab_config(env)


@pytest.mark.parametrize("identity", ["", " lab", "lab identity", "lab\nidentity"])
def test_malformed_lab_identity_is_refused(tmp_path, identity):
    env = _base_env(tmp_path / "key")
    env["PFSENSE_LAB_IDENTITY"] = identity
    with pytest.raises(LabConfigError, match=r"identity|IDENTITY"):
        load_lab_config(env)


@pytest.mark.parametrize("candidate", ["", "*", "LAB_*", "operational_alias", " LAB_ALIAS"])
def test_malformed_candidate_is_refused(tmp_path, candidate):
    env = _base_env(tmp_path / "key")
    env["PFSENSE_LAB_CANDIDATE"] = candidate
    with pytest.raises(LabConfigError, match="CANDIDATE"):
        load_lab_config(env)


def test_lab_config_never_references_production_names():
    """AST-based proof, same discipline as tests/tier1/test_isolation.py:
    lab/config.py must never import pfsense_mcp.config, and must never
    contain the literal strings PFSENSE_API_URL/PFSENSE_API_KEY_FILE
    anywhere in its source (I2)."""

    source = _MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(_MODULE_PATH))

    imported_modules = {
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any(
        module == "pfsense_mcp.config" or module.startswith("pfsense_mcp.config.") for module in imported_modules
    )

    forbidden_literals = {"PFSENSE_API_URL", "PFSENSE_API_KEY_FILE", "PFSENSE_IDENTITY"}
    string_literals = {
        node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert string_literals.isdisjoint(forbidden_literals)


def test_load_lab_key_material_reads_first_line(tmp_path):
    key_file = tmp_path / "lab.key"
    key_file.write_text("lab-key-value\nsecond-line-ignored\n")
    key_file.chmod(0o600)

    assert load_lab_key_material(key_file) == "lab-key-value"


def test_load_lab_key_material_rejects_empty_file(tmp_path):
    key_file = tmp_path / "empty.key"
    key_file.write_text("")
    key_file.chmod(0o600)

    with pytest.raises(LabConfigError, match="empty"):
        load_lab_key_material(key_file)


def test_load_lab_key_material_rejects_missing_file(tmp_path):
    with pytest.raises(LabConfigError, match="could not be opened"):
        load_lab_key_material(tmp_path / "does-not-exist.key")
