"""Repository-wide security policy constants shared by safety tooling."""

from __future__ import annotations

PROHIBITED_CREDENTIAL_FIELDS: frozenset[str] = frozenset({"ipsecpsk", "password", "key"})


def find_prohibited_credential_fields(value: object, *, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for field, child in value.items():
            child_path = f"{path}.{field}"
            if field.lower() in PROHIBITED_CREDENTIAL_FIELDS:
                findings.append(child_path)
            findings.extend(find_prohibited_credential_fields(child, path=child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(find_prohibited_credential_fields(child, path=f"{path}[{index}]"))
    return findings
