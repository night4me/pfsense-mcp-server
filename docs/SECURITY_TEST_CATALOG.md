# Security abuse-case test catalog

This catalog maps abuse cases to existing offline controls. It is a review aid,
not an authorization mechanism. Tier 1 cases remain design requirements and
must not be enabled by adding tests alone.

## Current READ and Tier 0 cases

| Abuse case | Expected result | Primary coverage |
|---|---|---|
| Credential field or value reaches a public boundary | Field absent; value absent from schemas, outputs, logs, errors, and fixtures | `test_credential_non_disclosure.py`, `test_security_scan.py`, `test_fixture_safety.py` |
| Symlink or pathname replacement targets another key file | Fail closed, or continue through the already validated original descriptor | `test_config.py` |
| Unsafe key owner, mode, type, size, or content | Startup fails with sanitized `ConfigurationError` | `test_config.py` |
| Capability/profile escalation | Requested tools remain the intersection of profile and exact-name restriction | `test_tool_registry.py`, `test_config.py` |
| Tool-restriction wildcard, empty element, or unknown name | Startup fails closed | `test_config.py`, `test_application_bootstrap.py` |
| ToolAnnotations treated as authorization | Capability and endpoint gates remain authoritative | `test_credential_non_disclosure.py`, `test_tool_registry.py` |
| Endpoint or HTTP-method substitution | Undeclared endpoint or non-GET request is refused | `test_endpoints_verified.py`, `test_rest_api_client.py`, `get_only_check.py` |
| Malformed JSON or response envelope | Typed sanitized error; no upstream body disclosure | `test_rest_api_client.py`, `test_pfsense_client.py` |
| Authentication or transport failure leaks upstream details | Typed sanitized error without identity, body, header, or credential | `test_rest_api_client.py`, `test_tool_audit.py` |
| Log or exception injection includes a registered secret | Secret is redacted; exception messages and argument values are not audited | `test_logging_redaction.py`, `test_tool_audit.py`, `test_logging_permissions.py` |
| Unexpected tool exception bypasses audit | One sanitized failure record, original `Exception` re-raised | `test_tool_audit.py` |
| Production-derived fixture enters approval flow | Proposal and repository scans fail closed | `test_fixture_safety.py`, `test_audit_fixture.py`, `test_security_scan.py` |
| Accidental WRITE import, endpoint, or capability activation | Static/registry gate fails; zero WRITE tools register | `test_tool_registry.py`, `tools_write_check.py`, `write_allow_list_check.py`, `write_capability_check.py` |
| Test collection initiates a live request | Live suite remains explicitly gated and skipped offline | `test_live_*.py`, `validate_junit.py` |

Response-size and compressed-expansion limits are not currently enforced. They
remain a documented transport-hardening question because a safe bound needs
representative upstream size evidence; do not guess a production limit.

## Future Tier 1 cases — not implemented

The Tier 1 acceptance suite must cover forged or replayed Recovery Contracts,
caller-supplied authoritative state, capability/endpoint/method/target
substitution, duplicate or missing natural identity, transient numeric-ID
drift, payload or snapshot digest mismatch, expiry, concurrent execution,
crash at every durable/mutation boundary, ambiguous upstream outcome,
unrelated-change rollback, config-history capture failure, compensation
failure, and manual reconciliation from `OUTCOME_UNKNOWN`.

The authoritative detail and legal state transitions are in
[TIER1_ROADMAP.md](TIER1_ROADMAP.md). None of these future cases permits a
WRITE implementation or activation without separate owner approval.

## Rejected or out-of-scope attacker capabilities

- A user with shell access as the server account can read process-owned files
  and control the stdio process; this is outside the local launcher trust
  boundary, not a remotely preventable MCP condition.
- A fully compromised pfSense appliance can return hostile data. Models,
  bounded list parameters, sanitized errors, and TLS reduce exposure but cannot
  make the upstream authoritative source trustworthy.
- Physical host compromise, kernel compromise, and malicious replacement of
  the running interpreter are outside the application threat model.
- HTTP-origin, bearer-token, and multi-tenant caller attacks do not apply while
  stdio remains the only MCP transport. They require a new threat model before
  any network transport is designed.
