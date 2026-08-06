# Public MCP API review

Date: 2026-08-06

This review evaluates the current 41-tool MCP surface for naming,
descriptions, parameter design, defaults, and discoverability. It does not
change the API. Recommendations explicitly target a future major release unless
they can be delivered as documentation-only improvements.

## Executive assessment

The API is coherent and intentionally narrow: every public operation uses the
`pfsense_get_` prefix, maps to an active READ capability, and returns a strongly
typed model. Registration is explicit rather than reflective. The flat tool
namespace is manageable at 41 tools, but naming inherited from upstream
pfSense concepts and the absence of machine-readable categories will become
more noticeable as the project grows.

No urgent API defect or security-driven breaking change was identified. The
existing surface should remain stable throughout the `0.x` READ-hardening
line.

## Inventory and consistency

- **Tools:** 41 READ, 0 WRITE.
- **Verb convention:** all names start with `pfsense_get_`.
- **Collection nouns:** most collection responses use plural names, including
  `interfaces`, `gateways`, `users`, and `firewall_rules`.
- **Singleton nouns:** settings, status, version, mode, and size tools generally
  use singular names.
- **Bounded collections:** collection tools consistently expose `limit` with a
  default of 100 and a documented bounded range.
- **Sensitive metadata:** `include_identifying_metadata` defaults to `false`
  wherever supported. `pfsense_get_auth_keys` deliberately has no disclosure
  argument because its optional upstream metadata is not safe to expose.

The canonical per-tool parameter, return, and security reference is
[API.md](API.md).

## Naming review

### Strengths

- The namespace makes provenance and read intent obvious.
- Names closely follow pfSense REST resources, which helps operators map a tool
  to appliance concepts and upstream documentation.
- Related families use stable prefixes such as `firewall_`, `system_`,
  `dns_resolver_`, and `ntp_`.

### Future-major recommendations

1. Consider using `list` for collections and reserving `get` for singletons.
   This would improve intent at a glance, but renaming every collection tool is
   breaking and does not justify churn today.
2. Review the upstream-derived `system_hasync` spelling. A future alias such as
   `system_ha_sync` would be easier to discover, but adding or renaming a tool
   changes the public surface and requires an explicit compatibility policy.
3. Decide whether `service_status` should remain singular when it returns a
   collection. Consistency favours `service_statuses` or `services`, but the
   current name is already established.
4. Establish a glossary for compound names such as FreeRADIUS, REST API, CARP,
   and ACME so future tool names do not vary in tokenization.

## Description review

Descriptions consistently state the resource and that the operation is
read-only. Sensitive-metadata parameters identify the additional field class,
and credential material is never promised or implied.

Opportunities for a future schema revision:

- use a consistent opening verb: `Get` for singleton resources and `List` for
  collections;
- state whether ordering is upstream-defined when `limit` is present;
- describe empty-result semantics uniformly;
- identify the required capability in structured tool metadata, not only in
  architecture documentation;
- make the standardized typed-error contract discoverable to MCP clients.

Descriptions should remain concise. Copying the full security model into 41
tool descriptions would reduce discoverability rather than improve it.

## Parameter review

The public parameter vocabulary is small and predictable:

- `limit` is bounded and defaults to 100;
- `include_identifying_metadata` is optional and defaults to `false`;
- resource selectors such as interface or table names are required where a
  collection cannot be queried safely without one.

Current ordering is sensible: disclosure choice first, then pagination or
resource-specific selectors according to the tool's established signature.
Changing positional order would be needlessly breaking.

For a future major release:

1. Rename `include_identifying_metadata` to `include_sensitive_metadata` if the
   project wants terminology to match the audit field
   `sensitive_metadata_requested`. The existing name is accurate enough and
   changing it now would break clients.
2. Prefer keyword-only optional arguments if the MCP framework preserves their
   schemas cleanly. This prevents accidental positional misuse in direct Python
   calls, but must first be tested against MCP schema generation.
3. Define one reusable constrained type for all public `limit` parameters if it
   can preserve today's exact JSON Schema and error behaviour.
4. Avoid adding generic filters until each can be bounded and represented with
   precise `Literal` or enum values.

## Return-value review

Strong Pydantic models provide a meaningful schema for each response and ignore
unexpected upstream fields. Singleton-response handling is standardized, and
malformed upstream shapes become sanitized typed errors.

Future-major considerations:

- give repeated collection envelopes explicit public names if generated model
  names are difficult for client UIs to present;
- document ordering and truncation in a shared envelope if pagination metadata
  is ever added;
- consider a documented, machine-readable error envelope only if MCP clients
  can use it without exposing upstream exception details.

Do not weaken `extra="ignore"` at the untrusted upstream boundary without a
field-level disclosure review. Strictly rejecting every new upstream property
would reduce compatibility, while serializing it would risk disclosure.

## Discoverability

The flat namespace is searchable and still usable, but users must understand
pfSense terminology. Documentation now provides a complete API reference and
client examples. Future discoverability improvements should prefer metadata
over more tools:

- capability/category tags exposed through a framework-supported mechanism;
- short usage examples attached to families rather than duplicated on every
  tool;
- a generated tool index grouped by system, network, firewall, service,
  identity, and diagnostics domains;
- explicit indicators for singleton versus collection and optional sensitive
  metadata.

## Compatibility policy recommendation

Treat tool names, parameter names/order/defaults, and public response schemas as
an external API. During `0.2.x` and `0.3`, make additive documentation and
security-preserving implementation changes only. Collect naming improvements
for a single future major-version migration with aliases or a documented
transition window where the MCP framework permits them.

## Manual review before a future major release

- Enumerate schemas using each supported MCP client, because presentation and
  generated-model naming differ by client.
- Compare names with the then-current pfSense REST API vocabulary.
- Test any aliases for duplicate-tool confusion and audit attribution.
- Publish a machine-readable compatibility diff and migration guide before
  changing a name, parameter, default, or response property.
