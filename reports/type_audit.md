# Type quality audit

Date: 2026-08-06

## Executive summary

The project passes its configured mypy gate and uses typed models effectively
at the public MCP boundary. Most `Any` usage is concentrated at deliberately
untrusted JSON/OpenAPI boundaries, where values are not known until runtime.
The strongest opportunities are to give those boundaries one explicit JSON
type vocabulary and to tighten internal scripts incrementally. A repository-wide
replacement would make the code less readable today and was not attempted.

No runtime or public API code was changed by this audit.

## Measurements

| Area | Python files | `Any` tokens | Files using `Any` | Type-ignore files |
|---|---:|---:|---:|---:|
| `src/pfsense_mcp` | 110 | 103 | 42 | 2 |
| `scripts` | 23 | 55 | 7 | 0 |

Configured mypy succeeds as part of the standard project gates. An additional
exploratory `mypy --strict src/pfsense_mcp scripts` run reported 17 errors in
7 files. This strict run is diagnostic only; strict mode is not currently the
project contract.

Strict-mode findings:

- eight incomplete annotations in fixture/scaffolding code and the untyped MCP
  framework object passed to `ToolRegistry`;
- seven `no-any-return` findings at JSON, OpenAPI, or sanitizer boundaries;
- one implicit re-export warning for `ConfigurationError`;
- two decorator return-value ignores in the READ and dormant WRITE audit
  wrappers (these are present in the configured run but do not fail it).

## Existing strengths

- Pydantic models define the serialized output boundary rather than returning
  raw upstream dictionaries.
- `Transport` and `RollbackPlan` are structural `Protocol`s, keeping concrete
  implementations replaceable and tests simple.
- Audit decorators use a bounded callable `TypeVar` and preserve signatures
  through `functools.wraps`.
- Enums represent capability, endpoint, profile, TLS, and Recovery Contract
  state vocabularies.
- Public tool parameters have concrete primitive types and bounded validation.
- Production and test transports implement a common typed response interface.

## `Any` assessment

### Justified boundary usage

`dict[str, Any]` in model `from_api` methods represents untrusted JSON before
field selection and Pydantic validation. Similar use in `rest_api_client.py`,
fixture sanitization, and OpenAPI discovery is defensible: JSON values are
recursive and heterogeneous. Replacing each occurrence with `object` would add
repeated narrowing without materially improving safety.

The dormant WRITE models also hold arbitrary JSON snapshots and mutation
payloads. Their typing should be revisited only with the Tier 1 Recovery
Contract design, because the authoritative persisted shape and serialization
rules are not yet settled.

### Highest-value reductions

1. Define a recursive JSON type in one internal module, for example
   `JSONScalar`, `JSONValue`, `JSONObject`, and `JSONArray`. Pilot it in the
   REST client and one model before broad adoption; recursive aliases can make
   Pydantic and mutation code harder to read if applied mechanically.
2. Validate `response.json()` as a mapping before returning it from
   `RestApiClient`. This could eliminate a strict `no-any-return` while making
   the response-shape boundary more explicit. Behaviour and exception mapping
   must remain identical.
3. Add precise policy/manifest types to scaffold tooling. A `TypedDict` for
   loaded discovery endpoints and fixture-approval records would remove several
   untyped parameters without affecting runtime APIs.
4. Annotate iterator returns in `scripts/lib/openapi.py` and the helper policy
   parameters in `scripts/scaffold_capability.py`.

## `Literal` and enum opportunities

- Keep persisted or public state vocabularies as enums; they provide runtime
  validation that `Literal` does not.
- A `Literal["GET"]` can describe the production REST method internally, but
  the stronger property is already structural: the public client exposes only
  `get`, and static checks inspect transport call sites.
- Scaffolding-only strings such as response shape and fixture action could use
  `Literal` after their complete accepted vocabularies are documented.
- Avoid replacing existing enums with literals merely to reduce imports.

## `Final` opportunities

Module-level security-policy constants are candidates for `Final`, especially
prohibited credential-key sets, endpoint registries, bounds, and log defaults.
The value is primarily reviewer signal; it does not make mutable contents
immutable. Prefer `Final[frozenset[str]]` or immutable mappings, and introduce
annotations only where they clarify a true invariant.

## `Protocol` opportunities

- The existing `Transport` protocol is the most important abstraction and
  should remain small.
- A narrow registrar protocol containing only `tool()` could type the MCP object
  passed to `ToolRegistry`, but it should be introduced only after checking the
  installed MCP package's exported types.
- Filesystem/store protocols may be appropriate when Tier 1 persistence is
  designed. Adding them before persistence semantics exist would be speculative.
- Do not introduce repository/service interfaces around every concrete class;
  `MockTransport` already supplies the key test seam.

## `TypedDict` opportunities

Good candidates are dictionaries with stable keys used only inside tooling:

- checkpoint state;
- OpenAPI field and operation summaries;
- scaffold discovery endpoints;
- fixture audit/approval records.

Raw appliance payloads are poor candidates because upstream optionality and
version drift are precisely what the model conversion boundary handles.
Pydantic models should remain the typed public representation.

## Overloads and generics

No compelling overload was identified. Overloads for singleton versus
collection REST responses would obscure runtime shape validation and couple
callers to endpoint metadata. The current concrete PfSense client methods are
clearer.

Generics could describe collection envelopes, but would change generated model
names or schemas unless carefully isolated. Treat that as a future-major API
design topic, not a typing cleanup.

## Type-ignore review

The two `# type: ignore[return-value]` comments are in decorators that return a
runtime-preserved wrapper as the original callable type. This is a conventional
limitation of `TypeVar`-based decorator typing. A future Python-version policy
could use `ParamSpec` plus a typed wrapper to remove the ignores, provided MCP
signature introspection and audit metadata remain unchanged.

## Recommended sequence

1. Add return and parameter annotations to internal scripts until exploratory
   strict mypy failures are limited to intentional JSON boundaries.
2. Pilot a shared recursive JSON alias in a small internal module and measure
   readability before expanding it.
3. Type the MCP registrar boundary using upstream framework types or a narrow
   local protocol.
4. Convert stable tooling record dictionaries to `TypedDict` one workflow at a
   time, with tests unchanged.
5. Reconsider strict mode per module; do not flip it repository-wide until the
   remaining exceptions express deliberate boundary choices.

## Manual review

- Confirm whether the MCP library exposes a stable public registrar type before
  defining a local protocol.
- Revisit dormant WRITE payload types only as part of an explicitly approved
  Tier 1 design.
- Review generated JSON Schemas after any generic or type-alias refactor, even
  when Python signatures appear unchanged.
