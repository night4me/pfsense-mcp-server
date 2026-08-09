# Endpoint Catalogue (ADR-019 Part 1)

`endpoint_catalogue.json` is the committed **Endpoint Catalogue**
artifact ADR-019 defines
(`docs/API_SURFACE_ARCHITECTURE.md` Part 1): a durable, human-reviewed
record of pfSense API GET operations this project's tooling has
`DISCOVERED` and a human has `CATALOGUED` — nothing more. It is:

- **Data, not code.** Loaded by
  `src/pfsense_mcp/api_surface/store.py` into the frozen, `extra="forbid"`
  `EndpointCatalogue`/`CatalogueEntry` Pydantic models
  (`src/pfsense_mcp/api_surface/catalogue.py`). Never imported as Python;
  never executed.
- **Not packaged.** Excluded from both the wheel (`pyproject.toml`'s
  wheel target packages only `src/pfsense_mcp`) and the sdist (not named
  in its include-list) — matching `lab/`'s existing exclusion pattern.
- **Not consulted by production.** `pfsense_mcp.api_surface` is not
  imported by `Application`, `factory`, `server`, `ToolRegistry`, or any
  READ tool — enforced by
  `tests/api_surface/test_catalogue_isolation.py`, not only documented.
- **No runtime effect, by construction.** `CatalogueEntry` has no field
  that could represent `TYPED`/`IMPLEMENTED`/`CAPABILITY_MAPPED`/
  `AUTHORIZED`/`MCP_EXPOSED` — an entry existing here can never imply,
  claim, or cause any of those later states. Whether a catalogued path
  has gone further than `CATALOGUED` is a fact about
  `pfsense_mcp.endpoints`/`pfsense_mcp.capabilities`/
  `pfsense_mcp.tools.registry`, entirely outside this artifact's
  knowledge.

## Regenerating

`scripts/build_endpoint_catalogue.py` fetches a pfSense OpenAPI schema
(live, via the same authenticated config this project's other developer
tooling already uses, or from a local `--schema-file` snapshot) and
reports what would change against the currently committed file. By
default it is a **dry run** — it writes nothing. Pass `--update` to
write the updated file to the working tree.

**Writing the file is not the same as it taking effect.** Like any other
change to this repository, an updated `endpoint_catalogue.json` only
becomes part of the project through an ordinary, human-reviewed pull
request and merge — the script itself never stages, commits, or pushes
anything, and nothing in CI ever runs it automatically. This is a
structural requirement of ADR-019 (`docs/API_SURFACE_ARCHITECTURE.md`
Part 1's "Catalogue regeneration must not bypass human review either"),
not merely a convention: an unreviewed, auto-committed catalogue update
would be a real supply-chain integrity gap even though the artifact has
no runtime effect, since a poisoned or mistaken entry could still
mislead a later human reviewer relying on it.

Regenerating never changes an existing entry's `intended_use` — that
field is a human judgment, set only by directly editing this file in a
reviewed commit. A rebuild only adds newly discovered paths (with
`intended_use: "none"`, the safe default) and reports, but does not
remove, paths the schema no longer mentions.

This file currently starts **empty** (`entries: []`) — this
implementation slice ships the mechanism, not a populated catalogue. No
live pfSense schema was fetched to seed it, since doing so responsibly
requires a real, credentialed pfSense connection this session did not
have; populating it is a separate, future, human-reviewed act.
