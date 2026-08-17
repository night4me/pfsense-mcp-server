# ADR-032: Nexus READ transport architecture (Phase E design, Phase F implemented offline)

- **Status:** Phase E's design below is preserved unmodified as the
  historical record it was accepted as. **Update (Phase F, 2026-08-17):**
  owner-authorized narrowly-scoped implementation of the design's core
  (`NexusSession`, `NexusTransport`) as real, offline-tested code —
  `src/pfsense_mcp/backends/nexus/session.py`,
  `src/pfsense_mcp/backends/nexus/transport.py`. **Still not wired into
  any runtime/backend-selection path** and **no live Nexus access was
  performed** — both remain exactly as forbidden this phase as they were
  in Phase E. See the "Phase F implementation notes" section appended
  at the end of this document for exactly what was built, what remains
  unresolved, and the GO/NO-GO recommendation for a future Phase G.
- **Scope:** Specifies the minimum transport required to move
  `NexusCarpStatusReader` (`src/pfsense_mcp/backends/nexus/carp_status.py`,
  Phase D) from OFFLINE-TESTED toward LIVE-READ-VERIFIED. Makes no change
  to Tier1 signed schemas, digest formats, or ADR-031. Does not make
  Nexus WRITE reachable in any way, does not touch community backend
  code, does not wire anything into `factory.py`/`tools/registry.py`/
  `application.py`.

## 1. Controller authentication

All findings below are re-confirmed against evidence already gathered
directly from `Netgate/pfsense-api`'s own source in Phase B/D of this
track (`example.py`, `helper_funcs.py`, `pfapi_openapi.yml`); GitHub's
raw-content host rate-limited further fetches during this phase, so
nothing here is newly re-verified beyond what was already captured
verbatim earlier in this session — cited as such throughout.

- **FACT — login flow.** `POST /login` with body
  `LoginCredentials{username, password, secondfactor?}` — `username`
  and `password` are **base64-encoded** (the schema's own field
  descriptions say so explicitly), `secondfactor` optional (2FA code,
  plain string, format undocumented). Response `200`:
  `LoginResponse{token, user, version, alerts}`. Response `400`:
  generic `Error{errcode, errlevel, errmsg, alerts}` — this project's
  established two-status-code finding (Phase A) applies here too: a
  failed login is **not** a distinct HTTP status, it's a `400` with
  `Error` body, indistinguishable at the status-code level from any
  other validation failure.
- **FACT — token representation.** `token` is a JWT. Netgate's own
  example code decodes it client-side to inspect claims:
  `json.loads(base64.b64decode(token.split(".")[1] + '=='))`, reading
  `sessInfo['exp']` for expiry. **No JWT claim schema is published** —
  the only confirmed claim name is `exp` (Unix timestamp), observed by
  direct client-side decoding in the official example, not documented
  anywhere formally.
- **FACT — refresh-token delivery.** "A JWT refresh token is also
  applied to cookie" (the operation's own description text). The
  example code confirms this is an `httpx` cookie jar
  (`client.get_httpx_client().cookies`), carried forward into
  subsequent `AuthenticatedClient` instances.
- **INFERENCE, not FACT — refresh-token lifetime.** A code *comment* in
  `example.py` says "Cookie jar contains the **24-hour** refresh
  token" — this is Netgate's own example author's comment, not a
  schema-enforced or documented guarantee. Treat "24 hours" as a
  strong hint, not a value to hardcode as authoritative.
- **UNKNOWN — access-token lifetime.** No fixed access-token TTL is
  documented anywhere. It must be read from the JWT's own `exp` claim
  at runtime; the official example's own refresh timer (below) does
  not derive its cadence from the actual token expiry, so it cannot be
  used as evidence of the real TTL either.
- **FACT — refresh mechanism.** `POST /login/refresh` with body
  `RefreshTokenParam{username}`, relying on the refresh-token cookie
  already being attached to the request. Response `200`: a **new**
  `LoginResponse` (same schema as login — a fresh access token, not a
  distinct "refresh response" shape). Response `400`: `Error` — same
  ambiguous-failure-mode caveat as login.
  **FACT — the operation's own description states the refresh-token
  cookie "must be valid for a successful refresh"** — i.e. this
  endpoint cannot itself re-establish a session once the refresh token
  has expired; a fresh `POST /login` is required at that point.
- **INFERENCE — refresh cadence.** The official example refreshes
  proactively every 4 minutes (`now - self.start > 240`, checked via a
  15-second polling timer), well before any plausible token expiry —
  a defensive safety margin chosen by Netgate's own example author, not
  a documented requirement. A real implementation should decode `exp`
  and refresh with its own safety margin relative to the *actual*
  claim, not blindly copy this constant.
- **Required credentials/configuration (FACT, from the schema +
  examples):** a Controller username/password (the example defaults to
  `admin`, but any Controller account works), optionally a 2FA code.
  **No separate per-device credential exists for READ operations** —
  the same Controller-level session is reused across every device via
  the confirmed base-path-prefix mechanism (Phase B), so a Nexus
  transport's *credential* surface is exactly one username/password
  pair, categorically different from the community backend's per-
  appliance API key file.

## 2. Device routing

Formalizing Phase B's confirmed finding precisely:

```
{CONTROLLER_URL}/api/device/{device_type}/{device_id}/api{operation_path}
```

- **FACT.** `device_type` is the literal string `"pfsense"` in every
  official example (`helper_funcs.py::createDeviceApiChild`,
  `example.py`). **No enum or format constraint exists anywhere in the
  OpenAPI schema for `device_type`** — checked directly this phase
  (`ControlledDevice.device_type: {"type": "string"}`, no enum). Other
  device types may exist in a broader Nexus context (the "Multi-
  instance Management" framing doesn't claim pfSense-only); none were
  observed. A transport should treat this as a **required, explicit
  configuration value**, not a hardcoded constant, even though every
  known use is `"pfsense"` — exactly matching the owner's instruction
  that device identity must be explicit configuration, never inferred.
- **FACT.** `device_id` is a plain, unconstrained string
  (`ControlledDevice.device_id: {"type": "string"}`, no regex/format,
  checked directly this phase) — obtained from `/mim/devices` (list) or
  `/mim/devices/device/{device_id}` (single lookup, which itself uses
  the same string as a path parameter). No UUID/length/character-set
  guarantee is documented. Display code in the official examples
  truncates it at 50 characters for a table column, which is a display
  choice, not a length bound.
- **Security-relevant consequence (not previously stated this
  explicitly): `device_id` must be validated and percent-encoded as an
  opaque path segment before being concatenated into a URL.** Because
  it is unconstrained and, in the eventual real implementation, would
  come from configuration (owner decision 2 — "device identity is
  explicit configuration and never inferred ambiguously"), a transport
  must reject a `device_id` containing a `/`, `..`, or other path-
  altering sequence rather than silently URL-encoding around it — a
  malformed identifier should fail closed at construction time, not
  produce a URL that resolves somewhere unintended. This is exactly the
  kind of "confused deputy via normalized target collision" concern
  ADR-031 already flagged in the abstract; this ADR makes it concrete
  for the one piece of routing state a READ-only transport actually
  handles.
- **No exceptions found.** Every operation in the schema — including
  `/aliases`, `/system/status`, `/services/carp/status` — uses the same
  bare `paths:` templates regardless of which base URL (Controller-only
  vs. per-device) they're reached through; nothing schema-visible
  changes behavior based on routing context. Re-confirmed this phase:
  no CARP-specific routing exception exists.

## 3. HTTP transport behavior

- **FACT, and a significant finding: every official Netgate example
  disables TLS verification** (`verify_ssl=False`, in both
  `example.py` and `helper_funcs.py`, on every `Client`/
  `AuthenticatedClient` construction, no exceptions). **This ADR
  explicitly rejects that default.** It is inconsistent with this
  project's own established posture (`tls.py`: `TLSMode.STRICT` is the
  only mode that requires no extra configuration; `INSECURE` exists but
  is documented as temporary and must be explicitly requested). A
  Nexus transport must default to strict certificate verification and
  require an explicit, separately-named opt-out (mirroring
  `PFSENSE_TLS_MODE`/`resolve_verify()`'s existing shape) if insecure
  verification is ever needed for a lab Controller — never inherit
  Netgate's own example default silently.
- **FACT — timeouts observed in examples** (not documented as
  requirements, just what Netgate's own reference code uses):
  main session client `httpx.Timeout(40, connect=10)`; per-device child
  client default `timeout=120` (constructor parameter,
  `connect=20` from a fixed inner default); a "clone" client used for
  one-shot short-lived calls (`get_status` during discovery)
  `timeout=30, connect=20`. Wide variance — not evidence of a
  recommended value, evidence that Netgate's own examples special-case
  timeout per call-site rather than using one constant. This project's
  own community `HttpTransport` uses one fixed, explicit timeout
  (`connect=10.0, read=30.0, write=10.0, pool=10.0`) for every call —
  **recommend the same discipline for Nexus**: one explicit, documented
  timeout constant, not per-call-site tuning, unless a specific
  operation is later shown to need otherwise.
- **UNKNOWN — retry policy.** No retry logic was found in any
  official example (failures print and either exit or `continue` a
  loop; nothing resembles exponential backoff or automatic retry). The
  generated `pfapi` client library's own HTTP-call-wrapper internals
  (`pfapi/api/*.py`, e.g. `pfapi/api/system/get_status.py`) were not
  fetched this phase (rate-limited) and could theoretically add retry
  behavior invisible in the example scripts — **explicitly unresolved,
  listed as a blocker below.** This project's own existing philosophy
  (fail-closed, no blind retry — see `write_api_client.py`'s docstring
  and ADR-013's reconciliation authority) argues for **no automatic
  retry** in the Nexus transport either, matching the community
  backend's own `RestApiClient`, which does not retry.
- **UNKNOWN — redirect handling.** Not addressed by any example or the
  schema. Recommend explicitly disabling redirect-following
  (`httpx.Client(follow_redirects=False)`), matching a fail-closed
  default and avoiding any possibility of a redirect silently
  retargeting a request to an unintended host.
- **FACT — error/status handling required.** Confirmed twice now
  (Phase A and re-confirmed this phase): exactly two HTTP status codes
  are used across the entire schema, `200` and `400`. A Nexus transport
  **cannot** reuse the community `RestApiClient`'s 401/403-by-status-
  code auth-failure detection (`errors.py`'s `PfSenseAuthError` mapping)
  — it must inspect the JSON body's `Error.errcode`/`errlevel` to
  distinguish an authentication failure from a validation failure from
  a not-found condition, none of which is currently formally enumerated
  anywhere in the schema (no documented `errcode` value list was found).
- **Response decoding / malformed-response handling.** Must mirror the
  community backend's own fail-closed discipline exactly
  (`rest_api_client.py::_try_parse_json` returns `None` on invalid
  JSON, then `_request()` raises `PfSenseAPIError` if `body is None` or
  not a dict) — a Nexus transport should raise the equivalent on
  non-JSON or non-object response bodies, never attempt a partial
  parse or best-effort field extraction.
- **Logging without credential/token leakage.** Mirror
  `errors.py`'s own stated rule ("No exception in this module may
  include a credential value... Code that catches a lower-level
  exception must construct a new, sanitized message") and
  `rest_api_client.py`'s existing log lines (`identity=%s path=%s
  status=%s`, never the body or headers). A Nexus transport's logging
  must never emit the JWT access token, the refresh-token cookie value,
  the base64-encoded username/password, or the raw response body of any
  `/login`/`/login/refresh` call.

## 4. Security boundaries

Restated as explicit, binding commitments for any future Phase F, not
just design notes:

- **READ-only by construction.** The transport interface (below)
  exposes exactly one operation shape: `GET`, returning parsed JSON.
  No method accepting a request body or a non-GET HTTP method may
  exist on it.
- **No generic arbitrary-path dispatch.** The transport must not expose
  a `request(method, path)`-shaped public method the way
  `Transport.request()` does internally for the community backend —
  that protocol is already the reviewed community-backend chokepoint;
  a Nexus equivalent must be its own narrow, capability-specific
  surface (see Architecture, below), not a copy of the generic shape,
  precisely because "generic dispatch" is one of this entire track's
  standing hard boundaries.
- **No mutation methods, ever, in this design.** Nothing in this ADR
  specifies or hints at a POST/PUT/PATCH/DELETE call. `/services/carp/enabled`,
  `/services/carp/maintenancemode`, and every other Nexus write-shaped
  endpoint found across four phases of research are explicitly out of
  scope and not referenced as anything but "endpoints that exist,"
  never "endpoints this transport calls."
- **No mechanism that could accidentally make Nexus WRITE reachable.**
  The transport, as specified, cannot reach `tier1/executor.py` or
  `write_api_client.py` — nothing in its design imports or references
  either, and `tests/backends/test_isolation.py` (generalized in Phase
  D to scan all of `backends/`) already enforces this structurally for
  whatever code eventually lands here.
- **0 default-reachable WRITE preserved.** This ADR authorizes no
  runtime wiring of any kind; the 42/0 contract is unaffected by
  definition, since nothing here is reachable from `factory.py`/
  `tools/registry.py`/`application.py`.
- **ADR-031 remains the mandatory gate for Nexus WRITE.** Nothing in
  this document weakens, reinterprets, or works around ADR-031's
  invariant. This ADR is READ-only-scoped by its own terms and does not
  attempt to satisfy ADR-031's backend/device identity binding
  requirement — that requirement is specifically about signed
  authorization material, which no READ operation ever produces or
  consumes.

## 5. Architecture

**Smallest interfaces, mirroring the existing `Transport`/`RestApiClient`
split exactly, so the pattern is familiar rather than novel:**

```
NexusSession            -- owns login, JWT/cookie state, refresh
    |
NexusTransport          -- GET-only, device-base-path-aware, wraps
    |                       one authenticated httpx.Client per session
    |                       (or per device-scoped child, mirroring
    |                       RequestClient.createDeviceApiChild's own
    |                       shape) -- never exposes method/path as
    |                       caller-supplied arbitrary arguments
    |
NexusCarpStatusReader   -- UNCHANGED from Phase D. Still takes an
                            injected fetch_raw: Callable[[], dict].
                            Phase F's job is to supply a real
                            fetch_raw = lambda: nexus_transport.
                            get_json("/services/carp/status") closure
                            (or equivalent), not to change this
                            reader's own shape at all.
```

- **`NexusCarpStatusReader` never owns JWT/session/routing logic.**
  This is already true today (Phase D) by construction — it takes
  `fetch_raw: Callable[[], dict[str, Any]]` and calls it, nothing more.
  Phase F's entire job is producing a `fetch_raw` closure backed by a
  real `NexusTransport`; **the reader itself requires zero changes.**
  This is the single strongest piece of evidence that Phase D's "smallest
  isolated adapter" scoping decision was correct: the seam between
  business logic and transport was already exactly where it needed to
  be before this transport design work even started.
- **Backend isolation preserved.** `NexusSession`/`NexusTransport`
  would live under `src/pfsense_mcp/backends/nexus/` (alongside
  `carp_status.py`), never imported by `factory.py`, `pfsense_client.py`,
  `rest_api_client.py`, `transport/http.py`, or any community-backend
  file — `tests/backends/test_isolation.py` already enforces the
  "nothing outside `backends/` imports `backends/`" half of this; a
  Phase F implementation gets that guarantee for free.
- **No coupling into community backend code.** `NexusTransport` does
  **not** implement the existing `Transport` Protocol
  (`transport/base.py`) — that protocol's `request(method, path, *,
  body)` shape is deliberately generic in a way this ADR's own Section
  4 says a Nexus transport must not be. A new, narrower, GET-only
  protocol is warranted, not reuse of the existing one merely because
  it's already there.
- **Proposed production files (Phase F, not created by this ADR):**
  - `src/pfsense_mcp/backends/nexus/session.py` — `NexusSession`:
    login, JWT decode (`exp` extraction only — no other claim
    interpretation), refresh-before-expiry, credential handling. Takes
    a controller URL + username + password (+ optional 2FA) at
    construction; never logs any of them.
  - `src/pfsense_mcp/backends/nexus/transport.py` — `NexusTransport`:
    GET-only, takes a `NexusSession` plus `device_type`/`device_id`,
    builds the base path via a validated URL-builder (see below),
    issues one HTTP GET per call, decodes JSON, raises on non-2xx or
    malformed body. Exposes exactly one public method, something like
    `get_json(operation_path: str) -> dict[str, Any]` — still narrower
    than the community `Transport.request()`, since it hardcodes GET
    and forbids a body, but even this is a slightly wider surface than
    `NexusCarpStatusReader` needs alone; **Phase F should decide
    whether an even narrower, single-purpose method per capability is
    preferable** to a shared `get_json(path)` — flagged as an open
    question below, not resolved here.
  - `src/pfsense_mcp/backends/nexus/routing.py` — the URL-builder
    (see "What was implemented this phase," below — a first version of
    this file already exists and is the one piece of this ADR turned
    into real, tested code this phase, since it is provably not "the
    transport": no network I/O, no session state, no credentials).
- **Exact configuration additions Phase F would eventually need**
  (naming illustrative, not committed): `PFSENSE_NEXUS_CONTROLLER_URL`,
  `PFSENSE_NEXUS_USERNAME`, `PFSENSE_NEXUS_PASSWORD_FILE` (never a
  plain env var for a password, matching this project's existing
  `PFSENSE_API_KEY_FILE` file-based-credential convention),
  `PFSENSE_NEXUS_DEVICE_TYPE`, `PFSENSE_NEXUS_DEVICE_ID`, and a TLS-mode
  setting mirroring `PFSENSE_TLS_MODE` (defaulting to strict,
  explicitly rejecting Netgate's own example default). None of these
  are added to `config.py` by this ADR — stated as a requirement for
  Phase F.

## 6. Testing strategy (design for Phase F; only the URL-builder's own
tests are implemented this phase — see below)

Deterministic, offline, fixture/mock-based — no real network calls in
any of these, mirroring how `tests/backends/nexus/test_carp_status.py`
already tests `normalize_carp_status()`/`NexusCarpStatusReader` without
any HTTP dependency:

- **Successful authentication** — mock the login HTTP call, assert
  `NexusSession` extracts the token and schedules/knows how to
  determine refresh timing from a synthetic `exp` claim.
- **Authentication failure** — mock a `400`/`Error`-shaped login
  response, assert a clear, typed exception (not a generic one),
  credential values never appear in the exception message.
- **Expired token/session behavior** — construct a `NexusSession` with
  a synthetic already-expired `exp`, assert it refuses to use the stale
  token and either refreshes or fails closed rather than sending a
  request with a token it knows is expired.
- **Device URL construction** — the one piece of this design already
  implemented and tested this phase; see below for the actual test
  list (valid ids, encoding, rejection of path-altering characters).
- **Malformed identifiers** — `device_id`/`device_type` containing `/`,
  `..`, control characters, empty string — must all be rejected before
  any URL is constructed, never silently encoded around.
- **TLS/timeout/network failures** — mock `httpx.ConnectError`/
  `httpx.TimeoutException`/`httpx.TransportError` at the transport
  layer, assert translation into this project's own typed exceptions
  (mirroring `HttpTransport.request()`'s existing pattern exactly, not
  inventing new exception types where the existing `errors.py`
  hierarchy already covers the case).
- **Non-2xx responses** — mock a `400` with a real `Error`-shaped body,
  assert the transport raises with the `errcode`/`errmsg` surfaced in
  the exception, never silently swallowed.
- **Malformed JSON** — mock a response body that isn't valid JSON at
  all, assert fail-closed (mirroring `_try_parse_json`'s existing
  `None`-on-failure + caller-raises pattern).
- **Missing CARP fields** — already fully covered today by Phase D's
  `test_nexus_carp_status.py` at the normalization layer; Phase F needs
  no new tests here, only an end-to-end test proving the real
  `NexusTransport` → `normalize_carp_status()` wiring produces the same
  result as the existing fixture-based unit tests.
- **Prevention of arbitrary endpoint dispatch** — a structural test
  (mirroring `tests/backends/test_isolation.py`'s AST-based approach)
  asserting `NexusTransport` exposes no method accepting a caller-
  supplied HTTP method, and that its path-accepting method(s), if any,
  cannot be reached with anything other than the literal, hardcoded
  `/services/carp/status`-style constants this codebase defines itself
  — never a caller-supplied string.
- **Prevention of WRITE reachability** — extend the existing
  `test_backends_package_defines_no_write_shaped_members` (already
  scans all of `backends/`) to also assert no HTTP method other than
  `"GET"` appears as a literal anywhere under `backends/nexus/`.
- **Secret/token redaction** — assert that stringifying/logging a
  `NexusSession` or any exception it raises never contains the literal
  password, base64-encoded credential, or JWT token substring, using a
  synthetic known-value fixture and asserting its absence from every
  log line and exception message produced during a simulated failure.

## 7. Live-read prerequisites (not performed this phase)

Before any real `GET` could be issued against a live Nexus Controller:

- A running Netgate Nexus Controller (pfSense Plus 25.07+, confirmed
  Phase A) reachable from wherever the transport runs.
- At least one pfSense Plus device registered with that Controller
  (confirmed two-step registration process, Phase B: device shares
  "Registration Data," Controller imports it, exports "Activation Data"
  back) and in `state: "active"` (or `"online"`, per the example
  scripts' own check — the exact live-state string was not indepen-
  dently reconciled between the OpenAPI schema's documented enum
  (`active, error, offline, rebooting, pending`) and the example
  scripts' runtime check for `"online"`; this is itself a small,
  concrete, checkable-only-with-live-access discrepancy worth resolving
  in Phase F, not resolvable from static sources alone).
- A Controller-level username/password (and 2FA code, if the Controller
  account requires it) with sufficient privilege to call
  `/services/carp/status` for the target device — the exact privilege
  model for Nexus Controller accounts (equivalent to the community
  backend's REST-API privilege strings, ADR-026) was **not** researched
  this phase and is a real gap: Phase F should not assume a Controller
  admin account is required, but has no evidence yet of a narrower
  scoped-account option either.
- Explicit owner authorization for the live call itself, separate from
  authorization to write the transport code — matching this entire
  track's standing pattern (every prior phase's live-validation step
  was skipped, never silently attempted, when credentials weren't
  already available).

**None of the above is available in this environment. No live Nexus
Controller/device/credential exists in this session's reach — this
matches every prior phase's finding and this ADR performs no live
access of any kind.**

## What was implemented this phase (the one piece that is provably not
"the transport")

`src/pfsense_mcp/backends/nexus/routing.py` —
`build_device_base_path(device_type: str, device_id: str) -> str`. Pure,
stateless, zero network I/O, zero credentials, zero session state:
formats and validates the confirmed
`/api/device/{device_type}/{device_id}/api` path segment (the
Controller's own base URL is a separate, caller-supplied prefix, kept
out of this function entirely — it's pure path-segment construction,
not URL assembly). Rejects (raises `ValueError`, matching this
project's existing `PfSenseRequestValidationError`-style fail-closed
input validation, though this function lives below any pfSense-error-
model layer so uses the plain, standard exception) any `device_type`/
`device_id` that is empty or contains `/`, `..`, whitespace, or any
character outside a conservative allow-list — proving the "malformed
identifiers must be rejected before URL construction" requirement from
Sections 2 and 6 with real, executable code, not just a design promise.
This is deliberately the *only* production code this phase adds:
everything else above (session, transport, config) remains
specification only, exactly as authorized.

## Unresolved questions / blockers for Phase F

1. Real access-token TTL (JWT `exp` semantics beyond the one confirmed
   claim name) — not documented, only observable with a live token.
2. Whether the generated `pfapi` client library's own HTTP call wrappers
   (`pfapi/api/*.py`) add retry/backoff behavior invisible in the
   example scripts — not fetched this phase (rate-limited), should be
   checked before Phase F rather than assumed either way.
3. Redirect-handling default — no evidence either way; this ADR
   recommends disabling it but that is a recommendation, not a
   confirmed requirement.
4. The `active` (schema) vs. `"online"` (example-script runtime check)
   device-state string discrepancy — only resolvable against a live
   Controller.
5. Nexus Controller account privilege model for scoping a READ-only
   credential (this track's own least-privilege standard, ADR-026,
   has no established Nexus equivalent yet) — not researched this
   phase at all.
6. Whether `NexusTransport` should expose one shared `get_json(path)`
   or a narrower per-capability method — explicitly left open in
   Section 5, a real design choice for Phase F, not a gap in this
   phase's research.

## Recommendation: GO / NO-GO for Phase F

**Conditional GO**, narrowly scoped. The routing mechanism (Section 2),
the security boundary (Section 4), and the reader/transport seam
(Section 5) are specified precisely enough to implement without further
research. The TLS-default deviation from Netgate's own examples
(Section 3) is resolved and non-negotiable (strict verification,
explicit opt-out only). The credential/configuration model (Section 5)
is concrete enough to add to `config.py` without ambiguity.

**What should not be treated as resolved going into Phase F:**
unresolved questions 1–3 (token TTL, generated-client retry behavior,
redirect policy) should be either confirmed against source before
writing code, or explicitly accepted as documented assumptions in
Phase F's own commit message if a live Controller remains unavailable
to verify them. Unresolved question 5 (Nexus account privilege
scoping) is the one gap serious enough to flag as a real blocker for
*live* validation specifically — Phase F can and should implement and
offline-test the full transport regardless, but should not treat
"credentials become available" as sufficient on its own to authorize a
live read; a least-privilege Nexus account should be designed first,
matching this track's own established standard rather than defaulting
to a Controller admin account out of convenience.

## Phase F implementation notes (2026-08-17)

### Blockers resolved from authoritative source this phase

Fetched `Netgate/pfsense-api`'s actual generated Python client source
(`py/pfapi/client.py`, `py/pfapi/api/login/login.py`) via the GitHub
Contents API (`raw.githubusercontent.com` was rate-limiting this
session; `api.github.com` was not) — this decisively resolves two of
Phase E's three "unresolved questions":

- **Retry behavior: CONFIRMED, none.** `login.py`'s `sync_detailed()`
  issues exactly one `client.get_httpx_client().request(**kwargs)` call
  with no wrapping retry/backoff logic anywhere in `client.py` or the
  call-site. This project's `NexusSession`/`NexusTransport` match:
  zero retries, confirmed by `test_login_issues_exactly_one_request_on_failure_no_retry`
  and `test_single_request_on_failure_no_retry`.
- **Redirect behavior: CONFIRMED, `follow_redirects=False` by default.**
  `Client`/`AuthenticatedClient`'s own `attrs` field definition:
  `_follow_redirects: bool = field(default=False, ...)`. This project's
  transport matches exactly, confirmed by
  `test_client_does_not_follow_redirects` in both `test_session.py`
  and `test_transport.py`.
- **A related, unprompted finding:** the generated client's own
  `_parse_response()` (in `login.py`, and presumably every other
  generated call-site) returns `None` silently for any status code
  outside the documented `200`/`400` unless
  `Client.raise_on_unexpected_status=True` is explicitly set (default
  `False`). This project's `NexusSession`/`NexusTransport` deliberately
  do **not** replicate that default — both raise (`PfSenseAuthError`/
  `PfSenseAPIError`) on any non-200, matching this project's own
  fail-closed posture rather than Netgate's own generated client's
  fail-silent one.

**Access-token TTL beyond the `exp` claim remains genuinely unresolved**
— no live token was available to inspect, and no further source
revealed a fixed duration. `NexusSession` never assumes one: it decodes
`exp` from the actual token issued at login and refuses to proceed
(`PfSenseAuthError`) if that claim is missing or malformed, exactly the
"fail closed if token expiry cannot be safely determined" requirement.

### Exact production files added

- `src/pfsense_mcp/backends/nexus/session.py` — `NexusSession`. Owns
  `POST /login` and `POST /login/refresh` — the only two mutation-
  shaped HTTP verbs this entire Nexus track is permitted to issue, and
  the only two anywhere in this module or `transport.py`. Decodes the
  JWT `exp` claim (base64url, no signature verification — the
  Controller is the signer of a token this session itself just
  received, not a third party's claim being trusted) and refreshes
  proactively 30 seconds before expiry, or immediately if already past
  it. Never logs, reprs, or raises an exception containing the
  password, the base64-encoded credential, or the token value.
- `src/pfsense_mcp/backends/nexus/transport.py` — `NexusTransport` +
  `NexusEndpointInfo` + `NexusEndpoints`. GET-only: exactly one public
  method, `get_json()`, which only accepts a `NexusEndpointInfo`
  instance (currently exactly one: `NexusEndpoints.CARP_STATUS`) —
  never a caller-supplied raw string. No method on the class accepts
  an HTTP method argument, and the class never calls `.post()`/
  `.put()`/`.patch()`/`.delete()` on its underlying `httpx.Client`
  (enforced by a structural test reading the module's own source).
  Uses `routing.py::build_device_base_path()` (Phase E) at
  construction time, so a malformed `device_type`/`device_id` fails
  before any HTTP client is even created. Takes the session as a
  narrow `_TokenProvider` Protocol (one method,
  `get_valid_access_token() -> str`), not the concrete `NexusSession`
  class — matching `backends/ports.py`'s own established narrow-
  Protocol dependency-injection pattern, and meaning this module never
  needs to import `session.py` at all.

Both classes default `verify=True` (strict TLS) and set
`follow_redirects=False` explicitly — deliberately not inheriting
Netgate's own example code's `verify_ssl=False` default (ADR-032
Section 3's non-negotiable finding). Both use the same explicit
timeout shape the community backend's own `HttpTransport` already uses
(`connect=10.0, read=30.0, write=10.0, pool=10.0`), overridable per
instance.

**No configuration was added to `config.py`.** No `PFSENSE_NEXUS_*`
environment variable exists anywhere in this codebase as a result of
this phase — `NexusSession`/`NexusTransport` take their controller
URL, credentials, and device identity as explicit constructor
arguments only, with no wiring to any settings/config layer.

### How arbitrary dispatch and mutation reachability are prevented

- `NexusTransport.get_json()` raises `TypeError` if passed anything
  other than a `NexusEndpointInfo` instance (`test_get_json_rejects_raw_string_path`).
- An AST-level test (`test_no_endpointinfo_constructed_outside_nexusendpoints`)
  proves `NexusEndpointInfo(...)` is never constructed anywhere in
  `transport.py` outside the `NexusEndpoints` class body itself — so
  even though `get_json()`'s own type check alone couldn't stop a
  caller from building an off-allow-list `NexusEndpointInfo` by hand
  (documented explicitly by
  `test_get_json_rejects_arbitrary_endpoint_info_look_alike`, which
  shows this mechanically succeeds), no code anywhere in this
  repository ever does that — the real guarantee is architectural
  (nothing produces such a value), not purely a runtime check.
- `test_transport_has_no_mutation_verb_methods` and
  `test_transport_source_never_calls_httpx_mutation_methods` together
  prove, structurally, that `NexusTransport` has no POST/PUT/PATCH/
  DELETE capability at all, at either the method-name or source-code-
  call level.
- `tests/backends/test_isolation.py` (generalized in Phase D to scan
  every file under `backends/`) continues to cover both new files
  automatically — re-run and confirmed passing this phase without any
  change to that test file itself.

### CARP integration test result

`tests/backends/nexus/test_carp_integration.py` (5 tests, all offline/
respx-mocked) proves the full chain —
`NexusSession.login()` → `NexusTransport.get_json()` →
`normalize_carp_status()`/`NexusCarpStatusReader.get_carp_status()` —
produces the correct `CarpStatus` on a well-formed response, fails
closed (`PfSenseResponseShapeError`) on a missing or wrong-typed CARP
field propagated all the way through the real transport (not just the
normalization function in isolation, which Phase D already covered),
and that a login failure propagates before any CARP request is even
attempted. This wiring exists in test code only — not exposed in
production code, not registered as a tool, not reachable through
`factory.py`/`tools/registry.py`/`application.py`, or any backend-
selection path.

### Unresolved upstream findings (carried forward, not solved this phase)

1. Real access-token TTL beyond the `exp` claim — still unresolved,
   requires a live token to observe.
2. The `active` (schema) vs. `"online"` (example-script runtime check)
   device-state string discrepancy — untouched this phase, per the
   owner's explicit instruction not to add device-state policy unless
   required by the transport (it wasn't — this transport never reads
   or reasons about device state).
3. Nexus Controller account privilege-scoping model — still not
   researched, remains a live-validation prerequisite only, does not
   block anything implemented this phase.

### GO / NO-GO for Phase G

**NO-GO on runtime wiring or live access — not authorized, not
attempted, matches Phase F's own explicit scope.** For a future,
separately-authorized Phase G specifically about connecting this
transport to a real Nexus Controller: **conditional GO**, narrower
than Phase F itself. The transport's own correctness is now backed by
102 offline tests (session, transport, routing, CARP integration,
isolation) rather than design documentation alone. What Phase G would
still need before any live call: (a) real Controller/device/credential
access (explicitly not available in this environment, per every prior
phase's finding), (b) resolution or explicit acceptance of the
access-token-TTL unknown against a real token, (c) a designed,
least-privilege Nexus account rather than defaulting to a Controller
admin credential out of convenience — this remains the one gap serious
enough to gate live validation specifically, unchanged from Phase E's
own recommendation.
