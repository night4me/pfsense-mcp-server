# Architecture diagrams

These diagrams describe the current release's production READ path (95
tools, 0 default WRITE) and the protected WRITE architecture built and
independently verified per `ADR-026`. Solid paths are active in
production; not-default-reachable paths are explicitly labeled as such
rather than as "future" or "inert" — the WRITE architecture is real,
implemented, and live-verified code, just never reachable without an
explicit, separate operator opt-in.

## Overall architecture

```mermaid
flowchart LR
    Caller[Trusted local MCP client] -->|stdio| App[Application / FastMCP]
    App --> Registry[ToolRegistry]
    Registry --> Tools[95 thin READ tools]
    Tools --> Domain[PfSenseClient]
    Domain --> Rest[RestApiClient\nGET-only]
    Rest --> Transport[HttpTransport]
    Transport -->|HTTPS GET| PfSense[pfSense REST API]
    Rest --> Models[Typed Pydantic models]
    Models --> Tools

    Profile[Auditor capability profile] --> Registry
    Endpoints[Verified endpoint registry] --> Rest
    Mock[MockTransport] -. offline tests .-> Rest

    Tier0[Dormant Tier 0 WRITE modules] -. not constructed .-> App
```

## READ request flow

```mermaid
sequenceDiagram
    participant C as MCP client
    participant T as MCP tool
    participant P as PfSenseClient
    participant R as RestApiClient
    participant H as HttpTransport
    participant F as pfSense

    C->>T: tool(arguments)
    T->>T: bind/audit disclosure choice
    T->>P: semantic READ method
    P->>P: validate bounded parameters
    P->>R: get(verified endpoint, params)
    R->>R: enforce API version and GET
    R->>H: request("GET", path)
    H->>F: HTTPS GET + API-key header
    F-->>H: HTTP response
    H-->>R: TransportResponse
    R->>R: parse JSON and map status/errors
    R-->>P: untrusted dict
    P->>P: shape checks + typed model mapping
    P-->>T: model/list
    T-->>C: serialized typed output
```

## MCP tool registration

```mermaid
flowchart TD
    Start[Application bootstrap] --> ProfileName[Load PFSENSE_PROFILE]
    ProfileName --> Profiles[get_profile]
    Profiles --> CapSet[Immutable capability set]
    CapSet --> Registry[ToolRegistry.register_all]

    Registry --> C1{Capability present?}
    C1 -->|yes| Build[Build thin tool callable]
    C1 -->|no| Skip[Do not register]
    Build --> Audit[Wrap with audit_logged]
    Audit --> MCP[FastMCP.tool registration]

    Registry --> WriteDispatch[register_all_write]
    WriteDispatch --> Empty[No branches / no WRITE registration]

    Tests[Registry and profile tests] -. assert 95 READ / 0 WRITE .-> MCP
```

## Configuration loading

```mermaid
flowchart TD
    Env[Process environment] --> Required{Required values present?}
    Required -->|no| Fail[Sanitized ConfigurationError\nprocess exits closed]
    Required -->|yes| URL[Validate HTTPS origin]
    URL --> Identity[Validate bounded identity]
    Identity --> TLS[Validate TLS mode and CA file]
    TLS --> Logs[Validate log bounds]
    Logs --> KeyOpen[Open key descriptor\nO_NOFOLLOW]
    KeyOpen --> KeyChecks{fstat: regular, current owner,\nno group/other bits, bounded?}
    KeyChecks -->|no| Fail
    KeyChecks -->|yes| KeyRead[Read bounded first line\nfrom same descriptor]
    KeyRead -->|empty/control/too long/read failure| Fail
    KeyRead --> Config[Immutable PfSenseConfig]
    Config --> SecretFilter[Register key with log redaction]
    SecretFilter --> Factory[Construct transport and READ client]
```

## REST client and error boundary

```mermaid
flowchart LR
    Domain[PfSenseClient] --> Endpoint[EndpointInfo]
    Endpoint --> Version{API version supported?}
    Version -->|no| Unsupported[UnsupportedOperationError]
    Version -->|yes| Method[GET-only request path]
    Method --> Transport[Transport.request]
    Transport --> Response{Outcome}
    Response -->|connection/timeout| Connection[PfSenseConnectionError]
    Response -->|401/403| Auth[PfSenseAuthError\nsanitary identity-free message]
    Response -->|other failure| API[PfSenseApiError\nstatus + response ID only]
    Response -->|success| JSON[Parse JSON object]
    JSON --> Shape[Domain shape/model validation]
    Shape -->|invalid| ShapeError[PfSenseResponseShapeError]
    Shape -->|valid| Public[Typed public model]
```

## Audit logging

```mermaid
flowchart TD
    Invoke[Tool invocation] --> Binder[Signature binding]
    Binder --> Context[tool name\nupstream identity\nmetadata supported/requested]
    Context --> Start[tool_invoked]
    Start --> Call[Execute tool]
    Call -->|success| Success[tool_succeeded\nduration + no values]
    Call -->|PfSenseMCPError| Domain[tool_failed\nfailure_class=domain\nexception class only]
    Call -->|other Exception| Unexpected[tool_failed\nfailure_class=unexpected\nexception class only]
    Domain --> Reraise[Re-raise unchanged]
    Unexpected --> Reraise

    Filter[SecretRedactionFilter] --> Sink[Rotating owner-only local log]
    Start --> Filter
    Success --> Filter
    Domain --> Filter
    Unexpected --> Filter

    Never[Arguments, responses, payloads,\nexception messages, credentials] -. never logged .-> Sink
```

## Security boundaries

```mermaid
flowchart LR
    subgraph TrustedLocal[Trusted local account boundary]
        Client[MCP client]
        Server[stdio MCP server]
        Key[Owner-only API-key file]
        Logs[Value-minimized logs]
        Client --> Server
        Key --> Server
        Server --> Logs
    end

    subgraph UntrustedInput[Untrusted data boundary]
        Appliance[pfSense API]
        JSON[Raw JSON / HTTP status]
        Appliance --> JSON
    end

    Server -->|HTTPS GET| Appliance
    JSON --> Validators[Status + shape + Pydantic validation]
    Validators --> Public[Credential-free public schemas/output]
    Public --> Server

    Repo[Public repository / CI] -->|MockTransport + sanitized fixtures only| Server
    Private[Private live acceptance] -. separately approved .-> Appliance
```

## READ security path (summary)

Source: `src/pfsense_mcp/tools/registry.py`, `capabilities.py`, `profiles.py`,
`pfsense_client.py`. Every one of the 95 registered READ tools takes this
exact path — no exceptions.

```mermaid
flowchart LR
    A["AI / MCP client"] -->|"stdio (trust boundary)"| B["Explicit registered<br/>MCP tool<br/>(1 of 95, no dispatcher)"]
    B --> C["Capability / profile gate<br/>(auditor: READ only)"]
    C --> D["Least-privilege mapping<br/>(exact pfSense privilege)"]
    D --> E["One fixed typed<br/>client method"]
    E --> F["pfREST GET<br/>(GET-only, enforced)"]
    F --> G[("pfSense appliance")]
    G --> H["Typed model boundary<br/>(secret fields excluded<br/>by construction)"]
    H --> I["Safe MCP result"]

    style A fill:#eee,stroke:#333
    style G fill:#eee,stroke:#333
    style C fill:#fff3cd,stroke:#856404
    style D fill:#fff3cd,stroke:#856404
    style H fill:#d1e7dd,stroke:#0f5132
```

Yellow boxes are hard, fail-closed gates (a capability not in the active
profile is never registered at all — not merely hidden). The green box is
where confirmed secret-bearing fields are structurally excluded from the
Pydantic model, not filtered post hoc. See "READ request flow" above for
the full call-by-call sequence this summarizes.

## Protected WRITE authorization path (`ADR-026`)

Source: `src/pfsense_mcp/tier1/execution_coordinator.py`,
`alias_description_execution.py`, `executor.py`, `state_machine.py`,
`SECURITY_MODEL.md`, and
[`ADR-026`](adr/ADR-026-first-write-capability-adapter.md) (accepted,
live-verified evidence). This describes the one capability that exists
today, `set_firewall_alias_description_v1` — not a general WRITE
framework covering arbitrary mutations.

```mermaid
flowchart TD
    Default["Default auditor profile:<br/>0 WRITE tools registered<br/>(this entire diagram is unreachable)"]
    Profile{"Operator explicitly selects<br/>PFSENSE_PROFILE=write_protected?"}
    Runtime{"Full Tier 1 material provisioned?<br/>(pinned Ed25519 authorities,<br/>encrypted contract store,<br/>live TPM witness connectivity)"}
    NoTool["build_production_runtime returns None -<br/>tool still not registered,<br/>regardless of profile"]

    Default -.-> Profile
    Profile -->|"no (default)"| Default
    Profile -->|"yes, explicit opt-in"| Runtime
    Runtime -->|"no - any piece missing"| NoTool
    Runtime -->|"yes"| Reachable["Exactly one WRITE tool registered:<br/>set_firewall_alias_description_v1<br/>IMPLEMENTED: yes. VERIFIED: yes (ADR-026).<br/>DEFAULT-REACHABLE: NO - requires this<br/>explicit, non-default opt-in every time"]

    Reachable --> Op["Operator intent<br/>(human, off-host)"]
    Op --> Plan["Deterministic security-posture plan<br/>+ canonical, independently-<br/>recomputable plan digest"]
    Plan --> Sign1["Off-host Ed25519 signature<br/>(PlanAuthorizationV2 -<br/>never signed by the executing process)"]
    Sign1 --> Gate["ExecutionCoordinator: 6 gates,<br/>fixed order, fail closed on first miss"]

    subgraph Gate6["Pre-execution gates (IMPLEMENTED + VERIFIED)"]
        direction TB
        G1["1. Structural validation"]
        G2["2. Signature verification"]
        G3["3. Expiry / currentness"]
        G4["4. Exact plan digest +<br/>authorized step membership"]
        G5["5. Freshness re-check<br/>(capability posture +<br/>TPM anchor assurance)"]
        G6["6. Atomic one-time<br/>authorization consumption"]
        G1-->G2-->G3-->G4-->G5-->G6
    end
    Gate --> Gate6
    Gate6 -->|"any gate fails"| Deny["Denied - sanitized, uniform<br/>(no earlier gate's pass/fail leaked)"]
    Gate6 -->|"all 6 pass"| Contract["RecoveryContract created<br/>(encrypted, HMAC-authenticated,<br/>closed state machine)"]

    Contract --> Confirm["Off-host ConfirmationEvidence<br/>(separate signer identity,<br/>bound to same contract/intent digests)"]
    Confirm --> CAS["Atomic PREPARED -> EXECUTING"]
    CAS --> Exec["MutationExecutor<br/>(sealed - the ONLY code path<br/>that ever sends a mutating request)"]
    Exec --> Send["Exactly one bounded HTTPS request<br/>to one allow-listed endpoint"]
    Send --> ReadBack["Authoritative read-back"]
    ReadBack --> Outcome{"Semantic outcome?"}
    Outcome -->|"confirmed"| Verified["VERIFIED"]
    Outcome -->|"ambiguous/uncertain"| Reconcile["RECONCILIATION<br/>(never a blind retry)"]
    Outcome -->|"proven no effect"| Failed["FAILED"]

    TPM[("TPM monotonic witness -<br/>the only anti-rollback anchor<br/>backend implemented today<br/>(a software-only posture is<br/>modeled but not yet built)")] -. "required for gate 5 to pass;<br/>advances once per VERIFIED mutation" .-> G5
    Audit[("Integrity-protected<br/>audit trail (HMAC chain)")] -. "every state transition" .-> Contract

    style Deny fill:#f8d7da,stroke:#842029
    style Verified fill:#d1e7dd,stroke:#0f5132
    style Reconcile fill:#fff3cd,stroke:#856404
    style Failed fill:#f8d7da,stroke:#842023
    style Exec fill:#cfe2ff,stroke:#084298
```

**Implemented, verified, and default-reachable are three different
claims.** This path is real, committed code (`IMPLEMENTED`), exercised
end-to-end twice against a real disposable LAB appliance with
independent verification each time, never production (`VERIFIED`), and
requires an explicit non-default profile opt-in plus a full Tier 1
material provisioning step before the one tool is even registered
(`NOT DEFAULT-REACHABLE`). None of the six pre-execution gates, the
`RecoveryContract` state machine, or the sealed executor are
hypothetical — but none of them are reachable by an AI model deciding,
on its own, to call a tool. The off-host Ed25519 signature step is the
concrete reason why: the running MCP server process never holds a
private key capable of producing a valid `PlanAuthorizationV2` or
`ConfirmationEvidence`, by construction.

## Defense in depth / trust boundaries

This is the high-level model: where each class of failure is actually
stopped, derived from the same source as the two diagrams above. Verbs
are deliberately specific (`STOPS`/`LIMITS`/`CONSTRAINS`/`DETECTS`/`PROVIDES`)
rather than a blanket "secure" — a defense-in-depth layer is not an
absolute guarantee, and this diagram does not claim otherwise.

```mermaid
flowchart TD
    AI["Untrusted / fallible AI reasoning<br/>(not treated as a security authority)"]

    L1["Explicit MCP surface<br/>STOPS: arbitrary endpoint selection -<br/>95 named tools, no generic dispatcher"]
    L2["Capability / profile boundary<br/>STOPS: unauthorized capability reachability -<br/>auditor grants 0 WRITE capabilities"]
    L3["Least-privilege pfSense identity<br/>LIMITS: blast radius even if an upper<br/>layer fails - scoped credential, not admin"]
    L4["Typed model / secret-exclusion boundary<br/>STOPS: confirmed credential/private-key<br/>fields from reaching AI output"]
    L5["READ / WRITE separation<br/>STOPS: ordinary observation from<br/>ever becoming mutation by itself"]
    L6["Authorization + confirmation boundary<br/>(WRITE path only)<br/>CONSTRAINS: intent - off-host signatures,<br/>separate identities, one-time use"]
    L7["Freshness / state validation<br/>(WRITE path only)<br/>STOPS: stale plans, concurrent-state<br/>mismatch, replay"]
    L8["Deterministic execution + read-back<br/>(WRITE path only)<br/>DETECTS: ambiguous mutation outcomes -<br/>never a blind retry"]
    L9["RecoveryContract state machine<br/>(WRITE path only)<br/>GOVERNS: full mutation lifecycle,<br/>durable and auditable"]
    L10["Integrity-protected audit trail<br/>DETECTS: state/audit tampering -<br/>HMAC-authenticated chain"]
    L11["TPM monotonic witness<br/>(WRITE path only)<br/>PROVIDES: hardware-backed anti-rollback<br/>evidence - the only anchor backend<br/>implemented today; required for<br/>production WRITE activation"]

    AI --> L1 --> L2 --> L3 --> L4 --> L5
    L5 -.->|"READ ends here for all 95 tools"| Done["Typed result returned"]
    L5 --> L6 --> L7 --> L8 --> L9 --> L10
    L9 -. "required before any plan is<br/>considered safe_to_proceed" .-> L11

    style AI fill:#f8d7da,stroke:#842029
    style L2 fill:#fff3cd,stroke:#856404
    style L6 fill:#fff3cd,stroke:#856404
    style Done fill:#d1e7dd,stroke:#0f5132
    style L11 fill:#cfe2ff,stroke:#084298
```

Layers L1–L5 apply to every request, READ or WRITE. Layers L6–L11 exist
only on the WRITE path and are unreachable under the default profile —
see the authorization-path diagram above for how an AI model is kept
out of that path entirely, not merely discouraged from using it.
