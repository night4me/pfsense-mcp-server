# Architecture diagrams

These diagrams describe the immutable v0.3.0 production baseline (same
active READ path as v0.2.2) and the inert Tier 1 development framework it
ships. Solid paths are active in production; future/dormant paths are
explicitly labeled.

## Overall architecture

```mermaid
flowchart LR
    Caller[Trusted local MCP client] -->|stdio| App[Application / FastMCP]
    App --> Registry[ToolRegistry]
    Registry --> Tools[42 thin READ tools]
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

    Tests[Registry and profile tests] -. assert 42 READ / 0 WRITE .-> MCP
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

## Inert Tier 1 framework and future execution path

```mermaid
flowchart TD
    Caller[Separately authorized operator] --> Prepare[Prepare mutation intent]
    Prepare --> Read[Existing verified READ method]
    Read --> Snapshot[Capture target pre-state]
    Snapshot --> Store[Authoritative crash-safe contract store]
    Store --> Contract[Target/capability/endpoint/method/intent-bound contract ID]

    Caller --> DryRun[Dry-run tool]
    DryRun --> Validate[Allow-list + capability + typed payload validation]
    Validate --> Diff[Predicted semantic diff\nzero mutation]

    Caller --> Confirm[Explicit execute confirmation + contract ID]
    Confirm --> Load[Load authoritative contract by ID]
    Load --> CAS[Atomic PREPARED → EXECUTING]
    CAS -. executor not implemented .-> Write[Future WriteApiClient\nonly non-GET chokepoint]
    Write -->|approved HTTPS mutation| PfSense[Disposable/test pfSense first]
    PfSense --> ReadBack[Verified READ-back]
    ReadBack --> Commit{Expected semantic state?}
    Commit -->|yes| Verified[VERIFIED]
    Commit -->|no/ambiguous| Unknown[RECONCILIATION\noperator decision required]

    Verified --> Rollback[Target-bound rollback]
    Rollback --> RollCAS[VERIFIED → ROLLING_BACK]
    RollCAS --> Restore[Approved restore request]
    Restore --> VerifyRestore[READ-back semantic equivalence]
    VerifyRestore --> RolledBack[ROLLED_BACK]

    Policy[Empty production mutation policy] -. blocks .-> Write
    Warning[No executor, endpoint, capability, or tool is active] -.-> Write
```

The contract, state-machine, policy, audit, and authenticated-store boxes exist
only as isolated domain infrastructure. The dotted execution path requires
every remaining milestone in [the Tier 1 roadmap](TIER1_ROADMAP.md) and
separate capability-specific authorization before any WRITE endpoint or tool
is added.
