## Summary

<!-- Explain the problem and the focused change. -->

## Compatibility and security

- Public API changed: no
- Capability or endpoint set changed: no
- WRITE capability activated: no
- Live pfSense access performed: no
- Credential or identifying appliance data included: no

<!-- Explain every "yes" response and link the explicit project approval. -->

## Verification

<!-- List only checks actually executed. Typical local gates: -->

- [ ] Ruff format and check
- [ ] mypy
- [ ] full offline pytest suite
- [ ] `make quick`
- [ ] `make validate`
- [ ] Relevant security, fixture, packaging, or coverage checks

## Documentation and tests

- [ ] Tests cover the changed behaviour and negative security properties.
- [ ] User-facing or architecture documentation is updated where necessary.
- [ ] The change contains no private fixtures, raw responses, credentials, or unsanitized logs.

## Reviewer notes

<!-- Call out residual risk, intentionally deferred work, or manual checks. -->
