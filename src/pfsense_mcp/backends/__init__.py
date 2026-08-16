"""Backend-neutral READ capability interfaces (Nexus Phase A, ADR-030).

Research/design artifact only. Nothing in this package is imported by
`factory.py`, `tools/registry.py`, `application.py`, or anything under
`tier1/` -- `tests/backends/test_isolation.py` enforces this the same
way `tests/tier1/test_isolation.py` enforces Tier1's own isolation.

No concrete Nexus (or any second-backend) implementation exists here.
ADR-030's compatibility matrix found every candidate Nexus endpoint
inspected deeply enough had at least one required current-side model
field with no honest source in the Nexus schema -- writing a
"working" adapter would mean fabricating those fields, which this
project's fail-closed posture forbids. `ports.py` defines the target
shape only; implementing it is future, explicitly-authorized work.
"""
