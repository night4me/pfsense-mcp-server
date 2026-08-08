"""Disposable-lab tooling for Tier 1 acceptance evidence.

Not packaged (excluded from both the wheel and sdist by pyproject.toml's
explicit include lists — neither lists `lab/`), not collected by
pytest's default run (`pyproject.toml`'s `addopts` ignores this
directory), and never imported by `src/pfsense_mcp` or `tests/`. See
docs/tier1/specs/disposable_lab_execution_model.md for the full
specification this package implements.

Live execution against a real disposable lab VM requires separate,
explicit command-level approval per `docs/TIER1_ROADMAP.md` Milestone 8
— implementing and offline-testing this package does not imply that
approval. See docs/adr/ADR-016-alias-candidate-lab-authorization.md for
the research authorization that unblocked this package's implementation.
"""
