from scripts.release_state_check import ROOT, release_checks


def test_current_release_state_documentation_is_consistent():
    """v0.4.1 is a release-repair release (fixes v0.4.0's PyPI publish
    failure and a long-standing false "v0.3.1 published" claim -- see
    CHANGELOG.md's [0.4.1] entry). Deliberately NOT yet declared "the
    immutable production baseline, published on PyPI" -- v0.3.0 remains
    the real, currently-installable release until the owner actually
    publishes v0.4.1. This one `False` is the correct, expected state at
    this checkpoint (same pattern as v0.4.0's own preparation commit).
    Update to all-True only in the same commit that also updates
    README's status paragraph to declare v0.4.1 published, immediately
    preceding the owner's own tag/publish action."""

    assert release_checks(ROOT) == {
        "docs/ACCEPTANCE_v0.4.1.md": True,
        "released changelog heading": True,
        "README immutable production baseline": False,
        "README PyPI publication status": True,
        "MIT license metadata": True,
    }
