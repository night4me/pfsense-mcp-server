from scripts.release_state_check import ROOT, release_checks


def test_current_release_state_documentation_is_consistent():
    """v0.4.0 is prepared (version bumped, CHANGELOG finalized, acceptance
    doc present) but deliberately NOT yet declared "the immutable
    production baseline, published on PyPI" in README.md -- that claim
    only becomes true the moment the owner actually tags and publishes
    it, which this release-preparation commit does not do. This one
    `False` is therefore the correct, expected state at this checkpoint,
    not a bug -- `make release-check` surfacing it is exactly the
    intended "not yet ready to publish" signal. Update this assertion to
    all-True only in the same commit that also updates README's status
    paragraph to declare the new version published, immediately preceding
    (or as part of) the owner's own tag/publish action."""

    assert release_checks(ROOT) == {
        "docs/ACCEPTANCE_v0.4.0.md": True,
        "released changelog heading": True,
        "README immutable production baseline": False,
        "README PyPI publication status": True,
        "MIT license metadata": True,
    }
