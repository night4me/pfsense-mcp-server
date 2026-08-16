from scripts.release_state_check import ROOT, release_checks


def test_current_release_state_documentation_is_consistent():
    """v0.4.0's README status paragraph now declares it the immutable
    production baseline, published on PyPI -- this is the release-status
    commit immediately preceding the owner's own tag/publish action (see
    the prior commit's version of this docstring for why the single
    `False` was correct at that earlier checkpoint)."""

    assert release_checks(ROOT) == {
        "docs/ACCEPTANCE_v0.4.0.md": True,
        "released changelog heading": True,
        "README immutable production baseline": True,
        "README PyPI publication status": True,
        "MIT license metadata": True,
    }
