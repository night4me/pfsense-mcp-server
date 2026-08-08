from scripts.release_state_check import ROOT, release_checks


def test_current_release_state_documentation_is_consistent():
    assert release_checks(ROOT) == {
        "docs/ACCEPTANCE_v0.2.2.md": True,
        "released changelog heading": True,
        "README immutable production baseline": True,
        "README PyPI publication status": True,
        "MIT license metadata": True,
    }
