"""Regression protection for README.md's PyPI long_description rendering.

Found 2026-08-23: `README.md` contained two ```mermaid fenced diagrams.
GitHub renders these natively; PyPI's long_description renderer
(`readme_renderer`, the same library `twine check` and Warehouse use)
does not -- it rendered the fence as an ordinary code block, exposing
the raw Mermaid source text on the live PyPI project page. Because
`pyproject.toml` declares `readme = "README.md"`, hatchling embeds this
file verbatim as the wheel/sdist `long_description` at build time, so
the defect was permanently baked into the already-published v0.7.1
artifact -- fixable only by publishing a corrected version, exactly
like the stale Quick-start pin `test_readme_install_version.py` guards
against.

Fixed by replacing both fences with standard Markdown image syntax
pointing at checked-in, pre-rendered SVGs referenced by an absolute
raw.githubusercontent.com URL (works on both GitHub and PyPI; a
repository-relative path would 404 on PyPI, which has no file tree of
its own). See `docs/adr/ADR-034-mermaid-pypi-compatibility.md` for the
full design and the main-branch-vs-tag URL trade-off, and
`assets/diagrams/*.mmd` for the maintained Mermaid source.

This file checks README.md's source directly (`readme = "README.md"`
in `pyproject.toml` is embedded verbatim with no transformation, so
this is exactly what reaches the built long_description) rather than
invoking a real `python -m build` here: doing so requires the calling
environment to satisfy `[build-system].requires`'s pinned
`hatchling<1.32` ceiling exactly (a deliberate ceiling below the
release that changed Core Metadata output -- see that pin's own
comment), which a plain `pip install -e ".[dev]"` environment is not
guaranteed to produce (`dev`'s own `hatchling<2.0` constraint is
looser). The actual built wheel/sdist METADATA/PKG-INFO were built and
inspected directly as a one-time verification for this change instead
(see the ADR and the corresponding task report for that evidence,
including a real `readme_renderer`-based render and `twine check
--strict`) -- not repeated on every test run, to keep this file free of
that environment dependency.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
DIAGRAMS_DIR = ROOT / "assets" / "diagrams"

_MERMAID_FENCE = re.compile(r"```mermaid")
_IMAGE_LINE = re.compile(r"!\[[^]]*]\((?P<url>[^)]+)\)")
_EXPECTED_DIAGRAM_URLS = (
    "https://raw.githubusercontent.com/night4me/pfsense-mcp-server/main/assets/diagrams/read-trust-path.svg",
    "https://raw.githubusercontent.com/night4me/pfsense-mcp-server/main/assets/diagrams/write-authorization-path.svg",
)


def test_readme_source_has_no_mermaid_fence():
    text = README.read_text(encoding="utf-8")
    assert not _MERMAID_FENCE.search(text), (
        "README.md contains a ```mermaid fence -- GitHub renders it, but PyPI's long_description "
        "renderer does not (found 2026-08-23; see docs/adr/ADR-034-mermaid-pypi-compatibility.md). "
        "Replace it with a checked-in static image, as done for the two existing diagrams."
    )


def test_pyproject_embeds_readme_verbatim_with_no_transformation():
    """The whole regression-protection argument above depends on this:
    hatchling embeds `readme = "README.md"` byte-for-byte as
    long_description, so checking README.md's source is equivalent to
    checking what PyPI receives. If this ever becomes a computed/dynamic
    readme, that assumption breaks and this test file's other checks
    would need a real build again."""

    pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'readme = "README.md"' in pyproject_text


def test_readme_references_both_expected_diagram_images_by_absolute_url():
    text = README.read_text(encoding="utf-8")
    found = {match.group("url") for match in _IMAGE_LINE.finditer(text)}
    for expected in _EXPECTED_DIAGRAM_URLS:
        assert expected in found, (
            f"README.md no longer references {expected!r} -- if a diagram was intentionally removed or "
            "renamed, update _EXPECTED_DIAGRAM_URLS here to match; if not, this is a regression."
        )


def test_readme_never_uses_a_relative_path_for_a_diagram_image():
    """A relative path renders on GitHub (which resolves it against the
    repo tree) but 404s on PyPI (which has no file tree at all, only the
    long_description text) -- see ADR-034 for the full reasoning."""

    text = README.read_text(encoding="utf-8")
    for match in _IMAGE_LINE.finditer(text):
        url = match.group("url")
        if "assets/diagrams" in url:
            assert url.startswith("https://raw.githubusercontent.com/"), (
                f"README.md references a diagram image with a non-absolute URL ({url!r}) -- this "
                "would 404 on PyPI's long_description, which has no repository file tree to resolve "
                "a relative path against."
            )


@pytest.mark.parametrize(
    "name",
    [Path(url).name for url in _EXPECTED_DIAGRAM_URLS],
)
def test_diagram_svg_is_self_contained_with_no_script_or_external_reference(name: str):
    svg_path = DIAGRAMS_DIR / name
    assert svg_path.is_file(), f"{svg_path} referenced by README.md but missing from the repository"
    content = svg_path.read_text(encoding="utf-8")
    assert "<script" not in content.lower(), f"{svg_path} contains a <script> tag -- must not, it is embedded via <img>"
    assert "cdnjs.cloudflare.com" not in content, (
        f"{svg_path} references an external CDN (likely an unused Font Awesome @import mermaid-cli-style "
        "renderers inject by default) -- strip it so the shipped SVG has zero external references"
    )
    assert "@import" not in content, f"{svg_path} contains an external stylesheet @import"


@pytest.mark.parametrize(
    "name",
    [Path(url).name for url in _EXPECTED_DIAGRAM_URLS],
)
def test_diagram_has_a_maintained_mermaid_source_file(name: str):
    mmd_path = DIAGRAMS_DIR / name.replace(".svg", ".mmd")
    assert mmd_path.is_file(), (
        f"{mmd_path} is missing -- every checked-in diagram SVG must have a corresponding .mmd source "
        "file (the maintainable source of truth an editor regenerates the SVG from), per ADR-034"
    )
    assert mmd_path.read_text(encoding="utf-8").strip(), f"{mmd_path} exists but is empty"
