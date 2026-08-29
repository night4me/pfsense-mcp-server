"""Regression protection for the two hand-authored, README-facing
architecture-diagram SVGs (``read-trust-path.svg``,
``write-authorization-path.svg``).

Found 2026-08-28 via direct browser inspection of the rendered README:
after a v1.0 Product/UX closure-arc fix converted both diagrams from
Mermaid's ``flowchart LR`` to ``flowchart TD`` (to fix an illegible
mobile aspect ratio), Mermaid's own fixed 16px absolute font-size no
longer scaled proportionally to the much narrower computed layout --
edge-connector labels and node text visibly clipped against their own
box/label boundaries in real rendering. Both diagrams are now generated
by ``scripts/generate_trust_diagrams.py``, which computes every box's
size directly from its own wrapped text plus explicit padding, so a
box can never be smaller than the text it contains. This test parses
the checked-in SVGs as XML (not the generator's in-memory state) and
asserts the specific properties that caused the original defect:
edge-label font size meaningfully smaller than node-title font size,
every text line's estimated width comfortably inside its containing
box, and a still-legible-at-mobile-width aspect ratio.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DIAGRAMS_DIR = ROOT / "assets" / "diagrams"
DIAGRAM_NAMES = ["read-trust-path.svg", "write-authorization-path.svg"]

SVG_NS = "{http://www.w3.org/2000/svg}"

# Mirrors scripts/generate_trust_diagrams.py's own conservative
# character-width estimate -- deliberately the same overestimate, so
# this test's "does the text fit" check uses the same safety margin
# the generator itself was designed around, not a stricter one that
# would spuriously fail on the generator's own intended output.
_CHAR_WIDTH_FACTOR = 0.60
_NODE_PAD_X = 22
_LABEL_PAD_X = 10

FONT_SIZE_RE = re.compile(r"\.node-label\s*\{[^}]*font-size:\s*([\d.]+)px")
LABEL_FONT_SIZE_RE = re.compile(r"\.edge-label\s*\{[^}]*font-size:\s*([\d.]+)px")
VIEWBOX_RE = re.compile(r'viewBox="0 0 ([\d.]+) ([\d.]+)"')


def _svg_text(name: str) -> str:
    path = DIAGRAMS_DIR / name
    assert path.is_file(), f"{path} is missing"
    return path.read_text(encoding="utf-8")


def _parse(name: str) -> ET.Element:
    return ET.fromstring(_svg_text(name))


@pytest.mark.parametrize("name", DIAGRAM_NAMES)
def test_edge_label_font_is_meaningfully_smaller_than_node_font(name: str):
    content = _svg_text(name)
    node_font = FONT_SIZE_RE.search(content)
    label_font = LABEL_FONT_SIZE_RE.search(content)
    assert node_font, f"{name} has no '.node-label' font-size declaration"
    assert label_font, f"{name} has no '.edge-label' font-size declaration"
    node_size = float(node_font.group(1))
    label_size = float(label_font.group(1))
    assert label_size < node_size, (
        f"{name}: edge-label font ({label_size}px) must be smaller than node-title font ({node_size}px) -- "
        "a same-size (or larger) edge label is exactly the defect found 2026-08-28 (labels dominating "
        "the diagram instead of being subordinate to node titles)"
    )
    assert label_size <= node_size * 0.85, (
        f"{name}: edge-label font ({label_size}px) is not meaningfully smaller than node-title font "
        f"({node_size}px) -- expected at most 85% of the node font size"
    )


def _direct_text_children(group: ET.Element) -> list[str]:
    return [child.text or "" for child in group if child.tag == f"{SVG_NS}text"]


@pytest.mark.parametrize("name", DIAGRAM_NAMES)
def test_no_text_line_overflows_its_containing_box(name: str):
    """Every `<g>` element the generator emits containing a `<rect>`/
    `<polygon>` shape immediately followed by its `<text>` line(s) is a
    node box or an edge-label background. This walks each one and
    asserts every text line is estimated to fit within the shape's own
    width (using the generator's own conservative per-character
    estimate) -- a direct, deterministic proxy for "does this text
    clip against its box", the exact defect found via real browser
    rendering on 2026-08-28."""
    root = _parse(name)
    checked = 0
    for group in root.iter(f"{SVG_NS}g"):
        rect = group.find(f"{SVG_NS}rect")
        polygon = group.find(f"{SVG_NS}polygon")
        texts = _direct_text_children(group)
        if not texts:
            continue
        is_label = rect is not None and rect.get("fill") == "#e8e8e8"
        font_size = 10.5 if is_label else 15.0
        pad = _LABEL_PAD_X if is_label else _NODE_PAD_X

        if rect is not None:
            box_width = float(rect.get("width", "0"))
        elif polygon is not None:
            xs = [float(pair.split(",")[0]) for pair in polygon.get("points", "").split()]
            box_width = (max(xs) - min(xs)) * 0.55  # diamond's usable width at mid-height only
        else:
            continue

        available = box_width - 2 * pad
        for line in texts:
            estimated_width = len(line) * font_size * _CHAR_WIDTH_FACTOR
            assert estimated_width <= available + 1.0, (
                f"{name}: text {line!r} (estimated {estimated_width:.1f}px at {font_size}px font) "
                f"does not fit within its box's available inner width ({available:.1f}px, shape width "
                f"{box_width:.1f}px) -- this is the exact clipping defect found 2026-08-28"
            )
            checked += 1
    assert checked > 0, f"{name}: no text lines were actually checked -- test logic may not be matching real content"


@pytest.mark.parametrize("name", DIAGRAM_NAMES)
def test_viewbox_is_narrow_and_tall_not_wide_and_short(name: str):
    """Guards the original C1 aspect-ratio fix this diagram already
    satisfies -- a regression back to a wide/short layout (the defect
    fixed earlier in the v1.0 Product/UX closure arc) would make the
    diagram illegible at mobile width again."""
    content = _svg_text(name)
    match = VIEWBOX_RE.search(content)
    assert match, f"{name} has no viewBox"
    width, height = float(match.group(1)), float(match.group(2))
    assert width <= 620, f"{name}: viewBox width {width}px is too wide for a README-facing diagram"
    assert height > width, f"{name}: viewBox {width}x{height} is not taller than it is wide"


@pytest.mark.parametrize("name", DIAGRAM_NAMES)
def test_svg_is_self_contained(name: str):
    """Same safety properties ADR-034 requires of every embedded
    diagram SVG -- re-asserted here since these two are no longer
    mermaid.ink output and must independently satisfy the same
    constraint, not merely inherit it."""
    content = _svg_text(name)
    assert "<script" not in content.lower()
    assert "@import" not in content
    # xmlns="http://www.w3.org/2000/svg" is a required, inert namespace
    # declaration, not a network reference -- only an actual href/src/
    # url() pointing off-host would be an external-resource dependency.
    assert 'href="http' not in content and 'src="http' not in content and "url(http" not in content
    assert "<foreignObject" not in content, f"{name}: hand-authored SVGs use plain <text>, never HTML foreignObject"
