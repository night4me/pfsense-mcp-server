"""Deterministic, hand-authored replacement for the two small README-facing
architecture diagrams (``read-trust-path.svg``, ``write-authorization-path.svg``).

Why not mermaid.ink (ADR-034 documents the general PyPI-safe *embedding*
pattern this project still uses for both these images and
``docs/ARCHITECTURE_DIAGRAMS.md``'s own, separately-rendered diagrams --
this script only replaces how these two specific SVGs are *generated*,
not the embedding pattern itself): found 2026-08-28, via direct browser
inspection of the rendered README, that converting these two diagrams
from ``flowchart LR`` to ``flowchart TD`` (a v1.0 Product/UX
closure-arc fix for a mobile-aspect-ratio defect -- a 2341x118px wide
diagram scaled to ~19px tall on a phone) fixed the aspect ratio but
introduced a *new* defect. Mermaid renders all text at one fixed
absolute font-size (16px) regardless of how narrow the computed layout
ends up being, so relative to the new ~250px-wide canvas, node text --
and especially edge-connector labels, whose background pill is sized
tightly around the label text with no separate smaller font of its own
-- visibly clipped against their own containing box/label background
in real rendering.

This script replaces both diagrams with fully hand-computed geometry:
node title text and edge-label text use different, explicitly chosen
font sizes (labels meaningfully smaller and unobtrusive, unlike
Mermaid's default where both were identical); every box's width and
height are computed from its own wrapped text using a conservative
per-character width estimate (see ``_CHAR_WIDTH_FACTOR`` below) plus
generous padding, so a box is never sized smaller than the text it
contains. ``tests/test_trust_diagram_typography.py`` asserts these
invariants (font-size ratio, computed text-vs-box fit, viewBox
aspect ratio) directly against the checked-in SVGs so a future
regeneration cannot silently reintroduce the same defect.

Run ``python scripts/generate_trust_diagrams.py`` from the repository
root to regenerate both SVGs in place.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIAGRAMS_DIR = ROOT / "assets" / "diagrams"

FONT_STACK = "Segoe UI, Helvetica, Arial, sans-serif"

NODE_FONT_SIZE = 15
LABEL_FONT_SIZE = 10.5  # deliberately well below NODE_FONT_SIZE -- see module docstring
NODE_LINE_HEIGHT = 20
LABEL_LINE_HEIGHT = 14

# Conservative average character-advance width for a proportional
# sans-serif font, as a fraction of font-size. Real Helvetica/Arial
# metrics average closer to 0.50-0.55em for mixed-case English text;
# 0.60 is deliberately an overestimate (safety margin against actually
# clipping, the exact defect this script exists to eliminate) -- no
# font-metrics library is available in this environment to measure
# exactly, so erring wide is the safe direction.
_CHAR_WIDTH_FACTOR = 0.60

NODE_PAD_X = 22
NODE_PAD_Y = 16
LABEL_PAD_X = 10
LABEL_PAD_Y = 6

DEFAULT_NODE_FILL = "#ECECFF"
DEFAULT_NODE_STROKE = "#9370DB"
ARROW_STROKE = "#333333"
LABEL_BG = "#e8e8e8"
LABEL_TEXT_COLOR = "#555555"

V_GAP = 46  # vertical gap between stacked node boxes
BRANCH_GAP = 24  # horizontal gap between two side-by-side branch boxes


def _text_width(text: str, font_size: float) -> float:
    return len(text) * font_size * _CHAR_WIDTH_FACTOR


def _wrap_to_width(text: str, font_size: float, max_width: float) -> list[str]:
    max_chars = max(int(max_width / (font_size * _CHAR_WIDTH_FACTOR)), 8)
    wrapped: list[str] = []
    for paragraph in text.split("\n"):
        wrapped.extend(textwrap.wrap(paragraph, width=max_chars) or [""])
    return wrapped


@dataclass
class Node:
    text: str
    fill: str = DEFAULT_NODE_FILL
    stroke: str = DEFAULT_NODE_STROKE
    shape: str = "rect"  # "rect" or "diamond"
    lines: list[str] = field(default_factory=list, init=False)
    width: float = field(default=0.0, init=False)
    height: float = field(default=0.0, init=False)
    x: float = field(default=0.0, init=False)
    y: float = field(default=0.0, init=False)


def _layout_node(node: Node, box_width: float) -> None:
    inner_width = box_width - 2 * NODE_PAD_X
    node.lines = _wrap_to_width(node.text, NODE_FONT_SIZE, inner_width)
    node.width = box_width
    if node.shape == "diamond":
        # A diamond's usable horizontal span at mid-height only -- give
        # it generous extra width/height so wrapped text never nears a
        # sloped edge.
        node.width = box_width * 1.35
        node.height = len(node.lines) * NODE_LINE_HEIGHT + 2 * NODE_PAD_Y + 24
    else:
        node.height = len(node.lines) * NODE_LINE_HEIGHT + 2 * NODE_PAD_Y


def _widest_required_box(nodes: list[Node], min_width: float = 190) -> float:
    widest = min_width
    for node in nodes:
        # A single unwrapped line's natural width, for nodes short
        # enough not to need wrapping at all.
        natural = _text_width(node.text.replace("\n", " "), NODE_FONT_SIZE) + 2 * NODE_PAD_X
        widest = max(widest, min(natural, 320))
    return widest


def _node_svg(node: Node, cx: float, cy: float) -> str:
    x = cx - node.width / 2
    y = cy - node.height / 2
    text_lines = []
    start_y = cy - (len(node.lines) - 1) * NODE_LINE_HEIGHT / 2
    for i, line in enumerate(node.lines):
        ty = start_y + i * NODE_LINE_HEIGHT
        text_lines.append(
            f'<text x="{cx:.1f}" y="{ty:.1f}" text-anchor="middle" dominant-baseline="middle">{_escape(line)}</text>'
        )
    if node.shape == "diamond":
        points = f"{cx:.1f},{y:.1f} {x + node.width:.1f},{cy:.1f} {cx:.1f},{y + node.height:.1f} {x:.1f},{cy:.1f}"
        shape_svg = f'<polygon points="{points}" fill="{node.fill}" stroke="{node.stroke}" stroke-width="1.5"/>'
    else:
        shape_svg = (
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{node.width:.1f}" height="{node.height:.1f}" rx="6" '
            f'fill="{node.fill}" stroke="{node.stroke}" stroke-width="1.5"/>'
        )
    return f"<g>{shape_svg}{''.join(text_lines)}</g>"


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _arrow_svg(x1: float, y1: float, x2: float, y2: float, *, dashed: bool = False) -> str:
    dash = ' stroke-dasharray="4,3"' if dashed else ""
    return (
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
        f'stroke="{ARROW_STROKE}" stroke-width="1.5"{dash} marker-end="url(#arrowhead)"/>'
    )


def _edge_label_svg(text: str, cx: float, cy: float) -> tuple[str, float]:
    lines = _wrap_to_width(text, LABEL_FONT_SIZE, 150)
    width = max(_text_width(line, LABEL_FONT_SIZE) for line in lines) + 2 * LABEL_PAD_X
    height = len(lines) * LABEL_LINE_HEIGHT + 2 * LABEL_PAD_Y
    x = cx - width / 2
    y = cy - height / 2
    start_y = cy - (len(lines) - 1) * LABEL_LINE_HEIGHT / 2
    text_svg = "".join(
        f'<text x="{cx:.1f}" y="{start_y + i * LABEL_LINE_HEIGHT:.1f}" text-anchor="middle" '
        f'dominant-baseline="middle" class="edge-label">{_escape(line)}</text>'
        for i, line in enumerate(lines)
    )
    rect = f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="{height:.1f}" rx="3" fill="{LABEL_BG}"/>'
    return f"<g>{rect}{text_svg}</g>", height


_SVG_HEAD = """<svg id="{svg_id}" width="100%" xmlns="http://www.w3.org/2000/svg" class="flowchart" \
style="max-width: {max_width:.0f}px;" viewBox="0 0 {view_width:.1f} {view_height:.1f}" \
role="graphics-document document" aria-labelledby="{svg_id}Title">
<title id="{svg_id}Title">{title}</title>
<defs>
<marker id="arrowhead" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" \
orient="auto-start-reverse">
<path d="M 0 0 L 10 5 L 0 10 z" fill="{arrow_stroke}"/>
</marker>
</defs>
<style>
#{svg_id} text {{ font-family: {font_stack}; }}
#{svg_id} .node-label {{ font-size: {node_font_size}px; fill: #1a1a1a; }}
#{svg_id} .edge-label {{ font-size: {label_font_size}px; fill: {label_text_color}; font-style: italic; }}
</style>
<g class="node-label">
"""


def _render_linear_diagram(
    *,
    svg_id: str,
    title: str,
    nodes: list[Node],
    edge_labels: dict[int, str],
    dashed_edges: set[int] | None = None,
) -> str:
    """Nodes stacked top-to-bottom in a single column. edge_labels maps
    the index of the *source* node (0-based) to a label shown on the
    arrow leaving it."""
    dashed_edges = dashed_edges or set()
    box_width = _widest_required_box(nodes)
    for node in nodes:
        _layout_node(node, box_width)

    view_width = box_width + 40
    cx = view_width / 2

    y: float = 20
    body: list[str] = []
    positions: list[tuple[float, float]] = []
    for i, node in enumerate(nodes):
        cy = y + node.height / 2
        node.x, node.y = cx, cy
        positions.append((cx, cy))
        body.append(_node_svg(node, cx, cy))
        y += node.height
        if i < len(nodes) - 1:
            gap_top = y
            label = edge_labels.get(i)
            if label:
                label_svg, _label_height = _edge_label_svg(label, cx, gap_top + V_GAP / 2)
                body.append(_arrow_svg(cx, gap_top, cx, gap_top + V_GAP, dashed=i in dashed_edges))
                body.append(label_svg)
            else:
                body.append(_arrow_svg(cx, gap_top, cx, gap_top + V_GAP, dashed=i in dashed_edges))
            y += V_GAP

    view_height = y + 10
    return _assemble(svg_id, title, view_width, view_height, box_width, body)


def _assemble(svg_id: str, title: str, view_width: float, view_height: float, max_width: float, body: list[str]) -> str:
    head = _SVG_HEAD.format(
        svg_id=svg_id,
        title=_escape(title),
        max_width=max_width + 40,
        view_width=view_width,
        view_height=view_height,
        font_stack=FONT_STACK,
        node_font_size=NODE_FONT_SIZE,
        label_font_size=LABEL_FONT_SIZE,
        label_text_color=LABEL_TEXT_COLOR,
        arrow_stroke=ARROW_STROKE,
    )
    return head + "".join(body) + "</g></svg>\n"


def _generate_read_trust_path() -> str:
    nodes = [
        Node("AI / MCP client", fill="#eeeeee", stroke="#333333"),
        Node("Explicit registered MCP tool (1 of 95, no dispatcher)"),
        Node("Capability / profile gate (auditor: READ only)", fill="#fff3cd", stroke="#856404"),
        Node("Least-privilege mapping (exact pfSense privilege)", fill="#fff3cd", stroke="#856404"),
        Node("One fixed typed client method"),
        Node("pfREST GET (GET-only, enforced)"),
        Node("pfSense appliance", fill="#eeeeee", stroke="#333333"),
        Node("Typed model boundary (secret fields excluded by construction)", fill="#d1e7dd", stroke="#0f5132"),
        Node("Safe MCP result"),
    ]
    edge_labels = {0: "stdio (trust boundary)"}
    return _render_linear_diagram(
        svg_id="readTrustPath",
        title="pfsense-mcp-server: READ tool trust path, client to appliance and back",
        nodes=nodes,
        edge_labels=edge_labels,
    )


def _generate_write_authorization_path() -> str:
    main_chain_texts = [
        "Default profile: 0 WRITE tools (not reachable)",
        "write_protected profile + full Tier 1 material provisioned",
        "Off-host signed authorization + confirmation (separate identities)",
        "6 fail-closed gates (signature, expiry, digest, freshness, one-time use)",
        "Sealed MutationExecutor (only path that ever sends)",
        "Authoritative read-back",
    ]
    box_width = _widest_required_box([Node(text) for text in main_chain_texts])

    def n(text: str, **kw: str) -> Node:
        node = Node(text, **kw)
        _layout_node(node, box_width)
        return node

    a = n("Default profile: 0 WRITE tools (not reachable)", fill="#f8d7da", stroke="#842029")
    b = n("write_protected profile + full Tier 1 material provisioned")
    c = n("Off-host signed authorization + confirmation (separate identities)")
    d = n("6 fail-closed gates (signature, expiry, digest, freshness, one-time use)")
    e = n("Sealed MutationExecutor (only path that ever sends)", fill="#cfe2ff", stroke="#084298")
    f = n("Authoritative read-back")
    g = n("Outcome?", shape="diamond")

    # H and I are sized to their own content, independently of the main
    # chain's box_width -- forcing "VERIFIED" to the same width as
    # "6 fail-closed gates (...)" would waste horizontal space this
    # branch row doesn't need.
    h = Node("VERIFIED", fill="#d1e7dd", stroke="#0f5132")
    i = Node("RECONCILIATION (never blind retry)", fill="#fff3cd", stroke="#856404")
    _layout_node(h, _widest_required_box([h], min_width=120))
    _layout_node(i, _widest_required_box([i], min_width=120))

    branch_row_width = h.width + BRANCH_GAP + i.width
    view_width = max(box_width, g.width, branch_row_width) + 40
    cx = view_width / 2

    y: float = 20
    body: list[str] = []
    for node in [a, b, c, d, e, f, g]:
        cy = y + node.height / 2
        node.x, node.y = cx, cy
        body.append(_node_svg(node, cx, cy))
        y += node.height
        if node is a:
            gap_top = y
            label_svg, _ = _edge_label_svg("explicit operator\nopt-in required", cx, gap_top + V_GAP / 2)
            body.append(_arrow_svg(cx, gap_top, cx, gap_top + V_GAP, dashed=True))
            body.append(label_svg)
            y += V_GAP
        elif node is not g:
            gap_top = y
            body.append(_arrow_svg(cx, gap_top, cx, gap_top + V_GAP))
            y += V_GAP

    # Branch out of the diamond G into H (left, "confirmed") and I
    # (right, "ambiguous"), side by side.
    branch_top = y + V_GAP
    left_cx = cx - branch_row_width / 2 + h.width / 2
    right_cx = cx + branch_row_width / 2 - i.width / 2
    h.x, h.y = left_cx, branch_top + h.height / 2
    i.x, i.y = right_cx, branch_top + i.height / 2

    g_bottom = g.y + g.height / 2
    body.append(_arrow_svg(cx, g_bottom, left_cx, h.y - h.height / 2))
    body.append(_arrow_svg(cx, g_bottom, right_cx, i.y - i.height / 2))

    left_label_svg, _ = _edge_label_svg("confirmed", (cx + left_cx) / 2, g_bottom + (branch_top - g_bottom) / 2)
    right_label_svg, _ = _edge_label_svg("ambiguous", (cx + right_cx) / 2, g_bottom + (branch_top - g_bottom) / 2)
    body.append(left_label_svg)
    body.append(right_label_svg)

    body.append(_node_svg(h, h.x, h.y))
    body.append(_node_svg(i, i.x, i.y))

    view_height = branch_top + max(h.height, i.height) + 20
    return _assemble(
        "writeAuthorizationPath",
        "pfsense-mcp-server: WRITE authorization path, opt-in to verified outcome",
        view_width,
        view_height,
        view_width - 40,
        body,
    )


def main() -> None:
    (DIAGRAMS_DIR / "read-trust-path.svg").write_text(_generate_read_trust_path(), encoding="utf-8")
    (DIAGRAMS_DIR / "write-authorization-path.svg").write_text(_generate_write_authorization_path(), encoding="utf-8")
    print("Regenerated read-trust-path.svg and write-authorization-path.svg")


if __name__ == "__main__":
    main()
