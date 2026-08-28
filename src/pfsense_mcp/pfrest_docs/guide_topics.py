"""Guide-topic page parsing: pfREST's narrative documentation pages
(distinct from the OpenAPI reference), e.g.
https://pfrest.org/AUTHENTICATION_AND_AUTHORIZATION/
(pfREST_LIVE_GUIDANCE_ARC Phase 1/6).

`GuideTopic` is a closed enum of pages independently verified live
(2026-08-28) to exist and return `200 text/html` -- never a
caller-supplied path. Extending this enum is a reviewed, deliberate
diff, exactly like extending `fetch.ALLOWED_HOSTS`.

The real page is a full mkdocs/Read-the-Docs-themed HTML document with
a large navigation sidebar; `extract_excerpt()` isolates the actual
article content (the `<div role="main" class="document" ...>` region,
verified present on every checked page) before stripping HTML, so the
returned excerpt is the page's real prose, not several hundred
navigation-link words first.
"""

from __future__ import annotations

import html
import re
from enum import Enum

MAX_EXCERPT_LENGTH = 1500

_TAG_PATTERN = re.compile(r"<[^>]+>")
_WHITESPACE_PATTERN = re.compile(r"\s+")
_MAIN_START_PATTERN = re.compile(r'<div[^>]*role="main"[^>]*>', re.IGNORECASE)
_END_MARKERS = ("rst-footer-buttons", "<footer")


class GuideTopic(str, Enum):
    AUTHENTICATION_AND_AUTHORIZATION = "AUTHENTICATION_AND_AUTHORIZATION"
    WORKING_WITH_OBJECT_IDS = "WORKING_WITH_OBJECT_IDS"
    QUERIES_FILTERS_AND_SORTING = "QUERIES_FILTERS_AND_SORTING"
    COMMON_CONTROL_PARAMETERS = "COMMON_CONTROL_PARAMETERS"
    WORKING_WITH_HATEOAS = "WORKING_WITH_HATEOAS"
    SWAGGER_AND_OPENAPI = "SWAGGER_AND_OPENAPI"


def guide_topic_url(topic: GuideTopic) -> str:
    return f"https://pfrest.org/{topic.value}/"


def extract_excerpt(html_document: str) -> str:
    """Isolate the real article content and return a bounded, plain-text
    excerpt. Falls back to stripping the whole document (still bounded)
    if the expected content markers are not found -- never raises on an
    unexpected page shape."""

    start_match = _MAIN_START_PATTERN.search(html_document)
    if start_match is None:
        return _strip(html_document)[:MAX_EXCERPT_LENGTH]

    start = start_match.end()
    end_positions = [pos for marker in _END_MARKERS if (pos := html_document.find(marker, start)) != -1]
    end = min(end_positions) if end_positions else len(html_document)
    return _strip(html_document[start:end])[:MAX_EXCERPT_LENGTH]


def _strip(raw: str) -> str:
    without_tags = _TAG_PATTERN.sub(" ", raw)
    unescaped = html.unescape(without_tags)
    return _WHITESPACE_PATTERN.sub(" ", unescaped).strip()
