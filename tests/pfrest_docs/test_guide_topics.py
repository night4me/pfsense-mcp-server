from __future__ import annotations

from pfsense_mcp.pfrest_docs.guide_topics import MAX_EXCERPT_LENGTH, GuideTopic, extract_excerpt, guide_topic_url


def test_guide_topic_url_is_https_pfrest_org():
    for topic in GuideTopic:
        url = guide_topic_url(topic)
        assert url.startswith("https://pfrest.org/")
        assert url.endswith("/")


def test_extract_excerpt_isolates_main_content_and_strips_html():
    html = (
        "<html><body>"
        '<div class="wy-nav-content"><div class="rst-content">'
        '<div role="main" class="document" itemscope="itemscope">'
        "<h1>Title</h1><p>Real content here.</p>"
        '</div><div class="rst-footer-buttons">nav junk</div>'
        "</div></div></body></html>"
    )
    excerpt = extract_excerpt(html)
    assert "Real content here." in excerpt
    assert "nav junk" not in excerpt
    assert "<p>" not in excerpt


def test_extract_excerpt_falls_back_when_main_marker_absent():
    html = "<html><body><p>No main marker here.</p></body></html>"
    excerpt = extract_excerpt(html)
    assert "No main marker here." in excerpt


def test_extract_excerpt_is_bounded():
    html = '<div role="main" class="document">' + ("x" * (MAX_EXCERPT_LENGTH * 5)) + "</div>"
    excerpt = extract_excerpt(html)
    assert len(excerpt) <= MAX_EXCERPT_LENGTH


def test_extract_excerpt_never_raises_on_malformed_html():
    for bad in ("", '<div role="main"', "<<<>>>", "\x00\x01\x02", "a" * 100000):
        excerpt = extract_excerpt(bad)
        assert isinstance(excerpt, str)


def test_extract_excerpt_strips_script_tags():
    html = '<div role="main" class="document"><script>alert(1)</script>Safe text</div>'
    excerpt = extract_excerpt(html)
    assert "<script>" not in excerpt
    assert "Safe text" in excerpt
