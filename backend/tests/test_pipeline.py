"""backend/tests/test_pipeline.py — feed-isolation regression test."""

from __future__ import annotations
import httpx
import pytest
from app.data.pipeline import OSINTPipeline

GOOD_FEED = "https://feed-ok.example.test/indicators"
BAD_FEED = "https://feed-down.example.test/indicators"

# Matched to your real pipeline structure fields
VALID_INDICATOR_PAYLOAD = {
    "title": "Test Threat Advisory",
    "description": "Critical RCE exploit discovered in core framework.",
    "link": "https://feed-ok.example.test/indicators/1",
    "published": "2026-07-07T00:00:00Z"
}

@pytest.mark.asyncio
async def test_partial_feed_failure_returns_surviving_indicators(monkeypatch):
    """One feed throws httpx.ConnectError; the cycle must still return the
    other feed's validated indicator, not raise and not return an empty list.
    """
    async def fake_get(self: httpx.AsyncClient, url: str, *args, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        if url == GOOD_FEED:
            # Wrap in an RSS/Atom mock format that feedparser expects
            mock_rss = f"""<rss><channel><item>
                <title>{VALID_INDICATOR_PAYLOAD['title']}</title>
                <description>{VALID_INDICATOR_PAYLOAD['description']}</description>
                <link>{VALID_INDICATOR_PAYLOAD['link']}</link>
                <published>{VALID_INDICATOR_PAYLOAD['published']}</published>
            </item></channel></rss>"""
            return httpx.Response(200, text=mock_rss, request=request)
        if url == BAD_FEED:
            raise httpx.ConnectError("simulated feed outage", request=request)
        raise AssertionError(f"test fetched an unexpected URL: {url}")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    pipeline = OSINTPipeline(target_feeds=[GOOD_FEED, BAD_FEED])
    try:
        indicators = await pipeline.run()
    finally:
        await pipeline.close()

    assert len(indicators) == 1, "A single dead feed is poisoning the whole ingestion cycle instead of being isolated"
    assert "Test Threat Advisory" in indicators[0].title

@pytest.mark.asyncio
async def test_wholesale_outage_still_surfaces_as_an_empty_list(monkeypatch):
    """If EVERY feed is down, run() should return an empty list natively."""
    async def always_fails(self: httpx.AsyncClient, url: str, *args, **kwargs) -> httpx.Response:
        raise httpx.ConnectError("simulated total outage", request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx.AsyncClient, "get", always_fails)

    pipeline = OSINTPipeline(target_feeds=[GOOD_FEED, BAD_FEED])
    try:
        indicators = await pipeline.run()
        assert indicators == [], "expected zero indicators when every feed is down"
    finally:
        await pipeline.close()