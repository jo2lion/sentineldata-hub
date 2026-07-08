"""backend/tests/test_pipeline.py — feed-isolation and datetime-hardening regression tests."""

from __future__ import annotations
from datetime import datetime, timezone

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


# --------------------------------------------------------------------------- #
# Datetime-hardening regression test.
#
# A prior pass added format="mixed" to the pd.to_datetime call inside
# _process_batch. This guards against a real, empirically-verified silent
# data-corruption bug in pandas' RFC822 date parsing -- and this test's exact
# payload below was itself empirically verified against this project's
# actual pandas 3.0.2 runtime (both with and without format="mixed") before
# being committed here, not hand-guessed. That verification also corrected
# an earlier, less precise understanding of the trigger condition, worth
# stating plainly rather than leaving the wrong mental model in place:
#
# The bug is NOT simply "two entries in the same batch have different
# weekday abbreviations." Pairs of RFC822 strings with correct, internally-
# consistent weekday/date pairings parse fine together via pandas' format
# guesser regardless of how many different weekdays are mixed in -- pandas
# correctly recognizes the weekday position as a genuine %a token in that
# case. The actual trigger is narrower and nastier: it fires when the FIRST
# entry pandas samples has an INTERNALLY INCONSISTENT weekday -- i.e. its
# weekday name does not match the weekday its own day/month/year actually
# fall on (verified directly: `pd.to_datetime([...], errors="raise")` on
# such a payload surfaces the literal guessed format as
# "Tue, %d %b %Y %H:%M:%S GMT" -- "Tue" frozen in as a fixed literal
# character sequence, not recognized as the %a token it should be, because
# the guesser's own consistency check on that first value failed). Once
# that happens, pandas locks the ENTIRE batch to that broken literal format
# for the rest of the parse -- every other entry, even ones with perfectly
# correct, self-consistent weekday/date pairs, then fails to match and
# silently becomes NaT under errors="coerce", with zero warning.
#
# This is a realistic failure mode, not a contrived one: a weekday/date
# mismatch like this is exactly what a timezone-conversion bug in an
# upstream feed generator produces -- e.g. converting a local timestamp to
# UTC shifts the calendar date across midnight, but the generator's template
# recomputes the offset without recomputing the weekday name that was
# derived from the pre-conversion local date. One such malformed entry
# anywhere in a batch (not necessarily the "worst" one, just whichever one
# pandas samples first) silently corrupts the observed_at timestamp of every
# other, perfectly valid entry ingested in that same cycle.
#
# THIS IS ALSO WHY THE ASSERTIONS BELOW CHECK EXACT TIMESTAMP EQUALITY, NOT
# JUST "not NaT": by the time _process_batch returns, every NaT has already
# been silently replaced by its own `.fillna(datetime.now(timezone.utc))` --
# a naive `assert not df["observed_at"].isna().any()` would trivially always
# pass whether or not the underlying bug is present, since there are no NaT
# values left to find once fillna has already run. The only way to actually
# detect this regression is to assert each entry's observed_at matches its
# expected, known, far-in-the-past (January 2019) timestamp exactly -- if
# format="mixed" regresses out and an entry falls back to "now" instead, that
# fallback will be off by years from January 2019, not off by some ambiguous
# rounding error, so there is no risk of a coincidental pass.
#
# Exercises _parse_and_vectorize + _process_batch directly, not run(): those
# two methods are where the pandas datetime parsing under test actually
# happens. run() would additionally require a real event loop, a real SQLite
# database, and network-level feed-fetch mocking -- already covered by the
# two feed-isolation tests above, and unrelated scope for a test whose whole
# purpose is the date-parsing step in isolation.
#
# One honest caveat about the CISA feed mock below: feedparser itself isn't
# installed in the sandbox this test was authored in (no PyPI network access
# there), so the claim that feedparser's `entry.published` preserves an RSS
# <pubDate> value close to its original raw text is based on feedparser's
# long-documented, standard behavior, not on an execution trace captured in
# that sandbox. The pandas-level parsing behavior this test actually
# verifies (the format="mixed" fix itself) WAS independently, empirically
# confirmed there. Run this test for real (feedparser is already a locked
# project dependency) as the actual end-to-end confirmation.
# --------------------------------------------------------------------------- #

# Item 1's <pubDate> deliberately claims "Tue" for 07 Jan 2019, which is
# actually a Monday -- modeling the realistic upstream-feed weekday/date
# mismatch described above. Items 2-4 have correct, self-consistent
# weekday/date pairs, proving the bug is not merely "different weekdays
# present" -- it's specifically triggered by the first sampled entry being
# internally inconsistent.
CISA_MULTI_ADVISORY_RSS_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CISA Cybersecurity Advisories</title>
    <item>
      <title>CVE-2019-90001: Critical Remote Code Execution in Widget Industrial Controller</title>
      <link>https://www.cisa.gov/news-events/ics-advisories/icsa-19-007-01</link>
      <description>CISA is aware of a critical remote code execution vulnerability affecting Widget Industrial Controller firmware prior to 4.2.1.</description>
      <pubDate>Tue, 07 Jan 2019 08:00:00 GMT</pubDate>
    </item>
    <item>
      <title>CVE-2019-90002: High Severity Injection Flaw in Acme Gateway</title>
      <link>https://www.cisa.gov/news-events/ics-advisories/icsa-19-009-02</link>
      <description>A high severity injection vulnerability has been identified in Acme Gateway devices.</description>
      <pubDate>Wed, 09 Jan 2019 14:30:00 GMT</pubDate>
    </item>
    <item>
      <title>CVE-2019-90003: Medium Severity Patch Advisory for Contoso PLC</title>
      <link>https://www.cisa.gov/news-events/ics-advisories/icsa-19-011-03</link>
      <description>A medium severity vulnerability requiring a firmware patch has been disclosed for Contoso PLC.</description>
      <pubDate>Fri, 11 Jan 2019 19:45:00 GMT</pubDate>
    </item>
    <item>
      <title>CVE-2019-90004: Critical Exploit Chain in Fabrikam SCADA Suite</title>
      <link>https://www.cisa.gov/news-events/ics-advisories/icsa-19-013-04</link>
      <description>An actively exploited critical vulnerability chain has been discovered in Fabrikam SCADA Suite.</description>
      <pubDate>Sun, 13 Jan 2019 03:15:00 GMT</pubDate>
    </item>
  </channel>
</rss>"""

EXPECTED_OBSERVED_AT_BY_LINK = {
    "https://www.cisa.gov/news-events/ics-advisories/icsa-19-007-01": datetime(2019, 1, 7, 8, 0, 0, tzinfo=timezone.utc),
    "https://www.cisa.gov/news-events/ics-advisories/icsa-19-009-02": datetime(2019, 1, 9, 14, 30, 0, tzinfo=timezone.utc),
    "https://www.cisa.gov/news-events/ics-advisories/icsa-19-011-03": datetime(2019, 1, 11, 19, 45, 0, tzinfo=timezone.utc),
    "https://www.cisa.gov/news-events/ics-advisories/icsa-19-013-04": datetime(2019, 1, 13, 3, 15, 0, tzinfo=timezone.utc),
}


def test_process_batch_parses_mixed_weekday_rfc822_dates_without_dropping_to_nat():
    """
    Regression guard for the pandas format-inference bug fixed in
    _process_batch (format="mixed" on the pd.to_datetime call). See the
    module comment above this test for the full mechanism, why the mock
    payload's first entry has a deliberately inconsistent weekday, and why
    this asserts exact timestamp equality rather than a bare "not NaT" check.

    Not marked @pytest.mark.asyncio: _parse_and_vectorize and _process_batch
    are plain synchronous methods (no network I/O, no event loop) -- only
    run() is async, and this test deliberately does not go through run().
    """
    pipeline = OSINTPipeline(target_feeds=[])

    raw_df = pipeline._parse_and_vectorize([CISA_MULTI_ADVISORY_RSS_PAYLOAD])
    assert len(raw_df) == 4, (
        f"expected all 4 CISA advisory <item> entries to survive feed parsing, got {len(raw_df)}"
    )

    processed_df = pipeline._process_batch(raw_df)
    assert len(processed_df) == 4, (
        "expected all 4 entries to survive _process_batch's deduplication -- "
        "if this drops below 4, the four deterministic UUIDv5 ids collided, "
        "which would itself indicate a different, separate bug"
    )

    for _, row in processed_df.iterrows():
        expected = EXPECTED_OBSERVED_AT_BY_LINK[row["source_url"]]
        actual = row["observed_at"].to_pydatetime()

        # Exact equality, not "close enough" or "not NaT" -- see the module
        # comment above for why a looser check would not actually catch the
        # regression this test exists to guard against.
        assert actual == expected, (
            f"observed_at for {row['source_url']!r} was {actual.isoformat()}, "
            f"expected {expected.isoformat()}. If this drifted to something "
            f"close to the current wall-clock time instead, this entry "
            f"silently NaT'd out of pd.to_datetime and was backfilled by "
            f"_process_batch's `.fillna(datetime.now(timezone.utc))` -- the "
            f"exact silent-data-corruption bug format=\"mixed\" exists to "
            f"prevent. Check that pd.to_datetime(..., format=\"mixed\") is "
            f"still present in _process_batch."
        )
        assert actual.tzinfo is not None, (
            f"observed_at for {row['source_url']!r} is naive -- "
            f"ThreatIndicator.observed_at's own validator would reject this "
            f"downstream with a ValidationError; catching it here at the "
            f"DataFrame stage gives a more direct failure closer to the cause."
        )