import asyncio
import json
import logging
import os
from datetime import datetime, timezone, timedelta
import hashlib
import uuid
from typing import List, Dict, Any, Optional
import feedparser
import httpx
import pandas as pd
from pydantic import ValidationError

from app.models.threat import ThreatIndicator
# --- PHASE 5: DATABASE IMPORTS ---
from sqlalchemy.orm import Session
from sqlalchemy.dialects.sqlite import insert as sqlite_upsert
from app.database.connection import SessionLocal
from app.database.models import ThreatIndicatorModel

# Explicit logging schema setup for system tracking
logger = logging.getLogger("sentineldata.pipeline")


def _summarize_critical_impact(indicators: List[ThreatIndicator]) -> Dict[str, Any]:
    """
    Builds the isolated, pre-computed impact-summary field for the critical
    webhook payload -- deliberately NOT left for the webhook receiver to
    derive by looping the raw `threats` array itself. Whatever is on the
    other end of SENTINEL_WEBHOOK_URL (Slack, Discord, PagerDuty, a bare
    logging sink) should not have to reimplement "how bad is this cycle"
    from a list of records -- that's exactly the kind of derived logic that
    quietly drifts between N different downstream consumers if it isn't
    computed once, here, and shipped as data alongside the raw list.

    Pure and side-effect-free -- no I/O, no logging -- safe to unit test
    directly without any network mocking. Callers must pass an already-
    filtered, non-empty critical (risk_score >= 5.0) list; this function
    does not itself re-validate that (dispatch_webhook_alert does, at the
    one call site that matters -- see its own docstring).
    """
    risk_scores = [indicator.risk_score for indicator in indicators]
    distinct_sources = {indicator.source_url for indicator in indicators}
    return {
        "headline": (
            f"{len(indicators)} critical-severity threat"
            f"{'s' if len(indicators) != 1 else ''} detected this ingestion cycle"
        ),
        "highest_risk_score": max(risk_scores),
        "distinct_source_count": len(distinct_sources),
        "action_required": "Immediate triage required -- see `threats` for per-indicator detail.",
    }


def _render_critical_markdown(indicators: List[ThreatIndicator], impact_summary: Dict[str, Any]) -> str:
    """
    Markdown-formatted alert body, for any webhook receiver that renders
    markdown directly (Slack/Discord/Mattermost-style `content` fields, a
    generic markdown-aware alert router). This is an ADDITIONAL
    representation alongside the structured `impact_summary`/`threats`
    fields below, not a replacement for them -- a receiver that wants
    structured data still has it; this is for the ones that just render a
    text blob.

    Deliberately kept to plain ATX '#'/'##' headings and '-' bullets -- no
    receiver-specific syntax (Slack's own mrkdwn dialect, Discord embed
    JSON) baked in here, since SENTINEL_WEBHOOK_URL's actual receiver is
    operator-configured and unknown to this code. A receiver that needs
    its own native format can still build it from the structured fields;
    this string is a convenience, not the sole representation.
    """
    lines = [
        "# \U0001F6A8 SENTINELDATA HUB -- CRITICAL THREAT ALERT",
        "",
        "## Impact Summary",
        f"- {impact_summary['headline']}",
        f"- Highest risk score this cycle: {impact_summary['highest_risk_score']:.1f}",
        f"- Distinct sources involved: {impact_summary['distinct_source_count']}",
        f"- {impact_summary['action_required']}",
        "",
        "## Threats",
    ]
    for indicator in indicators:
        lines.append(
            f"- **{indicator.title}** (risk {indicator.risk_score:.1f}) -- "
            f"observed {indicator.observed_at.isoformat()} -- {indicator.source_url}"
        )
    return "\n".join(lines)


async def dispatch_webhook_alert(indicators: List[ThreatIndicator]) -> None:
    """
    Fire-and-forget notifier for high-priority (risk_score >= 5.0) threats.

    Module-level, not a method on OSINTPipeline -- and deliberately opens
    its own short-lived httpx.AsyncClient rather than reusing
    OSINTPipeline._http_client. That shared client's lifecycle is owned by
    OSINTPipeline.close() (awaited once at app shutdown -- see main.py's
    lifespan), and this function runs detached via asyncio.create_task()
    with no ordering guarantee relative to that shutdown. Reusing a client
    that might already be closed, or racing close() closing it mid-POST, is
    a bug class this sidesteps entirely by not touching pipeline-owned
    state. The cost is a new connection per alert batch instead of
    connection reuse -- acceptable for a path that fires on critical-threat
    detection, not on every request.

    SENTINEL_WEBHOOK_URL is operator-configured (an env var set by whoever
    deploys this), not attacker-supplied feed content -- so follow_redirects
    =False here is defense-in-depth, not a fix for the same SSRF class the
    feed-fetching client's follow_redirects=False addresses in
    OSINTPipeline.http_client. It's still the safer default: a webhook
    receiver silently 3xx-ing the POST elsewhere is not something to
    auto-follow either, so redirects are rejected the same way feed
    redirects are, for the same reason -- see the is_redirect check below.

    Never raises. Every failure path is caught, logged at
    ingestion.webhook_failed, and swallowed. Nothing awaits the task this
    runs as; an exception that escaped here would surface only as an
    "exception was never retrieved" warning at garbage-collection time,
    which is strictly worse than handling it here.

    CHANNEL-SEPARATION BOUNDARY (this pass): this is the ONLY function in
    the pipeline that ever emits an outbound alert -- run() already filters
    validated_indicators down to risk_score >= 5.0 before calling this (see
    run()'s own comment), so Informational/Low/Medium threats never reach
    here at all; they are persisted by _persist_indicators and nothing
    else. That upstream filter is trusted for WHICH indicators get here,
    but not blindly: the re-filter immediately below is a second,
    independent enforcement of the exact same boundary at the one place
    that actually renders "emergency"/"CRITICAL" into the payload, so a
    future caller passing an unfiltered batch cannot silently mislabel a
    Low/Medium threat as a critical emergency.

    PAYLOAD FORMAT (this pass): previously a flat {event, generated_at,
    count, threats} object. Now carries explicit emergency flags
    (`emergency: true`, `priority: "CRITICAL"`), an isolated
    `impact_summary` field pre-computed by _summarize_critical_impact
    (not left for the receiver to derive from `threats`), and a `markdown`
    field with ATX headings for any receiver that renders text directly.
    `threats` itself is unchanged -- still the flat per-indicator list --
    so anything already parsing that key against the old shape keeps
    working; every other key here is additive.

    DESIGN TRADE-OFF, stated rather than silently decided: this still
    batches every critical indicator from one ingestion cycle into ONE
    webhook POST, not one POST per indicator. "Standalone" in this
    ticket's wording is read here as "a separate call/channel from DB
    persistence" (true -- this function is never invoked for a
    save-only cycle), not "one HTTP request per critical indicator."
    Per-indicator dispatch was considered and rejected: a single feed
    cycle that surfaces, say, 12 simultaneous critical CVEs would fire 12
    near-simultaneous POSTs to the same receiver, which is a self-inflicted
    webhook flood/rate-limit risk for zero gain in information -- the
    batched payload's `impact_summary` and `markdown` sections already give
    a receiver everything needed to raise 12 separate tickets on its own
    side if that's the desired downstream behavior. If your receiver
    genuinely requires one-alert-per-threat semantics, that's a real,
    separate ask -- flagged here rather than guessed at.
    """
    webhook_url = os.environ.get("SENTINEL_WEBHOOK_URL", "").strip()
    if not webhook_url or not indicators:
        return

    # Defense-in-depth re-filter -- see CHANNEL-SEPARATION BOUNDARY above.
    # Costs nothing on the happy path (run() already only ever calls this
    # with an all-critical list) and catches the one class of bug that
    # would otherwise silently ship a false "CRITICAL"/"emergency" alert.
    critical_only = [indicator for indicator in indicators if indicator.risk_score >= 5.0]
    if len(critical_only) != len(indicators):
        logger.warning(
            "ingestion.webhook_received_non_critical_indicators",
            extra={
                "received_count": len(indicators),
                "critical_count": len(critical_only),
            },
        )
    if not critical_only:
        return
    indicators = critical_only

    impact_summary = _summarize_critical_impact(indicators)

    payload: Dict[str, Any] = {
        "event": "sentinel.critical_threats_detected",
        "emergency": True,
        "priority": "CRITICAL",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(indicators),
        "impact_summary": impact_summary,
        "markdown": _render_critical_markdown(indicators, impact_summary),
        "threats": [
            {
                "id": indicator.id,
                "title": indicator.title,
                "source_url": indicator.source_url,
                "risk_score": indicator.risk_score,
                "observed_at": indicator.observed_at.isoformat(),
            }
            for indicator in indicators
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.post(webhook_url, json=payload)

            if response.is_redirect:
                logger.error(
                    "ingestion.webhook_failed",
                    extra={
                        "webhook_url": webhook_url,
                        "critical_count": len(indicators),
                        "reason": "webhook_receiver_returned_redirect",
                        "redirect_status": response.status_code,
                    },
                )
                return

            response.raise_for_status()

        logger.info(
            "ingestion.webhook_sent",
            extra={"webhook_url": webhook_url, "critical_count": len(indicators)},
        )
    except httpx.HTTPError as exc:
        logger.error(
            "ingestion.webhook_failed",
            extra={
                "webhook_url": webhook_url,
                "critical_count": len(indicators),
                "reason": str(exc),
            },
        )
    except Exception:
        # Last-resort safety net, not the primary handler -- see docstring:
        # this task is never awaited by anything, so an escaped exception
        # here would otherwise vanish into an unretrieved-exception warning
        # instead of a log line anyone would actually see.
        logger.error(
            "ingestion.webhook_failed",
            exc_info=True,
            extra={"webhook_url": webhook_url, "critical_count": len(indicators)},
        )


class OSINTPipeline:
    """
    High-throughput asynchronous data pipeline for ingesting, processing,
    and validating unstructured OSINT and CVE threat streams.
    """

    # Circuit-breaker tuning -- ticket-specified exact values, not derived
    # from any measured SLO. 5 consecutive failed fetches for a given feed
    # URL (see _record_fetch_outcome) trips that URL's breaker; a tripped
    # URL is bypassed entirely -- no network call attempted at all, see
    # run()'s CIRCUIT BREAKER section -- for 10 minutes, then given one
    # unbiased trial fetch on the next cycle that starts after the cooldown
    # expires.
    _CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = 5
    _CIRCUIT_BREAKER_COOLDOWN: timedelta = timedelta(minutes=10)

    def __init__(self, target_feeds: List[str]):
        self.target_feeds = target_feeds
        # Implement lazy-loading properties protected by an atomic lock boundary
        self._http_client: Optional[httpx.AsyncClient] = None
        self._lock = asyncio.Lock()
        # Holds references to in-flight webhook-alert tasks created via
        # asyncio.create_task() in run(). This is not decorative -- asyncio
        # does not keep a task alive on its own once nothing references it;
        # a task created and immediately dropped can be garbage-collected
        # before it finishes, silently killing the alert mid-flight. Each
        # task removes itself via add_done_callback once it completes (see
        # run()), so this set only ever holds genuinely in-flight tasks.
        self._background_tasks: set = set()
        # Circuit-breaker state, keyed by feed URL string -- see
        # _circuit_is_open / _record_fetch_outcome and run()'s CIRCUIT
        # BREAKER section for the full state machine. Both dicts are
        # mutated ONLY from plain synchronous methods (no `await` anywhere
        # in their bodies) called from run() -- under asyncio's cooperative
        # scheduling, a synchronous method body can never be interleaved by
        # another task, so no asyncio.Lock is needed here the way one is
        # for _http_client's lazy-init double-check above. This does NOT
        # prevent two concurrent run() invocations (e.g. two overlapping
        # /api/v1/threats requests sharing the one app.state.pipeline
        # instance -- see main.py) from each independently deciding to
        # fetch the same not-yet-tripped feed in the same window; that
        # duplicate-concurrent-ingestion-cycle behavior predates this
        # change and is not solved by it -- flagged, not fixed, out of this
        # ticket's scope.
        self._consecutive_failures: Dict[str, int] = {}
        self._circuit_open_until: Dict[str, datetime] = {}

    @property
    async def http_client(self) -> httpx.AsyncClient:
        """Safely fetches or initializes the HTTPX client pool using a double-check lock pattern.

        follow_redirects=False is a deliberate SSRF boundary, not an
        oversight: this pipeline fetches URLs supplied via SENTINEL_FEED_URLS
        and treats their response bodies as data, but the URLs themselves
        are still "third party until proven otherwise." A malicious or
        compromised feed origin can respond with a 3xx pointing at an
        internal address (a cloud metadata endpoint, localhost, an internal
        admin panel) to use this process's network position as an SSRF
        proxy. With follow_redirects=True, httpx would transparently chase
        that redirect and hand the internal response straight into the
        ingestion pipeline. With it False, httpx returns the un-followed 3xx
        response instead of raising -- see fetch_feed_data below, which
        detects that explicitly via response.is_redirect and rejects it
        rather than treating a bare "don't follow" flag as sufficient by
        itself.
        """
        if self._http_client is None:
            async with self._lock:
                if self._http_client is None:
                    self._http_client = httpx.AsyncClient(timeout=15.0, follow_redirects=False)
        return self._http_client

    async def fetch_feed_data(self, url: str) -> Optional[str]:
        """Fetch raw feed data asynchronously.

        Deliberately format-agnostic: this returns response.text regardless
        of whether the body turns out to be XML/Atom/RSS or a JSON
        vulnerability stream. Format detection happens downstream, per
        payload, in _parse_and_vectorize / _extract_json_records -- not
        here, and not by inspecting the URL or a Content-Type header,
        neither of which reliably tells you what a third-party feed
        actually sends.

        Three distinct failure classes are handled here, each logged
        differently on purpose -- collapsing them into one generic
        "network failure" log line would hide which case actually occurred:

        1. Redirect response (response.is_redirect). httpx will NOT chase
           this automatically (follow_redirects=False on the shared
           client), so it comes back as a normal, non-raising response
           object rather than an exception. Treating a bare 3xx as "empty
           feed, move on" would silently swallow what may be an SSRF probe
           against internal infrastructure -- so it's detected explicitly
           and logged as a rejected redirect, not absorbed as a non-event.
        2. httpx.HTTPStatusError, raised by response.raise_for_status() for
           4xx/5xx responses -- an upstream feed that is down, gone, or
           misconfigured.
        3. httpx.HTTPError (the transport-level superclass covering
           httpx.HTTPStatusError, connection failures, timeouts, etc.) --
           kept as a catch-all beneath the more specific handler above so a
           transport failure never crashes the whole ingestion cycle.

        In every case, a single feed failing returns None and the cycle
        continues with whatever other feeds succeeded -- see run(), which
        gathers all fetch_feed_data calls concurrently and only ever expects
        Optional[str] results, never an exception, from this method.
        """
        try:
            client = await self.http_client
            # Explicit per-request timeout=10.0 -- tighter than, and
            # independent of, the shared client's own timeout=15.0 (see
            # http_client above). That client-level value already bounded
            # every request routed through it, so nothing here was hanging
            # indefinitely before this edit; this makes the bound visible
            # at the actual call site instead of only inferable from client
            # construction elsewhere in the file, and deliberately
            # tightens it (15.0 -> 10.0) rather than just restating the
            # same number under a different name.
            response = await client.get(url, timeout=10.0)

            if response.is_redirect:
                logger.error(
                    "ingestion.feed_redirect_rejected",
                    extra={
                        "feed_url": url,
                        "redirect_status": response.status_code,
                        "redirect_location": response.headers.get("location", "<none>"),
                    },
                )
                return None

            response.raise_for_status()
            return response.text
        except httpx.HTTPStatusError as exc:
            logger.error(
                "ingestion.feed_http_status_error",
                extra={
                    "feed_url": url,
                    "status_code": exc.response.status_code,
                },
            )
            return None
        except httpx.HTTPError as exc:
            logger.error(f"Network failure fetching feed {url}: {str(exc)}")
            return None

    def _extract_json_records(self, raw_payload: str) -> Optional[List[Dict[str, Any]]]:
        """
        Attempts to parse raw_payload as a JSON vulnerability stream and map
        it into the same intermediate record shape the feedparser path
        below already builds: {title, description, source_url,
        published_raw}. That shared shape is what lets JSON- and XML/Atom-
        sourced entries flow through the exact same downstream
        deduplication, risk-scoring, and batch-upsert code in
        _process_batch/_persist_indicators without either path needing to
        know the other exists.

        json.loads is the parser used here -- not eval(), not a YAML
        loader, nothing with an execution or object-construction surface.
        That is what makes this "safely" parsed: a malformed or hostile
        JSON payload can, at worst, fail to parse or produce data this
        function then validates key-by-key: it cannot execute code or
        instantiate arbitrary Python objects the way an unsafe deserializer
        could.

        Return value carries three distinct outcomes, and callers must not
        collapse them:
          - None: raw_payload is not valid JSON at all -- "try the
            XML/Atom feedparser path instead."
          - [] (empty list): raw_payload IS valid JSON, but contained zero
            usable entries (empty array, or every entry missing a
            mappable title/source_url). This must NOT fall through to
            feedparser -- feedparser fed a JSON string will not raise, it
            will just also return zero entries, but treating a real (if
            empty) JSON response as "maybe it's actually XML" is the wrong
            fallback for the wrong reason.
          - non-empty list: usable records, appended into the same batch
            feedparser entries populate.

        Schema assumption, stated rather than silently guessed: there is no
        JSON feed schema specification anywhere in this project to conform
        to, so this maps the field names a vulnerability-stream API is
        most likely to use, not a confirmed contract. Top level is either a
        bare JSON array of entries, or an object with the array under one
        of a handful of common wrapper keys (vulnerabilities/items/results/
        data), or -- if none of those match -- a single JSON object is
        treated as one entry rather than discarded outright. Per-entry key
        aliases: title <- title/name/cve_id; description <-
        description/summary/details; source_url <- url/link/reference;
        published_raw <- published/date/timestamp/modified. Confirm these
        against whatever real JSON feed(s) SENTINEL_FEED_URLS ends up
        pointing at -- an entry using different key names is logged and
        skipped, not crashed, but also not silently mis-mapped.
        """
        try:
            parsed_json = json.loads(raw_payload)
        except (json.JSONDecodeError, TypeError):
            return None

        if isinstance(parsed_json, list):
            raw_entries = parsed_json
        elif isinstance(parsed_json, dict):
            raw_entries = None
            for wrapper_key in ("vulnerabilities", "items", "results", "data"):
                candidate = parsed_json.get(wrapper_key)
                if isinstance(candidate, list):
                    raw_entries = candidate
                    break
            if raw_entries is None:
                raw_entries = [parsed_json]
        else:
            # A JSON scalar (number, string, bool, null) has no usable
            # vulnerability-entry structure at all.
            return []

        records: List[Dict[str, Any]] = []
        for entry in raw_entries:
            if not isinstance(entry, dict):
                continue

            title = entry.get("title") or entry.get("name") or entry.get("cve_id")
            source_url = entry.get("url") or entry.get("link") or entry.get("reference")
            if not title or not source_url:
                # Both are non-optional on ThreatIndicator -- skip here,
                # with the actual missing-key context, rather than pass an
                # incomplete record through to fail Pydantic validation
                # later with a much less useful error further from its
                # actual cause.
                logger.warning(
                    "ingestion.json_entry_missing_required_fields",
                    extra={"entry_keys": list(entry.keys())},
                )
                continue

            description = (
                entry.get("description")
                or entry.get("summary")
                or entry.get("details")
                or ""
            )
            published_raw = (
                entry.get("published")
                or entry.get("date")
                or entry.get("timestamp")
                or entry.get("modified")
            )

            records.append({
                "title": title,
                "description": description,
                "source_url": source_url,
                "published_raw": published_raw,
            })

        return records

    def _parse_and_vectorize(self, raw_feed_payloads: List[str]) -> pd.DataFrame:
        """
        Parses each raw feed payload as either a JSON vulnerability stream
        or an XML/Atom/RSS feed (via feedparser), and vectorizes the
        combined result for downstream processing.

        Format is detected per payload, not per feed URL: fetch_feed_data
        (see above) is intentionally content-format-agnostic -- it fetches
        and returns raw text regardless of what's on the other end, since
        deciding "is this JSON or XML" from a URL string alone would be
        guessing. _extract_json_records is tried first for each payload;
        only a payload that is NOT valid JSON at all falls through to
        feedparser. A payload cannot be both -- valid JSON is never valid
        XML/Atom and vice versa -- so there's no double-parsing or
        format-preference ambiguity here.
        """
        extracted_records = []

        for raw_payload in raw_feed_payloads:
            if not raw_payload:
                continue

            json_records = self._extract_json_records(raw_payload)
            if json_records is not None:
                extracted_records.extend(json_records)
                continue

            parsed = feedparser.parse(raw_payload)
            for entry in parsed.entries:
                extracted_records.append({
                    "title": entry.get("title", ""),
                    "description": entry.get("description", entry.get("summary", "")),
                    "source_url": entry.get("link", ""),
                    "published_raw": entry.get("published", entry.get("updated", None))
                })

        if not extracted_records:
            return pd.DataFrame()

        # Enforce native Pandas 3.x PyArrow backend string storage (project directive:
        # "Always implement native Pandas 3.x string storage mechanisms backed by
        # PyArrow (string[pyarrow]) to guarantee zero memory overhead" -- this was
        # previously "string[python]", the opposite of that directive.
        df = pd.DataFrame(extracted_records)
        df = df.astype({
            "title": "string[pyarrow]",
            "description": "string[pyarrow]",
            "source_url": "string[pyarrow]"
        })
        return df

    def _process_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Executes vectorized deduplication, deterministic ID assignment,
        and high-speed risk metric calculations.
        """
        if df.empty:
            return df

        # 1. Clean and normalize temporal features to UTC.
        # utc=True is required, not optional: without it, pd.to_datetime infers
        # tz-awareness per-value from whatever offset (or lack of one) each feed's
        # date string happens to carry. A single feed mixing "+0000"-suffixed and
        # bare timestamps produces a column that is neither reliably naive nor
        # reliably aware, which is exactly the ambiguity ThreatIndicator.observed_at
        # now explicitly rejects. utc=True forces every parsed value to a single,
        # unambiguous UTC-aware representation up front.
        #
        # format="mixed" is not a cosmetic warning suppressor -- omitting it is
        # a silent data-corruption bug, verified empirically against this
        # pipeline's actual pandas 3.0.2 runtime. Without an explicit format,
        # pd.to_datetime infers ONE format from the first non-null value in the
        # column and then applies that literal format to every other value in
        # the column.
        #
        # CORRECTED characterization (a prior version of this comment said
        # the trigger was simply "two entries with different weekdays" --
        # that was imprecise, and the corrected version below was verified
        # while building backend/tests/test_pipeline.py's regression test):
        # the trigger is NOT "different weekday abbreviations are present in
        # the batch." Two RFC822 strings with correct, internally-consistent
        # weekday/date pairs (e.g. an actual Monday labeled "Mon" and an
        # actual Wednesday labeled "Wed") parse together just fine regardless
        # of how many distinct weekdays appear -- pandas correctly recognizes
        # that position as a genuine %a token in that case. The actual
        # trigger is narrower: it fires when the FIRST value pandas samples
        # has an INTERNALLY INCONSISTENT weekday -- its weekday name does not
        # match the weekday its own day/month/year actually fall on (e.g.
        # "Tue, 06 Jul 2026 ..." when 06 Jul 2026 is genuinely a Monday).
        # Reproduced directly with errors="raise" on such a value paired with
        # a second, entirely correct entry:
        #   ValueError: time data "Wed, 07 Jul 2026 09:00:00 GMT" doesn't match
        #   format "Tue, %d %b %Y %H:%M:%S GMT". You might want to try:
        #   - passing format if your strings have a consistent format;
        #   - passing format='ISO8601' if your strings are all ISO8601 but not
        #     necessarily in exactly the same format;
        #   - passing format='mixed', and the format will be inferred for each
        #     element individually.
        # Note the guessed format literally froze "Tue" as a fixed character
        # sequence rather than recognizing it as %a -- because that first
        # value's own weekday/date consistency check failed, pandas couldn't
        # confidently generalize that token, so it locked the ENTIRE batch to
        # that broken literal for the rest of the parse. Every other entry,
        # even ones with perfectly correct, self-consistent weekday/date
        # pairs, then fails to match and silently becomes NaT under
        # errors="coerce" -- with zero warning surfaced (confirmed: no
        # UserWarning fires under pandas 3.0.2, contrary to the assumption
        # this ticket was originally raised under).
        #
        # This is a realistic failure mode, not a contrived one: a weekday/
        # date mismatch like this is exactly what a timezone-conversion bug
        # in an upstream feed generator produces -- converting a local
        # timestamp to UTC can shift the calendar date across midnight while
        # the weekday name, derived earlier from the pre-conversion local
        # date, never gets recomputed. One such malformed entry anywhere in a
        # batch -- not necessarily the "worst" one, just whichever one pandas
        # samples first -- silently corrupts the observed_at timestamp of
        # every other, perfectly valid entry ingested in that same cycle.
        #
        # Every NaT produced this way is silently backfilled below by
        # fillna(now()) -- meaning a real feed's published/updated timestamp
        # gets silently replaced with "whenever this batch happened to run",
        # with no error, no warning, and no log line pointing at the cause.
        # format="mixed" tells pandas to infer the format independently per
        # element instead of locking onto one sampled value's literal shape,
        # which eliminates this failure mode entirely regardless of which
        # entry (if any) happens to carry an inconsistent weekday.
        #
        # Longer-term, more robust alternative (out of scope for this ticket,
        # not implemented here): feedparser already exposes parsed
        # published_parsed / updated_parsed struct_time fields on each entry,
        # which sidesteps re-parsing raw date strings through pandas' format
        # inference altogether. Flagged for a future pass, not touched here.
        df["observed_at"] = pd.to_datetime(
            df["published_raw"], errors="coerce", utc=True, format="mixed"
        )
        df["observed_at"] = df["observed_at"].fillna(datetime.now(timezone.utc))

        # 2. Compute Deterministic UUIDv5 identifiers from string payload hashes
        def generate_deterministic_uuid(row) -> str:
            payload_bytes = f"{row['title']}|{row['source_url']}".encode("utf-8")
            hash_md5 = hashlib.md5(payload_bytes).digest()
            return str(uuid.uuid5(uuid.NAMESPACE_URL, hash_md5.hex()))

        df["indicator_id"] = df.apply(generate_deterministic_uuid, axis=1).astype("string[pyarrow]")

        # 3. Vectorized Deduplication based on calculated unique hashes
        df = df.drop_duplicates(subset=["indicator_id"], keep="first")

        # 4. Vectorized Risk Scoring Matrix based on text evaluation
        df["risk_score"] = 1.0

        desc_lower = df["description"].str.lower()
        title_lower = df["title"].str.lower()

        # Assign risk conditions hierarchically via index alignment matching
        #
        # CVE year token is read dynamically from the system clock rather
        # than hardcoded, so this doesn't silently stop matching current-
        # year CVE mentions once the calendar rolls over (the previous
        # "cve-2026" literal would have quietly gone stale on 2027-01-01 --
        # no error, no log line, no warning, just a slow decay in how many
        # indicators get flagged critical).
        #
        # datetime.now(timezone.utc).year, not datetime.now().year: every
        # other clock read in this file (df["observed_at"] above,
        # dispatch_webhook_alert's generated_at, _persist_indicators'
        # written_at) is explicit UTC, and this should be no different. A
        # naive datetime.now().year reads the HOST's local clock -- a
        # worker running in UTC-8 still reports the outgoing year for the
        # first 8 hours of UTC's January 1st. That's not cosmetic here:
        # risk_score categorization is a security signal, not a timestamp
        # rendered for a human, so it should not drift depending on which
        # timezone happens to host this process. year is a 4-digit int
        # interpolated directly into the pattern -- no re.escape needed, it
        # carries no regex metacharacters.
        current_cve_year = datetime.now(timezone.utc).year
        critical_mask = desc_lower.str.contains(f"rce|critical|cve-{current_cve_year}|exploit", na=False) | \
                        title_lower.str.contains("rce|critical", na=False)
        high_mask = desc_lower.str.contains("high|zero-day|injection|malware", na=False) & ~critical_mask
        medium_mask = desc_lower.str.contains("medium|vulnerability|patch", na=False) & ~(critical_mask | high_mask)

        df.loc[critical_mask, "risk_score"] = 5.0
        df.loc[high_mask, "risk_score"] = 4.0
        df.loc[medium_mask, "risk_score"] = 3.0

        return df

    def _persist_indicators(self, validated_indicators: List[ThreatIndicator]) -> int:
        """
        Batch upsert write path. Deliberately NOT async -- runs on a worker
        thread via asyncio.to_thread (see run()), never directly on the
        event loop, same reasoning as before.

        Replaces the previous one-SELECT-plus-one-INSERT-per-indicator loop
        (a real N+1 pattern -- a 200-indicator cycle was up to 400 round
        trips to SQLite) with a single INSERT ... ON CONFLICT(id) DO UPDATE
        statement covering the whole batch in one atomic transaction.
        sqlalchemy.dialects.sqlite.insert() is required here, not the
        generic sqlalchemy.insert() -- only the dialect-specific construct
        exposes on_conflict_do_update(). This pipeline is SQLite-only today
        (see database/connection.py), so that's not a new portability
        constraint, just one worth stating rather than leaving implicit --
        this will need a different upsert construct if the DB is ever
        swapped.

        Conflict target is `id`, the table's primary key -- the same
        deterministic UUIDv5 computed from title+source_url in
        _process_batch. On conflict, title/link/summary/published_date/
        risk_score/ingested_at are all overwritten from the incoming row.
        title/link normally won't change (they're literally the hash
        input), but summary/published_date/risk_score legitimately can if
        an upstream feed edits an entry's description or bumps its
        <updated> timestamp between polling cycles -- silently keeping the
        old values on conflict would mean a since-escalated "now critical"
        indicator never actually updates in the database. ingested_at is
        explicitly bumped to `written_at` on conflict too, not left at its
        original insert-time value: that keeps GET /api/v1/metrics'
        MAX(ingested_at) truthful about when this pipeline last actually
        wrote a row, insert or update -- leaving it stale on updates would
        make the dashboard's "Last DB write" lag behind real activity.

        written_at now uses datetime.now(timezone.utc), an explicit,
        timezone-aware UTC construction, in place of the previous naive
        datetime.utcnow(). This is a deliberately narrow fix, and it is
        important to be precise about what it does and does not change:

        - On disk, this is a no-op. SQLAlchemy's SQLite DATETIME type has
          no native timezone-aware column type; its bind processor formats
          a value strictly from year/month/day/hour/minute/second/
          microsecond and never reads .tzinfo at all. A naive and an aware
          datetime representing the identical instant serialize to
          byte-identical stored strings. Nothing about the database schema
          or the bytes it holds changes as a result of this edit.
        - What changes is in-memory intent at construction time: the value
          assigned to `written_at` is now explicitly UTC-aware the moment
          it's created, rather than naive-and-implicitly-UTC-by-convention.
          This removes one more naive datetime.utcnow() call site from the
          codebase, consistent with the rest of this ticket's mandate.
        - UPDATE (later pass): GET /api/v1/metrics' re-localization of
          MAX(ingested_at) in main.py (`if latest_ingestion_time.tzinfo is
          None: replace(tzinfo=timezone.utc)`) was unaffected by this change
          when it landed, for the reason above -- SQLite round-trips a
          column as naive on read regardless of how it was written. That
          re-localization check is STILL there and still harmless, but a
          later pass added database/models.py's UTCDateTime TypeDecorator
          on both published_date and ingested_at, which now re-localizes to
          UTC internally on every read through those columns. That makes
          main.py's own check provably dead code for this column -- it will
          never see a naive value again -- though it hasn't been removed
          (still out of scope for whichever file is being touched at the
          time; harmless to leave in place either way).
        - UPDATE (later pass): database/models.py's ingested_at column
          previously declared default=datetime.utcnow (naive) as its
          ORM-level default, and there was no TypeDecorator giving these
          columns genuine DB-level tz-aware round-tripping -- both were
          flagged here as future recommendations. Both are now implemented:
          database/models.py defines a UTCDateTime TypeDecorator (applied to
          both published_date and ingested_at) and the default is now
          `default=lambda: datetime.now(timezone.utc)`. That default still
          practically never fires for pipeline-written rows, for the same
          reason stated above -- this method always supplies an explicit
          "ingested_at": written_at value in the upsert's values list, and
          the column default only applies to a row inserted through the ORM
          directly, bypassing this upsert path entirely.

        Return value semantics changed from the previous version: this
        returns the size of the upserted batch (insert OR update), not
        "newly inserted rows only" -- SQLite's ON CONFLICT DO UPDATE
        doesn't cheaply distinguish the two outcomes per row within one
        statement, and fabricating that distinction would be worse than
        not reporting it.

        Precondition this method depends on and enforces itself, not just
        trusts: no two rows in the same INSERT ... ON CONFLICT statement
        may target the same conflicting key -- SQLite raises "ON CONFLICT
        DO UPDATE command cannot affect row a second time" if they do.
        _process_batch's drop_duplicates(subset=["indicator_id"]) already
        guarantees this upstream, but this method re-deduplicates by id
        anyway (keeping the last occurrence) rather than silently trusting
        an invariant it doesn't itself control.
        """
        if not validated_indicators:
            return 0

        written_at = datetime.now(timezone.utc)

        # Defensive re-dedup by id, keeping the last occurrence -- see
        # docstring precondition above.
        deduped_by_id: Dict[str, ThreatIndicator] = {
            indicator.id: indicator for indicator in validated_indicators
        }

        values = [
            {
                "id": indicator.id,
                "title": indicator.title,
                "link": indicator.source_url,
                "summary": indicator.description,
                "published_date": indicator.observed_at,
                "risk_score": indicator.risk_score,
                "ingested_at": written_at,
            }
            for indicator in deduped_by_id.values()
        ]

        db: Session = SessionLocal()
        try:
            upsert_stmt = sqlite_upsert(ThreatIndicatorModel).values(values)
            upsert_stmt = upsert_stmt.on_conflict_do_update(
                index_elements=[ThreatIndicatorModel.id],
                set_={
                    "title": upsert_stmt.excluded.title,
                    "link": upsert_stmt.excluded.link,
                    "summary": upsert_stmt.excluded.summary,
                    "published_date": upsert_stmt.excluded.published_date,
                    "risk_score": upsert_stmt.excluded.risk_score,
                    "ingested_at": upsert_stmt.excluded.ingested_at,
                },
            )
            db.execute(upsert_stmt)
            db.commit()
            logger.info(
                "ingestion.persistence_batch_upsert_complete",
                extra={"batch_size": len(values)},
            )
        except Exception:
            db.rollback()
            logger.error("Database persistence sub-cycle failed.", exc_info=True)
            # Fail-open: don't crash the network request if storage hits a localized snag
            return 0
        finally:
            db.close()

        return len(values)

    def _circuit_is_open(self, url: str) -> bool:
        """
        True if `url` is currently inside its circuit-breaker cooldown
        window and must be bypassed entirely this cycle -- see run()'s
        CIRCUIT BREAKER section for where this gates the fetch list.

        A URL with no entry in _circuit_open_until has never tripped (or
        tripped once and has since been cleared by a successful trial
        fetch in _record_fetch_outcome) and is always open-for-business
        here -- that's why this reads via .get(url) (defaulting a missing
        entry to "not open") rather than assuming every feed URL has an
        existing entry.
        """
        cooldown_until = self._circuit_open_until.get(url)
        return cooldown_until is not None and datetime.now(timezone.utc) < cooldown_until

    def _record_fetch_outcome(self, url: str, succeeded: bool) -> None:
        """
        Updates `url`'s consecutive-failure counter and trips its circuit
        if the threshold is reached. Called exactly once per feed URL that
        was actually attempted this cycle -- run() never calls this for a
        bypassed/cooldown URL, since there is no outcome to record for a
        fetch that never ran.

        `succeeded` means "fetch_feed_data returned a non-None string",
        which is deliberately broader than this ticket's literal "HTTP/
        network exceptions or timeouts" wording: fetch_feed_data also
        returns None when it rejects a same-origin-abusing redirect (see
        that method's own docstring -- the SSRF boundary). Treating a
        persistently-redirecting feed the same as a persistently-timing-out
        one is a deliberate choice, not an oversight: operationally, both
        mean "this URL has given us zero usable bytes for N cycles in a
        row," and continuing to spend a request on it every cycle serves no
        purpose in either case. This does NOT weaken the SSRF defense --
        every attempted fetch still evaluates and rejects the redirect
        exactly as before (see fetch_feed_data); circuit-breaking only
        reduces how often we bother making the attempt at all.

        A True result resets the counter to 0 outright on ANY call -- even
        one immediately after a long failure streak -- not to
        (threshold - 1) or some partial credit: one clean fetch is treated
        as full recovery, matching the ticket's "resetting the counter on
        the next successful ... cycle" wording exactly.
        """
        if succeeded:
            self._consecutive_failures[url] = 0
            self._circuit_open_until.pop(url, None)
            return

        failures = self._consecutive_failures.get(url, 0) + 1
        self._consecutive_failures[url] = failures

        if failures >= self._CIRCUIT_BREAKER_FAILURE_THRESHOLD:
            # Deliberately NOT reset to 0 here -- only a success resets it
            # (see above). That means a single renewed failure on the very
            # next post-cooldown trial fetch keeps the counter at/above
            # threshold and re-trips immediately with a fresh cooldown,
            # rather than requiring 5 MORE consecutive failures to notice a
            # feed that never actually recovered. A feed that trips, then
            # succeeds even once, still gets the full reset above.
            cooldown_until = datetime.now(timezone.utc) + self._CIRCUIT_BREAKER_COOLDOWN
            self._circuit_open_until[url] = cooldown_until
            logger.error(
                "ingestion.circuit_breaker.tripped_for_feed",
                extra={
                    "feed_url": url,
                    "consecutive_failures": failures,
                    "cooldown_until": cooldown_until.isoformat(),
                },
            )

    async def run(self) -> List[ThreatIndicator]:
        """
        Pipeline entry point. Executes async network gathering, hands off payload
        processing to threads, and pipes validated structures back into Pydantic models.

        CONCURRENCY NOTE -- read this before "fixing" it again: the fetch
        step below already dispatches every feed URL's fetch_feed_data()
        call concurrently, and always has. fetch_tasks is a list of
        not-yet-awaited coroutines; asyncio.gather schedules ALL of them
        onto the event loop together and returns only once every one has
        completed -- a slow feed at index 0 does not block feed 1 from
        starting, because nothing here awaits fetch_tasks[0] before
        fetch_tasks[1] is even scheduled. This is the correct, idiomatic
        pattern for a batch of independent I/O-bound async calls.
        concurrent.futures.ThreadPoolExecutor would be a regression here,
        not an upgrade: fetch_feed_data's actual I/O (client.get()) is
        already non-blocking, cooperatively-scheduled async I/O on this one
        event loop -- there is no blocking call anywhere in it for a
        worker thread to usefully take over. Wrapping it in a thread pool
        would add OS thread creation/context-switch overhead and a second,
        redundant concurrency model (threads that would then need
        run_coroutine_threadsafe or a duplicated client to call back into
        asyncio at all) to solve a problem that does not exist here.

        return_exceptions=True on the gather() call below IS a genuine,
        previously-missing hardening -- the one real gap this pass closes.
        fetch_feed_data already catches httpx.HTTPStatusError and
        httpx.HTTPError internally and returns None instead of raising (see
        that method's own docstring), but without return_exceptions=True,
        ANY exception outside that specific hierarchy -- a bug introduced
        in a future edit to fetch_feed_data, an unexpected non-httpx
        exception surfacing from deep inside httpx's transport layer, a
        cancellation propagating oddly -- would previously propagate
        straight out of this gather() call, aborting every still-in-flight
        fetch and killing the entire ingestion cycle over one anomalous
        feed. That directly contradicted this pipeline's own stated
        resilience goal (see test_partial_feed_failure_returns_surviving_
        indicators) for every failure class OTHER than the two httpx ones
        fetch_feed_data explicitly catches itself. With
        return_exceptions=True, a raised exception is captured as a value
        in raw_results instead of propagating, and is explicitly logged and
        coerced to None below -- before reaching _parse_and_vectorize,
        which already safely skips any falsy/None entry (see its own
        `if not raw_payload: continue`) -- so an exception surviving this
        far costs that one feed's data for this cycle, nothing more.

        CIRCUIT BREAKER (added this pass): each feed URL carries its own
        consecutive-failure counter and cooldown timestamp (see
        _circuit_is_open / _record_fetch_outcome). A URL that fails 5
        times in a row is bypassed entirely -- no coroutine created, no
        network call attempted -- for the next 10 minutes, then given one
        unbiased trial fetch on whichever cycle next runs after that
        window closes. This interacts with one pre-existing piece of
        infrastructure worth naming: main.py wraps this whole method in
        asyncio.wait_for(..., timeout=SENTINEL_INGESTION_TIMEOUT_SECONDS).
        If THAT timeout fires mid-gather, this method is cancelled before
        reaching the outcome-recording loop below at all -- meaning a
        cycle that times out contributes zero circuit-breaker signal for
        any feed that cycle, even ones that individually would have
        resolved fast. That is an existing interaction, not a new gap this
        pass introduces, and is not addressed here.
        """
        logger.info(f"Starting ingestion cycle across {len(self.target_feeds)} targets.")

        # --- CIRCUIT BREAKER: pre-fetch gate ---
        # Any feed URL currently inside its cooldown window (see
        # _circuit_is_open) is bypassed entirely: no coroutine is created
        # for it at all, and it contributes None at its original index in
        # raw_payloads -- indistinguishable downstream from any other
        # failed fetch, since _parse_and_vectorize already treats any
        # falsy entry as "nothing from this feed this cycle." Indexed, not
        # dict-keyed, deliberately: self.target_feeds could in principle
        # contain the same URL string twice (a misconfigured
        # SENTINEL_FEED_URLS with a duplicate), and each occurrence must
        # still get its own independent fetch attempt and its own slot in
        # raw_payloads when not bypassed, exactly as it did before this
        # pass -- collapsing by URL string into a dict would silently
        # merge those into one shared fetch/result and change that
        # behavior.
        fetch_indices: List[int] = []
        fetch_tasks = []
        bypassed_urls: List[str] = []
        raw_payloads: List[Optional[str]] = [None] * len(self.target_feeds)

        for index, url in enumerate(self.target_feeds):
            if self._circuit_is_open(url):
                bypassed_urls.append(url)
                continue
            fetch_indices.append(index)
            fetch_tasks.append(self.fetch_feed_data(url))

        if bypassed_urls:
            logger.warning(
                "ingestion.circuit_breaker.bypassed_fetch",
                extra={"feed_urls": bypassed_urls, "bypassed_count": len(bypassed_urls)},
            )

        raw_results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        # --- CIRCUIT BREAKER: post-fetch outcome recording ---
        # Only feeds actually attempted this cycle (fetch_indices) get an
        # outcome recorded here -- see _record_fetch_outcome's own
        # docstring for why a bypassed feed must never reach that call.
        for index, result in zip(fetch_indices, raw_results):
            url = self.target_feeds[index]
            if isinstance(result, BaseException):
                logger.error(
                    "ingestion.feed_fetch_task_raised_unexpectedly",
                    extra={"feed_url": url, "reason": str(result)},
                )
                raw_payloads[index] = None
                self._record_fetch_outcome(url, succeeded=False)
            else:
                raw_payloads[index] = result
                self._record_fetch_outcome(url, succeeded=result is not None)

        # Offload heavy Pandas parsing and array manipulation to a background worker thread
        processed_df = await asyncio.to_thread(self._parse_and_vectorize, raw_payloads)
        optimized_df = await asyncio.to_thread(self._process_batch, processed_df)

        validated_indicators: List[ThreatIndicator] = []

        if optimized_df.empty:
            logger.info("Ingestion completed: Zero new target rows extracted.")
            return validated_indicators

        # Map optimized DataFrame rows into strict Pydantic instances
        for _, row in optimized_df.iterrows():
            try:
                indicator = ThreatIndicator(
                    id=row["indicator_id"],
                    title=row["title"],
                    description=row["description"],
                    source_url=row["source_url"],
                    risk_score=float(row["risk_score"]),
                    observed_at=row["observed_at"]
                )
                validated_indicators.append(indicator)
            except ValidationError as val_err:
                logger.error(f"Pydantic Validation Guard Rejected Row {row.get('indicator_id')}: {val_err.json()}")
                continue

        # --- PHASE 5: PERSISTENCE ENGINE ---
        # Offloaded to a worker thread -- see _persist_indicators docstring for why
        # this can no longer run inline on the event loop.
        if validated_indicators:
            written_count = await asyncio.to_thread(self._persist_indicators, validated_indicators)

            # Webhook dispatch is scheduled here, in run(), deliberately NOT
            # inside _persist_indicators. _persist_indicators executes on a
            # worker thread via asyncio.to_thread above and has no running
            # event loop of its own -- asyncio.create_task() calls
            # asyncio.get_running_loop() internally, and calling it from
            # that thread raises RuntimeError. Worse, _persist_indicators'
            # own try/except would catch that RuntimeError and log
            # "Database persistence sub-cycle failed" even though the batch
            # upsert had already committed successfully -- misreporting a
            # webhook-scheduling bug as a storage failure. run() is already
            # executing on the event loop, so this is where task creation
            # can actually succeed.
            #
            # Gating on written_count > 0 means a webhook only fires for
            # threats that were genuinely persisted this cycle -- if the
            # upsert rolled back, _persist_indicators returns 0 and nothing
            # gets alerted on, rather than claiming threats were "ingested
            # or updated" when the write that would have done so failed.
            if written_count > 0:
                critical_indicators = [
                    indicator for indicator in validated_indicators
                    if indicator.risk_score >= 5.0
                ]
                if critical_indicators:
                    # asyncio.create_task(), not await: a slow or hanging
                    # webhook receiver must not add latency to the
                    # /api/v1/threats response, which already has its own
                    # SENTINEL_INGESTION_TIMEOUT_SECONDS budget (see
                    # main.py) for actual ingestion work -- notification
                    # delivery is a side effect of a successful cycle, not
                    # part of what that timeout should be spent on.
                    #
                    # The task is tracked in self._background_tasks and
                    # removes itself on completion -- see __init__ and
                    # close() for why a bare, unreferenced create_task()
                    # call would be a real (if intermittent) bug here.
                    webhook_task = asyncio.create_task(
                        dispatch_webhook_alert(critical_indicators)
                    )
                    self._background_tasks.add(webhook_task)
                    webhook_task.add_done_callback(self._background_tasks.discard)

        logger.info(f"Ingestion lifecycle completed. Emitted {len(validated_indicators)} validated threat vectors.")
        return validated_indicators

    async def close(self):
        """Gracefully release HTTP connections and any still-pending webhook tasks.

        Cancels rather than awaits-to-completion any in-flight webhook
        alerts: at shutdown, a webhook that hasn't finished should not
        block process exit, and asyncio.gather(..., return_exceptions=True)
        below both waits for the cancellation to actually land and prevents
        an unrelated "Task was destroyed but it is pending" warning at
        interpreter teardown -- a cosmetic issue, but one that's cheap to
        avoid given _background_tasks already exists for this exact
        purpose.
        """
        if self._background_tasks:
            for task in list(self._background_tasks):
                task.cancel()
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        if self._http_client is not None:
            await self._http_client.aclose()
