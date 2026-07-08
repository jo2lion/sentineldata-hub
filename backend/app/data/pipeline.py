import asyncio
import json
import logging
import os
from datetime import datetime, timezone
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
    """
    webhook_url = os.environ.get("SENTINEL_WEBHOOK_URL", "").strip()
    if not webhook_url or not indicators:
        return

    payload: Dict[str, Any] = {
        "event": "sentinel.critical_threats_detected",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(indicators),
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
            response = await client.get(url)

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
        # the column. For RFC822-style dates ("Tue, 07 Jul 2026 10:15:00 GMT"),
        # the weekday abbreviation ("Tue") is baked into the inferred format as
        # a fixed literal, not recognized as a variable token -- so any other
        # entry in the same batch landing on a different weekday fails to match
        # that literal. Under errors="coerce" this failure is NOT surfaced as a
        # UserWarning (confirmed: no warning fires under pandas 3.0.2, contrary
        # to the assumption this ticket was raised under) -- it is swallowed
        # into a bare NaT with zero diagnostic trail. Reproduced directly:
        # feeding pandas two otherwise-valid RFC822 strings differing only by
        # weekday, with errors="raise" instead of "coerce", surfaces:
        #   ValueError: time data "Wed, 02 Jul 2026 10:15:00 GMT" doesn't match
        #   format "Tue, %d %b %Y %H:%M:%S GMT". You might want to try:
        #   - passing format if your strings have a consistent format;
        #   - passing format='ISO8601' if your strings are all ISO8601 but not
        #     necessarily in exactly the same format;
        #   - passing format='mixed', and the format will be inferred for each
        #     element individually.
        # Every NaT produced this way is silently backfilled below by
        # fillna(now()) -- meaning a real feed's published/updated timestamp
        # gets silently replaced with "whenever this batch happened to run",
        # with no error, no warning, and no log line pointing at the cause.
        # format="mixed" tells pandas to infer the format independently per
        # element instead of locking onto the first value's literal shape,
        # which eliminates this failure mode entirely.
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
        critical_mask = desc_lower.str.contains("rce|critical|cve-2026|exploit", na=False) | \
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
        - GET /api/v1/metrics' re-localization of MAX(ingested_at) in
          main.py (`if latest_ingestion_time.tzinfo is None: replace(
          tzinfo=timezone.utc)`) is unaffected either way: because the
          SQLite driver round-trips the column as naive on read regardless
          of how it was written, that value comes back naive whether
          `written_at` was constructed as naive or aware, so the existing
          re-localization-on-read logic continues to fire and remains
          correct without modification.
        - database/models.py's ingested_at column still declares
          default=datetime.utcnow (naive) as its ORM-level default. That
          default is never actually invoked for pipeline-written rows,
          since this method always supplies an explicit "ingested_at":
          written_at value in the upsert's values list -- the column
          default only applies to rows inserted through the ORM without an
          explicit value, which this code path never does. Reconciling
          that column default's naive convention with the aware value
          computed here is a database/models.py change and is out of this
          ticket's pipeline.py-only scope; not touched here.
        - Genuine DB-level tz-aware round-tripping (as opposed to this
          in-memory-only explicitness) would require a custom SQLAlchemy
          TypeDecorator on the ingested_at / published_date columns in
          database/models.py. Flagged as a future recommendation, not
          implemented in this pass.

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

    async def run(self) -> List[ThreatIndicator]:
        """
        Pipeline entry point. Executes async network gathering, hands off payload
        processing to threads, and pipes validated structures back into Pydantic models.
        """
        logger.info(f"Starting ingestion cycle across {len(self.target_feeds)} targets.")

        fetch_tasks = [self.fetch_feed_data(url) for url in self.target_feeds]
        raw_payloads = await asyncio.gather(*fetch_tasks)

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
