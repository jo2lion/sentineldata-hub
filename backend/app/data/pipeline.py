import asyncio
import logging
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
from app.database.connection import SessionLocal
from app.database.models import ThreatIndicatorModel

# Explicit logging schema setup for system tracking
logger = logging.getLogger("sentineldata.pipeline")

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
        """Fetch raw XML/RSS data asynchronously.

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

    def _parse_and_vectorize(self, raw_xml_data: List[str]) -> pd.DataFrame:
        """
        Parses raw feed text using feedparser inside a synchronous wrapper
        optimized for downstream DataFrame vectorization.
        """
        extracted_records = []

        for raw_xml in raw_xml_data:
            if not raw_xml:
                continue
            parsed = feedparser.parse(raw_xml)
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
        df["observed_at"] = pd.to_datetime(df["published_raw"], errors="coerce", utc=True)
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
        Synchronous SQLAlchemy ORM write path. Deliberately NOT async -- this
        runs on a worker thread via asyncio.to_thread (see run()), never
        directly on the event loop. Calling this inline from async code
        (as it previously was) blocks every other concurrent request on the
        process for the duration of every DB round-trip in the loop below.

        Known follow-up, not fixed here: this is one SELECT per candidate
        indicator (N+1). For a genuinely high-throughput pipeline this should
        become a single batched existence check (SELECT id WHERE id IN (...))
        or an INSERT ... ON CONFLICT DO NOTHING upsert. Left as-is because
        that's a real design decision (batch size, conflict semantics), not
        a one-line fix -- flagging rather than silently changing behavior.
        """
        stored_count = 0
        db: Session = SessionLocal()
        try:
            for indicator in validated_indicators:
                exists = db.query(ThreatIndicatorModel).filter(ThreatIndicatorModel.id == indicator.id).first()
                if not exists:
                    db_record = ThreatIndicatorModel(
                        id=indicator.id,
                        title=indicator.title,
                        link=indicator.source_url,
                        summary=indicator.description,
                        published_date=indicator.observed_at,
                        risk_score=indicator.risk_score
                    )
                    db.add(db_record)
                    stored_count += 1

            if stored_count > 0:
                db.commit()
                logger.info(f"Database sync complete. Saved {stored_count} new indicators to SQLite.")
        except Exception:
            db.rollback()
            logger.error("Database persistence sub-cycle failed.", exc_info=True)
            # Fail-open: don't crash the network request if storage hits a localized snag
        finally:
            db.close()

        return stored_count

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
            await asyncio.to_thread(self._persist_indicators, validated_indicators)

        logger.info(f"Ingestion lifecycle completed. Emitted {len(validated_indicators)} validated threat vectors.")
        return validated_indicators

    async def close(self):
        """Gracefully release HTTP connections."""
        if self._http_client is not None:
            await self._http_client.aclose()
