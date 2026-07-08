"""SentinelData Hub — FastAPI web entrypoint.

Defensive-security OSINT/CVE threat-intelligence API. This module owns the
HTTP transport layer only: process lifecycle, authentication, request
telemetry, and global exception mapping. All ingestion logic (feed
concurrency, deduplication/enrichment, HTTP fetching) is delegated to
``OSINTPipeline`` — this file does not re-implement any of that.

ASSUMED INTERFACE CONTRACT — verify against the real implementations before
first deploy. If either module's actual API differs, these are the only
symbols that need to change:

    app.models.threat.ThreatIndicator
        A pydantic.BaseModel subclass. Used here solely as a response type
        (``response_model=list[ThreatIndicator]``) — this module does not
        touch its fields directly, so internal schema changes to
        ThreatIndicator do not require edits here.

    app.data.pipeline.OSINTPipeline
        class OSINTPipeline:
            def __init__(self, target_feeds: list[str]) -> None: ...
            async def run(self) -> list[ThreatIndicator]: ...
            async def close(self) -> None: ...

Required environment variables (fail-closed — the process refuses to start
without them):

    SENTINEL_API_KEY               Shared secret required in the
                                   ``X-API-Key`` header on every request to
                                   /api/v1/threats.
    SENTINEL_FEED_URLS             Comma-separated list of OSINT/CVE feed
                                   URLs to ingest.

Optional environment variables:

    SENTINEL_ENV                    "development" enables /docs, /redoc,
                                    and /openapi.json. Any other value (or
                                    unset) disables them. Default:
                                    "production".
    SENTINEL_INGESTION_TIMEOUT_SECONDS
                                    Wall-clock budget for one full
                                    ingestion cycle before the request is
                                    failed with 504. Default: 30.
    SENTINEL_LOG_LEVEL              Root logger level. Default: "INFO".
    SENTINEL_HOST / SENTINEL_PORT   Bind address for `python -m
                                    app.main` / direct uvicorn.run()
                                    execution. Defaults: 0.0.0.0 / 8000.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Final

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import ValidationError
from sqlalchemy import case, func
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.data.pipeline import OSINTPipeline
from app.models.metrics import DashboardMetrics
from app.models.threat import ThreatIndicator

# --- PHASE 5: DATABASE SCHEMATIC INTERFACES ---
from app.database.connection import Base, engine, get_db
from app.database.models import ThreatIndicatorModel  # Pre-loads and registers table metadata with the Base object

# --------------------------------------------------------------------------- #
# Structured (JSON) logging — required for enterprise log-aggregator
# ingestion (Splunk/ELK/etc). Stdlib-only: no dependency outside the locked
# matrix.
# --------------------------------------------------------------------------- #

_RESERVED_LOG_RECORD_KEYS: Final[frozenset[str]] = frozenset(
    logging.LogRecord(
        name="", level=0, pathname="", lineno=0, msg="", args=(), exc_info=None
    ).__dict__.keys()
) | {"message", "asctime"}


class JSONLogFormatter(logging.Formatter):
    """Renders each log record as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info is not None:
            payload["exception"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key not in _RESERVED_LOG_RECORD_KEYS:
                payload[key] = value
        return json.dumps(payload, default=str)


def _configure_logging() -> logging.Logger:
    root_logger = logging.getLogger("sentineldata")
    if root_logger.handlers:
        # Idempotent under `uvicorn --reload`, which can re-import this module.
        return root_logger

    level_name = os.environ.get("SENTINEL_LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        raise RuntimeError(
            f"SENTINEL_LOG_LEVEL={level_name!r} is not a valid logging level "
            "(expected DEBUG, INFO, WARNING, ERROR, or CRITICAL)."
        )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONLogFormatter())
    root_logger.addHandler(handler)
    root_logger.setLevel(level)
    root_logger.propagate = False
    return root_logger


logger = _configure_logging()

# --------------------------------------------------------------------------- #
# Environment / configuration loading — fail-closed on anything required.
# --------------------------------------------------------------------------- #


def _load_api_key() -> str:
    key = os.environ.get("SENTINEL_API_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "SENTINEL_API_KEY is not set. Refusing to start an OSINT "
            "ingestion API without an authentication secret configured."
        )
    return key


def _load_feed_targets() -> list[str]:
    raw = os.environ.get("SENTINEL_FEED_URLS", "").strip()
    if not raw:
        raise RuntimeError(
            "SENTINEL_FEED_URLS is not set. Provide a comma-separated list "
            "of OSINT/CVE feed URLs to ingest."
        )
    targets = [url.strip() for url in raw.split(",") if url.strip()]
    if not targets:
        raise RuntimeError(
            "SENTINEL_FEED_URLS resolved to an empty target list after parsing."
        )
    return targets


def _load_ingestion_timeout_seconds() -> float:
    raw = os.environ.get("SENTINEL_INGESTION_TIMEOUT_SECONDS", "30").strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(
            f"SENTINEL_INGESTION_TIMEOUT_SECONDS must be numeric, got {raw!r}."
        ) from exc
    if value <= 0:
        raise RuntimeError("SENTINEL_INGESTION_TIMEOUT_SECONDS must be a positive number.")
    return value


_SENTINEL_ENV: Final[str] = os.environ.get("SENTINEL_ENV", "production").strip().lower()
_DOCS_ENABLED: Final[bool] = _SENTINEL_ENV in {"development", "dev", "local"}

# --------------------------------------------------------------------------- #
# Application lifecycle
# --------------------------------------------------------------------------- #


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Fail closed before any resource is opened
    try:
        api_key = _load_api_key()
        feed_targets = _load_feed_targets()
        ingestion_timeout = _load_ingestion_timeout_seconds()

        # Automatically generate SQLite structure on boot
        Base.metadata.create_all(bind=engine)

        logger.info(
            "startup.begin",
            extra={"feed_count": len(feed_targets), "environment": _SENTINEL_ENV},
        )

        start = time.monotonic()

        # Initialize our pipeline instance cleanly
        pipeline = OSINTPipeline(target_feeds=feed_targets)

        # Bind active state variables straight to the FastAPI runtime
        app.state.pipeline = pipeline
        app.state.api_key = api_key
        app.state.ingestion_timeout_seconds = ingestion_timeout
        app.state.feed_count = len(feed_targets)

        logger.info(
            "startup.complete",
            extra={"elapsed_ms": round((time.monotonic() - start) * 1000, 2)},
        )
    except Exception as exc:
        logger.critical("startup.pipeline_init_failed", exc_info=True)
        raise RuntimeError("Application failed to initialize secure infrastructure.") from exc

    try:
        yield
    finally:
        logger.info("shutdown.begin")
        try:
            await pipeline.close()
        except Exception:
            logger.error("shutdown.pipeline_close_failed", exc_info=True)
        logger.info("shutdown.complete")


app = FastAPI(
    title="SentinelData Hub — OSINT Threat Intelligence API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)

# --------------------------------------------------------------------------- #
# Request telemetry middleware
# --------------------------------------------------------------------------- #


@app.middleware("http")
async def request_telemetry_middleware(request: Request, call_next: Any) -> Any:
    start = time.monotonic()
    try:
        response = await call_next(request)
    except Exception:
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        logger.error(
            "request.failed",
            exc_info=True,
            extra={"method": request.method, "path": request.url.path, "elapsed_ms": elapsed_ms},
        )
        raise
    elapsed_ms = round((time.monotonic() - start) * 1000, 2)
    logger.info(
        "request.completed",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "elapsed_ms": elapsed_ms,
        },
    )
    return response


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(
    request: Request,
    provided_key: str | None = Depends(_api_key_header),
) -> None:
    expected_key: str | None = getattr(request.app.state, "api_key", None)
    if not expected_key:
        # Unreachable in practice — lifespan fails closed on a missing key —
        # but kept as defense-in-depth against future refactors.
        logger.critical("auth.misconfigured_missing_expected_key")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured on this instance.",
        )
    if provided_key is None or not secrets.compare_digest(provided_key, expected_key):
        logger.warning("auth.rejected", extra={"path": request.url.path})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header.",
        )


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #


@app.get(
    "/api/v1/threats",
    response_model=list[ThreatIndicator],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_api_key)],
    summary="Run a concurrent OSINT ingestion cycle and return validated threat indicators.",
)
async def get_threats(request: Request) -> list[ThreatIndicator]:
    pipeline: OSINTPipeline = request.app.state.pipeline
    timeout_seconds: float = request.app.state.ingestion_timeout_seconds

    cycle_start = time.monotonic()
    try:
        indicators = await asyncio.wait_for(
            pipeline.run(),
            timeout=timeout_seconds
        )
    except TimeoutError as exc:
        logger.error("ingestion.timeout", extra={"timeout_seconds": timeout_seconds})
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="The ingestion cycle exceeded the configured timeout.",
        ) from exc
    except httpx.HTTPError as exc:
        logger.error("ingestion.upstream_transport_error", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="One or more upstream OSINT feeds were unreachable.",
        ) from exc
    except ValidationError as exc:
        logger.error("ingestion.schema_validation_error", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream feed data failed ThreatIndicator schema validation.",
        ) from exc

    elapsed_ms = round((time.monotonic() - cycle_start) * 1000, 2)

    if len(indicators) == 0:
        logger.error(
            "ingestion.wholesale_outage_empty_cycle",
            extra={"feed_count": request.app.state.feed_count, "elapsed_ms": elapsed_ms}
        )
    else:
        logger.info(
            "ingestion.cycle_complete",
            extra={"indicator_count": len(indicators), "elapsed_ms": elapsed_ms},
        )

    return indicators


@app.get(
    "/api/v1/metrics",
    response_model=DashboardMetrics,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_api_key)],
    summary="Return server-computed KPI aggregates over the stored threat indicator set.",
)
def get_metrics(db: Session = Depends(get_db)) -> DashboardMetrics:
    """Aggregate telemetry over the SQLite-held indicator store.

    Deliberately a plain `def`, not `async def`. FastAPI dispatches sync
    route functions -- and sync dependencies, which get_db is: a plain
    generator, not an async generator -- to its worker threadpool
    automatically, off the event loop. That is the same non-blocking
    guarantee _persist_indicators needed an explicit asyncio.to_thread for
    in pipeline.py, obtained here for free because there is no async code
    path in this function to accidentally share the event loop with.

    All three counts and the freshness timestamp are computed in ONE query
    via SQL aggregates (COUNT / SUM(CASE...) / MAX), so this scales with an
    index scan against threat_indicators, not with a full-table pull into
    Python that would otherwise be the obvious -- and wrong, at scale --
    first draft.
    """
    row = db.query(
        func.count(ThreatIndicatorModel.id).label("total_indicators"),
        func.sum(
            case((ThreatIndicatorModel.risk_score >= 5.0, 1), else_=0)
        ).label("critical_count"),
        func.sum(
            case(
                (
                    (ThreatIndicatorModel.risk_score >= 4.0)
                    & (ThreatIndicatorModel.risk_score < 5.0),
                    1,
                ),
                else_=0,
            )
        ).label("high_count"),
        func.max(ThreatIndicatorModel.ingested_at).label("latest_ingestion_time"),
    ).one()

    latest_ingestion_time = row.latest_ingestion_time
    if latest_ingestion_time is not None and latest_ingestion_time.tzinfo is None:
        # SQLite has no true timezone-aware column type -- every datetime
        # written here (see database/models.py: ingested_at default is
        # datetime.utcnow) round-trips through the driver as naive. We know
        # by construction it was always written as UTC, so re-localizing on
        # read is a correct reconstruction, not a guess.
        latest_ingestion_time = latest_ingestion_time.replace(tzinfo=timezone.utc)

    return DashboardMetrics(
        total_indicators=row.total_indicators or 0,
        critical_count=row.critical_count or 0,
        high_count=row.high_count or 0,
        latest_ingestion_time=latest_ingestion_time,
    )


@app.get("/healthz", include_in_schema=False, status_code=status.HTTP_200_OK)
async def healthz(request: Request) -> dict[str, str]:
    """Unauthenticated liveness/readiness probe for the Docker/orchestration layer."""
    pipeline_ready = getattr(request.app.state, "pipeline", None) is not None
    return {"status": "ok" if pipeline_ready else "degraded"}


# --------------------------------------------------------------------------- #
# Global exception mapping
# --------------------------------------------------------------------------- #


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    logger.warning(
        "request.validation_error",
        extra={"path": request.url.path, "errors": exc.errors()},
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Request validation failed.", "errors": exc.errors()},
    )


@app.exception_handler(StarletteHTTPException)
async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    logger.info(
        "request.http_exception",
        extra={"path": request.url.path, "status_code": exc.status_code},
    )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def handle_unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    logger.critical(
        "request.unhandled_exception",
        exc_info=True,
        extra={"path": request.url.path},
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred."},
    )


# --------------------------------------------------------------------------- #
# Direct execution entrypoint (container CMD / local dev)
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=os.environ.get("SENTINEL_HOST", "0.0.0.0"),
        port=int(os.environ.get("SENTINEL_PORT", "8000")),
        log_config=None,  # We own logging via _configure_logging(); don't let
                          # uvicorn install its own handlers on top of it.
    )
