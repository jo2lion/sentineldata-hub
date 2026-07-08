"""SentinelData Hub — dashboard analytics response schema.

Backs GET /api/v1/metrics (see main.py). Server-computed KPI aggregates over
the SQLite-held threat_indicators table -- never a full table scan pulled
into Python and summed client-side.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DashboardMetrics(BaseModel):
    """Aggregate counts and freshness signal for the threat indicator store."""

    model_config = ConfigDict(str_strip_whitespace=True)

    total_indicators: int = Field(
        ..., ge=0, description="COUNT(*) over threat_indicators."
    )
    critical_count: int = Field(
        ..., ge=0, description="Indicators with risk_score >= 5.0."
    )
    high_count: int = Field(
        ..., ge=0, description="Indicators with 4.0 <= risk_score < 5.0."
    )
    latest_ingestion_time: datetime | None = Field(
        default=None,
        description=(
            "MAX(ingested_at) across all stored indicators, normalized to "
            "UTC. Null -- not a fabricated timestamp -- when the table is "
            "empty. An empty database genuinely has no 'latest ingestion' "
            "to report; claiming one would be a lie the frontend would "
            "render as if it were real telemetry."
        ),
    )
