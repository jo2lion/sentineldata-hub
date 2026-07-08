/**
 * Mirrors backend/app/models/threat.py::ThreatIndicator exactly, read directly
 * from that file (not guessed). Every field there is required (pydantic
 * Field(...), no Optional[X] anywhere), so nothing here is optional or
 * nullable. If threat.py ever adds an Optional[X] field, model it as
 * `X | null` — Pydantic serializes an unset Optional as JSON `null`, not as
 * an absent key — not as `field?: X`.
 */
export interface ThreatIndicator {
  /** Deterministic UUIDv5 computed from the payload hash. */
  id: string;
  title: string;
  description: string;
  /** Backend field name is source_url, not "source" or "link". */
  source_url: string;
  /** Bounded 1.0–5.0 by the backend's Field(ge=1.0, le=5.0). Not a 0–1 confidence score. */
  risk_score: number;
  /** ISO 8601 datetime string. Backend now enforces tz-aware UTC at validation time. */
  observed_at: string;
}

/**
 * Mirrors backend/app/models/metrics.py::DashboardMetrics exactly.
 *
 * NOTE on nullability -- this deliberately deviates from a literal
 * "latest_ingestion_time: string" spec. The backend computes this field via
 * SQL MAX(ingested_at) over the stored indicator table. On an empty table
 * (fresh deploy, or a wholesale outage before the first successful cycle)
 * that MAX is SQL NULL, which FastAPI/Pydantic serializes as JSON `null` --
 * not an absent key, not an empty string. Typing this as a bare `string`
 * would compile cleanly and then lie at runtime the first time someone
 * calls `.toLocaleString()` (or similar) on a `null` typed as `string`.
 * `string | null` is what the backend actually sends; the frontend must
 * handle both.
 */
export interface DashboardMetrics {
  total_indicators: number;
  critical_count: number;
  high_count: number;
  latest_ingestion_time: string | null;
}
