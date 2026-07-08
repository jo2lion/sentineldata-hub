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
