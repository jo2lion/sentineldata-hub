from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ThreatIndicator(BaseModel):
    """
    Unified Data Model representing a validated threat vector or OSINT/CVE indicator.
    """

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)

    id: str = Field(..., description="Deterministic UUIDv5 calculated from the payload hash.")
    title: str = Field(..., description="The headline or signature identification string of the security advisory.")
    description: str = Field(..., description="Unstructured textual payload containing vulnerability or threat data details.")
    source_url: str = Field(..., description="The definitive remote web URL reference string for origin validation.")
    risk_score: float = Field(..., ge=1.0, le=5.0, description="Calculated threat vector metric bound strictly between 1.0 and 5.0.")
    observed_at: datetime = Field(..., description="Temporal timestamp tracking when the entity was parsed or published.")

    @field_validator("observed_at")
    @classmethod
    def _require_timezone_aware_utc(cls, value: datetime) -> datetime:
        """Project directive: all timestamps must be timezone-aware, defaulting to UTC.

        A naive datetime here would pass validation silently and then raise
        TypeError the first time it's compared against an aware datetime
        (e.g. datetime.now(timezone.utc)) anywhere downstream. Reject naive
        input outright rather than silently guessing its timezone.
        """
        if value.tzinfo is None:
            raise ValueError(
                "observed_at must be timezone-aware (naive datetimes are rejected, "
                "not silently assumed to be UTC) — the upstream feed parser must "
                "attach a timezone before this reaches validation."
            )
        return value.astimezone(timezone.utc)
