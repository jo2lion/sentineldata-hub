from datetime import datetime
from pydantic import BaseModel, Field

class ThreatIndicator(BaseModel):
    """
    Unified Data Model representing a validated threat vector or OSINT/CVE indicator.
    """
    id: str = Field(..., description="Deterministic UUIDv5 calculated from the payload payload hash.")
    title: str = Field(..., description="The headline or signature identification string of the security advisory.")
    description: str = Field(..., description="Unstructured textual payload containing vulnerability or threat data details.")
    source_url: str = Field(..., description="The definitive remote web URL reference string for origin validation.")
    risk_score: float = Field(..., ge=1.0, le=5.0, description="Calculated threat vector metric bound strictly between 1.0 and 5.0.")
    observed_at: datetime = Field(..., description="Temporal timestamp tracking when the entity was parsed or published.")

    class Config:
        populate_by_name = True
        str_strip_whitespace = True