from sqlalchemy import Column, String, Float, DateTime
from .connection import Base
import datetime

class ThreatIndicatorModel(Base):
    __tablename__ = "threat_indicators"

    id = Column(String, primary_key=True, index=True)  # Will store our generated UUIDv5
    title = Column(String, nullable=False)
    link = Column(String, nullable=False)
    summary = Column(String, nullable=True)
    published_date = Column(DateTime, nullable=False)
    risk_score = Column(Float, default=1.0)
    ingested_at = Column(DateTime, default=datetime.datetime.utcnow)