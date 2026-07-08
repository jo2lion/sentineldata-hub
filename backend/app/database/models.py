from datetime import datetime, timezone

from sqlalchemy import Column, String, Float, DateTime
from sqlalchemy.types import TypeDecorator

from .connection import Base


class UTCDateTime(TypeDecorator):
    """
    Timezone-aware UTC datetime column type, layered over SQLAlchemy's
    SQLite DateTime.

    SQLite has no native timezone-aware storage, and SQLAlchemy's SQLite
    DateTime bind/result processors reflect that honestly: the bind
    processor writes a datetime's year/month/day/hour/minute/second/
    microsecond fields verbatim into the column and never inspects
    .tzinfo, and the result processor parses the stored string back into a
    NAIVE datetime with no way to recover whether the original value was
    aware or what offset it carried. Every plain DateTime column in this
    file was therefore "aware in the application's head, naive on the wire
    and naive again on the way back out" -- the exact naive/aware
    ambiguity pipeline.py's datetime-hardening pass already eliminated at
    the point of construction (ThreatIndicator.observed_at rejects naive
    input outright; _persist_indicators now builds written_at via
    datetime.now(timezone.utc)), but never at the point of storage. This
    type closes that remaining gap explicitly, in both directions:

    - On the way IN (process_bind_param): an aware value is converted to
      UTC and has its tzinfo stripped before being hitting the underlying
      DateTime bind processor -- which would silently discard tzinfo
      anyway, so this makes that conversion an explicit, intentional step
      instead of a silent side effect of the underlying type. A naive
      value is stored as-is: this codebase's established convention (every
      write path -- ThreatIndicator's validator, pipeline.py's
      _persist_indicators and _process_batch -- only ever constructs
      UTC-aware values to begin with) is that a naive value reaching
      persistence is already UTC, not local time, so it is never silently
      reinterpreted as anything else.
    - On the way OUT (process_result_value): the naive value SQLite always
      returns is explicitly re-localized to UTC (tzinfo=timezone.utc)
      before reaching any caller. Every value read through this type is
      therefore guaranteed timezone-aware. This makes main.py's existing
      "if latest_ingestion_time.tzinfo is None: replace(tzinfo=timezone.utc)"
      re-localization in GET /api/v1/metrics provably redundant for any
      column that uses this type -- it is NOT removed here (main.py is out
      of this change's database/models.py-only scope), but is now dead
      code that is safe to delete in a follow-up: it will simply never see
      a naive value again once every read goes through this type.

    Still SQLite-specific, same portability caveat pipeline.py's batch
    upsert already documents for sqlalchemy.dialects.sqlite.insert(): a
    different backend wouldn't need this at all (e.g. PostgreSQL's
    TIMESTAMPTZ genuinely stores an offset), and would need a different
    TypeDecorator, or none, if this project ever migrates off SQLite.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class ThreatIndicatorModel(Base):
    __tablename__ = "threat_indicators"

    id = Column(String, primary_key=True, index=True)  # Will store our generated UUIDv5
    title = Column(String, nullable=False)
    link = Column(String, nullable=False)
    summary = Column(String, nullable=True)
    # published_date holds indicator.observed_at, which ThreatIndicator's own
    # validator already guarantees is UTC-aware (see models/threat.py) --
    # UTCDateTime here just makes storage/retrieval honor that same
    # guarantee instead of silently flattening it to naive on write and read.
    published_date = Column(UTCDateTime, nullable=False)
    risk_score = Column(Float, default=1.0)
    # default is now a lambda producing an explicit, timezone-aware UTC
    # value at insert time (matching pipeline.py's _persist_indicators,
    # which already supplies its own explicit written_at and therefore never
    # actually triggers this column default in practice -- this default only
    # fires for a row inserted through the ORM directly, bypassing
    # _persist_indicators' upsert path entirely). The previous
    # default=datetime.datetime.utcnow was the last remaining naive-by-
    # convention datetime construction anywhere in this project's temporal
    # data path; this removes it.
    ingested_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))