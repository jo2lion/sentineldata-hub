import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# Default path is computed relative to this file's own location rather than
# hardcoded to a container-only absolute path. The previous default,
# "sqlite:////workspace/backend/sentinel_threats.db", is correct INSIDE the
# Docker image (WORKDIR is /workspace/backend there) but is a Linux-only path
# that does not resolve on Windows -- and this codebase has been run directly
# on Windows outside the container (pytest, local dev) earlier in this
# project. Computing it relative to __file__ resolves to the equivalent
# location on every platform without requiring SENTINEL_DB_URL to always be
# set manually for local runs.
_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "sentinel_threats.db"
DATABASE_URL = os.getenv("SENTINEL_DB_URL", f"sqlite:///{_DEFAULT_DB_PATH.as_posix()}")

# For SQLite, we enforce check_same_thread=False to allow async FastAPI threads to read safely
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """SQLAlchemy 2.0-native declarative base.

    Supersedes sqlalchemy.ext.declarative.declarative_base(), which still
    works in 2.0.x but is a deprecated compatibility shim (MovedIn20Warning)
    over what DeclarativeBase now does natively. Fully compatible with the
    legacy Column()-style model definitions in database/models.py -- no
    changes needed there.
    """
    pass


def get_db():
    """Context manager generator to safely yield and close database sessions per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
