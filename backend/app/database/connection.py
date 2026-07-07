import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Store the database file in a persistent workspace volume location
DATABASE_URL = os.getenv("SENTINEL_DB_URL", "sqlite:////workspace/backend/sentinel_threats.db")

# For SQLite, we enforce check_same_thread=False to allow async FastAPI threads to read safely
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Context manager generator to safely yield and close database sessions per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()