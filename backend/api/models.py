"""Database models for the phishing triage system."""
from sqlalchemy import create_engine, Column, String, Float, JSON, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///storage/submissions.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Submission(Base):
    """Model for tracking phishing submissions."""
    __tablename__ = "submissions"
    
    id = Column(String, primary_key=True, index=True)
    submission_type = Column(String)  # 'url' or 'email'
    url = Column(String, nullable=True)
    email_content = Column(Text, nullable=True)
    score = Column(Float, nullable=True)
    status = Column(String, default="queued")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Enrichment data
    urlhaus_data = Column(JSON, nullable=True)
    sandbox_data = Column(JSON, nullable=True)
    
    # Detonation settings
    detonate = Column(Boolean, default=False)
    sandbox_provider = Column(String, nullable=True)
    
    # Results
    report_markdown = Column(Text, nullable=True)
    iocs = Column(JSON, nullable=True)
    
    # Metadata
    features = Column(JSON, nullable=True)
    enrichment = Column(JSON, nullable=True)


def init_db():
    """Initialize the database."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
