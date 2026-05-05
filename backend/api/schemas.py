"""Pydantic schemas for API requests and responses."""
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class SubmitURL(BaseModel):
    """Schema for URL submission requests."""
    url: HttpUrl
    detonate: bool = False
    provider: Optional[str] = Field(None, pattern="^(anyrun|joe)$")


class SubmissionResponse(BaseModel):
    """Schema for submission response."""
    id: str
    status: str
    created_at: Optional[datetime] = None


class ReportResponse(BaseModel):
    """Schema for report response."""
    id: str
    status: str
    score: Optional[float] = None
    report_markdown: Optional[str] = None
    enrichment: Optional[Dict[str, Any]] = None
    sandbox: Optional[Dict[str, Any]] = None
    iocs: Optional[Dict[str, List[str]]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class HealthResponse(BaseModel):
    """Schema for health check response."""
    status: str
    timestamp: datetime
    version: str = "0.1.0"


class MetricsResponse(BaseModel):
    """Schema for metrics response."""
    total_submissions: int
    submissions_last_24h: int
    average_score: float
    high_risk_count: int
    detonations_today: int
    model_version: str
    last_drift_check: Optional[datetime] = None
    drift_detected: bool = False
