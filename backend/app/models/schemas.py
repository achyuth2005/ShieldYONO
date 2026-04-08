"""Pydantic response models for the API."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ReasonOutput(BaseModel):
    code: str
    message: str
    message_hi: str = ""
    severity: str  # HIGH, MEDIUM, LOW, INFO


class ActionOutput(BaseModel):
    block: bool
    warn: bool
    message: str
    message_hi: str = ""


class ScanResponse(BaseModel):
    model_config = {"protected_namespaces": ()}
    url: str
    resolved_url: Optional[str] = None
    risk_score: float = Field(ge=0, le=100)
    risk_tier: str  # SAFE, SUSPICIOUS, PHISHING
    confidence: float = Field(ge=0, le=1)
    verdict: str
    verdict_hi: str = ""
    reasons: list[ReasonOutput] = []
    features: dict = {}
    action: ActionOutput
    scan_id: str
    scanned_at: str
    cached: bool = False
    model_used: str = "heuristic"


class ErrorResponse(BaseModel):
    error: str
    detail: str
    url: Optional[str] = None


class AnalyticsResponse(BaseModel):
    total_scans: int
    safe_count: int
    suspicious_count: int
    phishing_count: int
    avg_risk_score: float


class RecentScanItem(BaseModel):
    scan_id: str
    url: str
    risk_score: float
    risk_tier: str
    verdict: str
    scanned_at: str
