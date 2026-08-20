"""Pydantic schemas for API validation and serialization"""

from pydantic import BaseModel, HttpUrl, Field
from datetime import datetime
from typing import Optional, List


# ============ Watchlist Schemas ============

class WatchlistDomainCreate(BaseModel):
    """Schema for creating watchlist entry"""
    brand_name: str = Field(..., min_length=1, max_length=255)
    domain: str = Field(..., min_length=1, max_length=255)
    category: str = Field(..., min_length=1, max_length=100)
    enabled: bool = True


class WatchlistDomainUpdate(BaseModel):
    """Schema for updating watchlist entry"""
    brand_name: Optional[str] = None
    domain: Optional[str] = None
    category: Optional[str] = None
    enabled: Optional[bool] = None


class WatchlistDomainResponse(BaseModel):
    """Schema for watchlist domain response"""
    id: int
    brand_name: str
    domain: str
    category: str
    enabled: bool
    created_at: datetime
    updated_at: datetime
    last_fingerprint_update: Optional[datetime] = None
    
    class Config:
        from_attributes = True


# ============ Feature Schemas ============

class FeatureScoreResponse(BaseModel):
    """Schema for feature scores"""
    domain_similarity: float
    text_similarity: float
    dom_similarity: float
    visual_similarity: float
    login_form_score: float
    keyword_score: float
    https_score: float
    
    class Config:
        from_attributes = True


# ============ Evidence Schemas ============

class EvidenceResponse(BaseModel):
    """Schema for evidence"""
    id: int
    evidence_type: str
    description: str
    severity: str
    score: Optional[float] = None
    
    class Config:
        from_attributes = True


# ============ Analysis Schemas ============

class DomainAnalysisCreate(BaseModel):
    """Schema for creating analysis"""
    url: str = Field(..., min_length=1, max_length=512)


class DomainAnalysisResponse(BaseModel):
    """Schema for analysis response"""
    id: int
    domain: str
    url: str
    matched_brand: Optional[str] = None
    phishing_probability: float
    risk_level: str
    processing_time_ms: int
    status: str
    created_at: datetime
    updated_at: datetime
    features: Optional[FeatureScoreResponse] = None
    evidence: List[EvidenceResponse] = []
    candidate_screenshot_path: Optional[str] = None
    reference_screenshot_path: Optional[str] = None
    
    class Config:
        from_attributes = True


class BatchAnalysisRequest(BaseModel):
    """Schema for batch analysis"""
    urls: List[str] = Field(..., min_items=1, max_items=100)


class BatchAnalysisResponse(BaseModel):
    """Schema for batch analysis response"""
    total: int
    completed: int
    failed: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    average_processing_time_ms: float
    results: List[DomainAnalysisResponse]


# ============ Feedback Schemas ============

class FeedbackCreate(BaseModel):
    """Schema for feedback"""
    classification: str = Field(..., pattern="^(confirmed_phishing|false_positive|unknown)$")
    notes: Optional[str] = None


class FeedbackResponse(BaseModel):
    """Schema for feedback response"""
    id: int
    analysis_id: int
    classification: str
    notes: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


# ============ Health Check ============

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    database: str
    redis: str
    model_loaded: bool
