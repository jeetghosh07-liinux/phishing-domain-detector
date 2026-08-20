"""SQLAlchemy models for database"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()


class WatchlistDomain(Base):
    """Legitimate domain watchlist"""
    __tablename__ = "watchlist_domains"
    
    id = Column(Integer, primary_key=True, index=True)
    brand_name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    category = Column(String(100), nullable=False)  # banking, payment, ecommerce, etc
    enabled = Column(Boolean, default=True)
    
    # Reference fingerprints
    reference_text_embedding = Column(Text, nullable=True)  # JSON serialized
    reference_visual_embedding = Column(Text, nullable=True)  # JSON serialized
    reference_phash = Column(String(64), nullable=True)
    reference_dom_fingerprint = Column(Text, nullable=True)  # JSON serialized
    reference_screenshot_path = Column(String(512), nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_fingerprint_update = Column(DateTime, nullable=True)
    
    # Relationships
    analyses = relationship("DomainAnalysis", back_populates="matched_domain_obj")
    
    def __repr__(self):
        return f"<WatchlistDomain {self.brand_name} - {self.domain}>"


class DomainAnalysis(Base):
    """Analysis result for a submitted domain"""
    __tablename__ = "domain_analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(512), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    
    # Matching
    matched_brand = Column(String(255), nullable=True)
    matched_domain_id = Column(Integer, ForeignKey("watchlist_domains.id"), nullable=True)
    
    # Risk assessment
    phishing_probability = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Processing
    processing_time_ms = Column(Integer, nullable=False)
    status = Column(String(50), default="completed")  # completed, failed, pending
    error_message = Column(Text, nullable=True)
    
    # Screenshots
    candidate_screenshot_path = Column(String(512), nullable=True)
    reference_screenshot_path = Column(String(512), nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    matched_domain_obj = relationship("WatchlistDomain", back_populates="analyses")
    feature_scores = relationship("FeatureScore", back_populates="analysis", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="analysis", cascade="all, delete-orphan")
    feedback = relationship("Feedback", back_populates="analysis", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<DomainAnalysis {self.domain} - {self.risk_level}>"


class FeatureScore(Base):
    """ML feature scores for analysis"""
    __tablename__ = "feature_scores"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("domain_analyses.id"), nullable=False, index=True)
    
    # Individual feature scores (0-1)
    domain_similarity = Column(Float, nullable=False)
    text_similarity = Column(Float, nullable=False)
    dom_similarity = Column(Float, nullable=False)
    visual_similarity = Column(Float, nullable=False)
    login_form_score = Column(Float, nullable=False)
    keyword_score = Column(Float, nullable=False)
    https_score = Column(Float, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    analysis = relationship("DomainAnalysis", back_populates="feature_scores")
    
    def __repr__(self):
        return f"<FeatureScore analysis_id={self.analysis_id}>"


class Evidence(Base):
    """Explainable evidence for risk classification"""
    __tablename__ = "evidence"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("domain_analyses.id"), nullable=False, index=True)
    
    evidence_type = Column(String(100), nullable=False)  # domain_similarity, visual, text, dom, login_form, keywords
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    score = Column(Float, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    analysis = relationship("DomainAnalysis", back_populates="evidence")
    
    def __repr__(self):
        return f"<Evidence {self.evidence_type} - {self.severity}>"


class Feedback(Base):
    """User feedback for false-positive/positive handling"""
    __tablename__ = "feedback"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("domain_analyses.id"), nullable=False, index=True)
    
    classification = Column(String(50), nullable=False)  # confirmed_phishing, false_positive, unknown
    notes = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    analysis = relationship("DomainAnalysis", back_populates="feedback")
    
    def __repr__(self):
        return f"<Feedback {self.analysis_id} - {self.classification}>"
