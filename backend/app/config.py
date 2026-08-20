"""Application configuration"""

from typing import Optional
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings from environment variables"""
    
    # Application
    APP_NAME: str = "Phishing Domain Detector"
    APP_ENV: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    
    # Database
    DATABASE_URL: str = "postgresql://phishing_user:phishing_pass@localhost:5432/phishing_detector"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"
    
    # ML Model
    MODEL_PATH: str = "app/ml/model.pkl"
    SCALER_PATH: str = "app/ml/scaler.pkl"
    
    # Web Crawling
    REQUEST_TIMEOUT: int = 15
    MAX_RESPONSE_SIZE: int = 10485760  # 10MB
    MAX_REDIRECTS: int = 5
    BROWSER_TIMEOUT: int = 30000  # 30s in ms
    
    # Analysis
    SEED_DATABASE: bool = True
    DEMO_MODE: bool = False
    CACHE_REFERENCE_FINGERPRINTS: bool = True
    
    # Security
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_PERIOD: int = 3600
    
    # Feature Thresholds
    PHISHING_THRESHOLD_LOW: float = 0.29
    PHISHING_THRESHOLD_MEDIUM: float = 0.59
    PHISHING_THRESHOLD_HIGH: float = 0.79
    
    class Config:
        env_file = ".env"
        case_sensitive = True
    
    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS origins from comma-separated string"""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
