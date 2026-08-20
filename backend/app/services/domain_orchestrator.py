"""Main domain analysis orchestrator"""

import logging
import asyncio
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

from app.services.domain_analyzer import DomainAnalyzer
from app.services.content_analyzer import ContentAnalyzer
from app.services.visual_analyzer import VisualAnalyzer
from app.services.feature_engine import FeatureExtractor, RiskCalculator
from app.ml.predict import ModelPredictor

logger = logging.getLogger(__name__)


class DomainAnalysisOrchestrator:
    """Orchestrate complete analysis pipeline"""
    
    def __init__(self, config):
        self.config = config
        self.domain_analyzer = DomainAnalyzer()
        self.content_analyzer = ContentAnalyzer()
        self.visual_analyzer = VisualAnalyzer()
        self.feature_extractor = FeatureExtractor()
        self.risk_calculator = RiskCalculator(
            threshold_low=config.PHISHING_THRESHOLD_LOW,
            threshold_medium=config.PHISHING_THRESHOLD_MEDIUM,
            threshold_high=config.PHISHING_THRESHOLD_HIGH,
        )
        self.model_predictor = ModelPredictor(
            model_path=config.MODEL_PATH,
            scaler_path=config.SCALER_PATH,
        )
        self.model_predictor.load()
    
    async def analyze_domain(
        self,
        url: str,
        watchlist_domain: Optional[str] = None,
    ) -> Dict:
        """
        Analyze a domain for phishing risk
        
        Returns:
            Complete analysis result with all scores and evidence
        """
        start_time = time.time()
        
        try:
            logger.info(f"Starting analysis for: {url}")
            
            # Step 1: Parse and validate URL
            parsed_url = self._validate_and_normalize_url(url)
            if not parsed_url:
                return self._error_response("Invalid URL format", start_time)
            
            candidate_domain, _, _ = self.domain_analyzer.parse_url(url)
            logger.info(f"Extracted domain: {candidate_domain}")
            
            # Step 2: If no watchlist domain provided, find best match
            if not watchlist_domain:
                # For now, use a default reference
                watchlist_domain = self._get_reference_domain(candidate_domain)
            
            # Step 3: Domain Analysis
            logger.info("Analyzing domain characteristics...")
            domain_analysis = self.domain_analyzer.calculate_domain_score(
                candidate_domain, watchlist_domain
            )
            
            # Step 4: Fetch webpage content
            logger.info("Fetching webpage content...")
            html_content = await self._fetch_webpage(url)
            if not html_content:
                return self._error_response("Failed to fetch webpage", start_time)
            
            # Step 5: Content Analysis
            logger.info("Analyzing HTML content...")
            visible_text = self.content_analyzer.extract_text_fingerprint(html_content)
            dom_fingerprint = self.content_analyzer.extract_dom_fingerprint(html_content)
            has_login_form, login_confidence, login_details = self.content_analyzer.detect_login_form(html_content)
            
            # Step 6: Text Similarity
            logger.info("Calculating text similarity...")
            reference_text = self._get_reference_text(watchlist_domain)
            text_similarity = self.content_analyzer.calculate_text_similarity(
                visible_text, reference_text
            )
            
            # Step 7: DOM Similarity
            logger.info("Calculating DOM similarity...")
            reference_dom = self._get_reference_dom(watchlist_domain)
            dom_similarity = self.content_analyzer.calculate_dom_similarity(
                dom_fingerprint, reference_dom
            )
            
            # Step 8: Screenshot Capture and Visual Analysis
            logger.info("Capturing screenshots...")
            candidate_screenshot = await self.visual_analyzer.capture_screenshot(url, self.config.BROWSER_TIMEOUT)
            reference_screenshot = self._get_reference_screenshot(watchlist_domain)
            
            visual_similarity = 0.0
            if candidate_screenshot and reference_screenshot:
                logger.info("Calculating visual similarity...")
                visual_comparison = self.visual_analyzer.compare_screenshots_advanced(
                    candidate_screenshot, reference_screenshot
                )
                visual_similarity = visual_comparison.get("combined_similarity", 0.0)
            
            # Step 9: Feature Extraction
            logger.info("Extracting features...")
            content_analysis = {
                "text_similarity": text_similarity,
                "dom_similarity": dom_similarity,
                "login_form_confidence": login_confidence,
            }
            
            visual_analysis = {
                "visual_similarity": visual_similarity,
            }
            
            feature_scores = self.feature_extractor.extract_features(
                domain_analysis=domain_analysis,
                content_analysis=content_analysis,
                visual_analysis=visual_analysis,
                has_login_form=has_login_form,
            )
            
            # Step 10: ML Prediction
            logger.info("Running ML classifier...")
            import numpy as np
            feature_vector = self.feature_extractor.create_feature_vector(feature_scores)
            prediction_label, ml_probability = self.model_predictor.predict(feature_vector)
            
            # Step 11: Risk Calculation
            logger.info("Calculating risk score...")
            risk_score, risk_level = self.risk_calculator.calculate_risk_score(
                ml_probability, feature_scores
            )
            
            # Step 12: Generate Evidence
            logger.info("Generating evidence...")
            evidence = self.risk_calculator.generate_evidence(
                feature_scores, domain_analysis, content_analysis
            )
            
            # Step 13: Generate Explanation
            explanation = self.risk_calculator.generate_explanation(evidence)
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Compile result
            result = {
                "success": True,
                "domain": candidate_domain,
                "url": url,
                "matched_brand": watchlist_domain,
                "matched_domain": watchlist_domain,
                "phishing_probability": float(risk_score),
                "risk_level": risk_level,
                "processing_time_ms": processing_time_ms,
                "status": "completed",
                "features": feature_scores,
                "evidence": evidence,
                "explanation": explanation,
                "screenshots": {
                    "candidate": candidate_screenshot,
                    "reference": reference_screenshot,
                },
                "login_form_detected": has_login_form,
            }
            
            logger.info(f"Analysis completed in {processing_time_ms}ms. Risk: {risk_level} ({risk_score:.2%})")
            return result
        
        except Exception as e:
            logger.error(f"Analysis error: {e}", exc_info=True)
            return self._error_response(str(e), start_time)
    
    async def _fetch_webpage(self, url: str) -> Optional[str]:
        """
        Safely fetch webpage content
        """
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(
                url,
                timeout=self.config.REQUEST_TIMEOUT,
                headers=headers,
                allow_redirects=True,
                verify=False,  # For demo purposes
            )
            
            if response.status_code != 200:
                logger.warning(f"HTTP {response.status_code} for {url}")
                return None
            
            if len(response.content) > self.config.MAX_RESPONSE_SIZE:
                logger.warning(f"Response too large: {len(response.content)} bytes")
                return response.text[:self.config.MAX_RESPONSE_SIZE]
            
            return response.text
        
        except requests.Timeout:
            logger.error(f"Request timeout for {url}")
            return None
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return None
    
    def _validate_and_normalize_url(self, url: str) -> Optional[str]:
        """
        Validate and normalize URL
        """
        try:
            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            
            # Validate scheme
            if parsed.scheme not in ('http', 'https'):
                return None
            
            # Validate hostname
            if not parsed.netloc:
                return None
            
            return url
        except Exception as e:
            logger.error(f"URL validation error: {e}")
            return None
    
    def _get_reference_domain(self, candidate: str) -> str:
        """
        Get reference domain (from watchlist or generate similar)
        For demo: return a plausible reference
        """
        # Extract main domain
        parts = candidate.replace('www.', '').split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return candidate
    
    def _get_reference_text(self, domain: str) -> str:
        """
        Get reference text for domain
        Returns synthetic reference text for demo
        """
        return f"Welcome to {domain}. Secure login. Account access. Banking services."
    
    def _get_reference_dom(self, domain: str) -> Dict:
        """
        Get reference DOM fingerprint
        """
        return {
            "title": domain,
            "num_forms": 2,
            "num_inputs": 5,
            "num_buttons": 3,
            "num_links": 15,
            "num_images": 8,
            "num_scripts": 5,
            "num_stylesheets": 3,
            "password_inputs": 1,
            "email_inputs": 1,
        }
    
    def _get_reference_screenshot(self, domain: str) -> Optional[str]:
        """
        Get reference screenshot for domain
        For demo: return None (will skip visual comparison)
        In production: retrieve from database
        """
        return None
    
    def _error_response(self, error_msg: str, start_time: float) -> Dict:
        """
        Generate error response
        """
        processing_time_ms = int((time.time() - start_time) * 1000)
        
        return {
            "success": False,
            "error": error_msg,
            "processing_time_ms": processing_time_ms,
            "status": "failed",
        }
