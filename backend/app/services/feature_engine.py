"""ML feature extraction and pipeline"""

import logging
from typing import Dict, List, Tuple
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract and fuse ML features"""
    
    def __init__(self):
        self.feature_names = [
            "domain_similarity",
            "text_similarity",
            "dom_similarity",
            "visual_similarity",
            "login_form_score",
            "keyword_score",
            "https_score",
        ]
    
    def extract_features(
        self,
        domain_analysis: Dict,
        content_analysis: Dict,
        visual_analysis: Dict,
        has_login_form: bool = False,
    ) -> Dict[str, float]:
        """
        Extract complete feature vector from analysis results
        
        Returns:
            Dictionary with all feature scores (0-1)
        """
        features = {}
        
        # Domain similarity
        features["domain_similarity"] = domain_analysis.get("similarity_score", 0.0)
        
        # Text similarity
        features["text_similarity"] = content_analysis.get("text_similarity", 0.0)
        
        # DOM similarity
        features["dom_similarity"] = content_analysis.get("dom_similarity", 0.0)
        
        # Visual similarity
        features["visual_similarity"] = visual_analysis.get("visual_similarity", 0.0)
        
        # Login form score (based on presence and confidence)
        login_confidence = content_analysis.get("login_form_confidence", 0.0)
        features["login_form_score"] = login_confidence if has_login_form else 0.0
        
        # Keyword score
        features["keyword_score"] = domain_analysis.get("keyword_score", 0.0)
        
        # HTTPS score (simplified: assume 0.9 if HTTPS, 0.5 if HTTP)
        # This would be determined from URL scheme
        features["https_score"] = 0.9  # Default optimistic
        
        # Ensure all values are in [0, 1]
        for key in features:
            features[key] = max(0.0, min(1.0, features[key]))
        
        return features
    
    def create_feature_vector(self, features: Dict[str, float]) -> np.ndarray:
        """
        Create numpy feature vector from features dict
        
        Returns:
            1D numpy array with features in consistent order
        """
        vector = np.array([
            features.get(name, 0.0) for name in self.feature_names
        ], dtype=np.float32)
        
        return vector
    
    def aggregate_features(self, features: Dict[str, float]) -> Dict[str, any]:
        """
        Calculate aggregate statistics from features
        """
        values = list(features.values())
        
        aggregated = {
            "mean_score": float(np.mean(values)),
            "max_score": float(np.max(values)),
            "min_score": float(np.min(values)),
            "std_dev": float(np.std(values)),
            "num_high_features": sum(1 for v in values if v > 0.7),
            "num_low_features": sum(1 for v in values if v < 0.3),
        }
        
        return aggregated


class RiskCalculator:
    """Calculate risk scores and levels"""
    
    def __init__(
        self,
        threshold_low: float = 0.29,
        threshold_medium: float = 0.59,
        threshold_high: float = 0.79,
    ):
        self.threshold_low = threshold_low
        self.threshold_medium = threshold_medium
        self.threshold_high = threshold_high
    
    def calculate_risk_score(
        self,
        ml_probability: float,
        feature_scores: Dict[str, float]
    ) -> Tuple[float, str]:
        """
        Calculate final risk score and level
        
        Returns:
            (probability_score, risk_level)
        """
        # Use ML probability directly
        risk_score = ml_probability
        
        # Adjust based on feature consistency
        high_features = sum(1 for v in feature_scores.values() if v > 0.7)
        if high_features >= 5:  # Most features indicate phishing
            risk_score = min(1.0, risk_score + 0.1)
        elif high_features <= 1:  # Most features indicate legitimate
            risk_score = max(0.0, risk_score - 0.1)
        
        # Determine risk level
        if risk_score <= self.threshold_low:
            risk_level = "LOW"
        elif risk_score <= self.threshold_medium:
            risk_level = "MEDIUM"
        elif risk_score <= self.threshold_high:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        return risk_score, risk_level
    
    def generate_evidence(
        self,
        feature_scores: Dict[str, float],
        domain_analysis: Dict,
        content_analysis: Dict,
    ) -> List[Dict[str, any]]:
        """
        Generate explainable evidence for risk classification
        """
        evidence = []
        
        # Domain similarity evidence
        domain_sim = feature_scores.get("domain_similarity", 0.0)
        if domain_sim > 0.8:
            evidence.append({
                "type": "domain_similarity",
                "description": f"Domain strongly resembles legitimate domain ({domain_sim:.1%} similar)",
                "severity": "high",
                "score": domain_sim,
            })
        elif domain_sim > 0.6:
            evidence.append({
                "type": "domain_similarity",
                "description": f"Domain moderately resembles legitimate domain ({domain_sim:.1%} similar)",
                "severity": "medium",
                "score": domain_sim,
            })
        
        # Text similarity evidence
        text_sim = feature_scores.get("text_similarity", 0.0)
        if text_sim > 0.8:
            evidence.append({
                "type": "text_similarity",
                "description": "Page content is highly similar to legitimate website",
                "severity": "high",
                "score": text_sim,
            })
        
        # DOM similarity evidence
        dom_sim = feature_scores.get("dom_similarity", 0.0)
        if dom_sim > 0.8:
            evidence.append({
                "type": "dom_similarity",
                "description": "Page structure strongly resembles legitimate website",
                "severity": "high",
                "score": dom_sim,
            })
        
        # Visual similarity evidence
        visual_sim = feature_scores.get("visual_similarity", 0.0)
        if visual_sim > 0.8:
            evidence.append({
                "type": "visual_similarity",
                "description": "Screenshot is highly similar to legitimate website",
                "severity": "high",
                "score": visual_sim,
            })
        
        # Login form evidence
        login_score = feature_scores.get("login_form_score", 0.0)
        if login_score > 0.5:
            evidence.append({
                "type": "login_form",
                "description": "Page contains login/authentication form",
                "severity": "medium",
                "score": login_score,
            })
        
        # Keyword evidence
        keyword_score = feature_scores.get("keyword_score", 0.0)
        keyword_count = domain_analysis.get("keyword_count", 0)
        if keyword_score > 0.5:
            evidence.append({
                "type": "suspicious_keywords",
                "description": f"Domain contains {keyword_count} suspicious keywords (verify, confirm, update, etc.)",
                "severity": "medium",
                "score": keyword_score,
            })
        
        # Typosquat indicators
        typosquat_indicators = domain_analysis.get("typosquat_indicators", [])
        if typosquat_indicators:
            evidence.append({
                "type": "typosquat_indicators",
                "description": f"Domain exhibits typosquatting patterns: {', '.join(typosquat_indicators)}",
                "severity": "high",
                "score": 0.8,
            })
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        evidence.sort(key=lambda x: severity_order.get(x["severity"], 4))
        
        return evidence
    
    def generate_explanation(self, evidence: List[Dict[str, any]]) -> str:
        """
        Generate natural language explanation from evidence
        """
        if not evidence:
            return "No significant indicators of phishing detected."
        
        # Start with top 3 pieces of evidence
        top_evidence = evidence[:3]
        explanations = []
        
        for ev in top_evidence:
            explanations.append(f"- {ev['description']}")
        
        explanation = (
            "The following factors contributed to this risk classification:\n\n" +
            "\n".join(explanations) +
            "\n\nThese combined signals suggest a potential phishing threat."
        )
        
        return explanation
