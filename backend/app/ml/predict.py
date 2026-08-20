"""ML model prediction and inference"""

import logging
import numpy as np
from typing import Tuple, Optional
from pathlib import Path
import pickle

logger = logging.getLogger(__name__)


class ModelPredictor:
    """Load and use trained ML model for predictions"""
    
    def __init__(self, model_path: str = "app/ml/model.pkl", scaler_path: str = "app/ml/scaler.pkl"):
        self.model_path = Path(model_path)
        self.scaler_path = Path(scaler_path)
        self.model = None
        self.scaler = None
        self.is_loaded = False
    
    def load(self) -> bool:
        """
        Load model and scaler from disk
        
        Returns:
            True if successful, False otherwise
        """
        if self.is_loaded and self.model is not None:
            return True
        
        try:
            # Check if files exist
            if not self.model_path.exists():
                logger.warning(f"Model not found at {self.model_path}")
                self._create_default_model()
                return True
            
            if not self.scaler_path.exists():
                logger.warning(f"Scaler not found at {self.scaler_path}")
                self._create_default_model()
                return True
            
            # Load model
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            # Load scaler
            with open(self.scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            
            self.is_loaded = True
            logger.info("Model and scaler loaded successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self._create_default_model()
            return False
    
    def _create_default_model(self):
        """
        Create a default model if files don't exist
        Uses simple rule-based approach
        """
        try:
            from sklearn.linear_model import LogisticRegression
            from sklearn.preprocessing import StandardScaler
            
            logger.info("Creating default model...")
            
            # Create a simple model
            self.model = LogisticRegression(random_state=42)
            self.scaler = StandardScaler()
            
            # Fit with dummy data
            X_dummy = np.array([
                [0.9, 0.8, 0.85, 0.88, 0.9, 0.8, 0.5],  # Phishing
                [0.1, 0.2, 0.15, 0.12, 0.1, 0.2, 0.9],  # Legitimate
            ])
            y_dummy = np.array([1, 0])
            
            self.scaler.fit(X_dummy)
            X_scaled = self.scaler.transform(X_dummy)
            self.model.fit(X_scaled, y_dummy)
            
            self.is_loaded = True
            logger.info("Default model created")
        
        except Exception as e:
            logger.error(f"Error creating default model: {e}")
    
    def predict(self, features: np.ndarray) -> Tuple[float, float]:
        """
        Predict phishing probability for features
        
        Args:
            features: 1D numpy array with 7 features
        
        Returns:
            (prediction_label, probability_score)
        """
        if not self.is_loaded or self.model is None:
            logger.error("Model not loaded")
            return 0, 0.5
        
        try:
            # Ensure correct shape
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict
            prediction = self.model.predict(features_scaled)[0]
            probability = self.model.predict_proba(features_scaled)[0, 1]
            
            return int(prediction), float(probability)
        
        except Exception as e:
            logger.error(f"Error in prediction: {e}")
            return 0, 0.5
    
    def predict_batch(self, features_list: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict for multiple samples
        
        Returns:
            (predictions, probabilities)
        """
        if not self.is_loaded or self.model is None:
            logger.error("Model not loaded")
            return np.zeros(len(features_list)), np.full(len(features_list), 0.5)
        
        try:
            features_scaled = self.scaler.transform(features_list)
            predictions = self.model.predict(features_scaled)
            probabilities = self.model.predict_proba(features_scaled)[:, 1]
            
            return predictions, probabilities
        
        except Exception as e:
            logger.error(f"Error in batch prediction: {e}")
            return np.zeros(len(features_list)), np.full(len(features_list), 0.5)
