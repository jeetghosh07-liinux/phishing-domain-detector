"""ML model training and evaluation"""

import logging
import pickle
import json
from pathlib import Path
from typing import Dict, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve, auc
)
import pandas as pd

logger = logging.getLogger(__name__)


class ModelTrainer:
    """Train ML classifier for phishing detection"""
    
    def __init__(self, model_path: str = "app/ml/model.pkl", scaler_path: str = "app/ml/scaler.pkl"):
        self.model_path = Path(model_path)
        self.scaler_path = Path(scaler_path)
        self.model = None
        self.scaler = None
        self.feature_names = [
            "domain_similarity",
            "text_similarity",
            "dom_similarity",
            "visual_similarity",
            "login_form_score",
            "keyword_score",
            "https_score",
        ]
    
    def generate_synthetic_dataset(self, n_phishing: int = 500, n_legitimate: int = 500) -> pd.DataFrame:
        """
        Generate synthetic training dataset
        
        Returns:
            DataFrame with features and labels
        """
        logger.info(f"Generating synthetic dataset: {n_phishing} phishing, {n_legitimate} legitimate")
        
        data = []
        
        # Phishing samples (label=1)
        for i in range(n_phishing):
            # Phishing domains have high similarity features
            sample = {
                "domain_similarity": np.random.beta(8, 2),  # Biased towards high values
                "text_similarity": np.random.beta(7, 3),
                "dom_similarity": np.random.beta(7, 3),
                "visual_similarity": np.random.beta(8, 2),
                "login_form_score": np.random.beta(6, 4),
                "keyword_score": np.random.beta(6, 4),
                "https_score": np.random.beta(5, 5),  # Can be high or low
                "label": 1,
            }
            data.append(sample)
        
        # Legitimate samples (label=0)
        for i in range(n_legitimate):
            # Legitimate domains have low similarity features
            sample = {
                "domain_similarity": np.random.beta(2, 8),  # Biased towards low values
                "text_similarity": np.random.beta(2, 8),
                "dom_similarity": np.random.beta(2, 8),
                "visual_similarity": np.random.beta(2, 8),
                "login_form_score": np.random.beta(3, 7),
                "keyword_score": np.random.beta(3, 7),
                "https_score": np.random.beta(7, 3),  # Usually have HTTPS
                "label": 0,
            }
            data.append(sample)
        
        df = pd.DataFrame(data)
        logger.info(f"Dataset created with {len(df)} samples")
        
        return df
    
    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2, val_size: float = 0.1) -> Dict[str, float]:
        """
        Train logistic regression model
        
        Returns:
            Dictionary with evaluation metrics
        """
        logger.info("Starting model training...")
        
        # Split into train, val, test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        val_ratio = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio, random_state=42, stratify=y_temp
        )
        
        logger.info(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
        
        # Standardize features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train logistic regression
        self.model = LogisticRegression(
            max_iter=1000,
            random_state=42,
            class_weight='balanced',  # Handle class imbalance
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        logger.info("Model training completed")
        
        # Evaluate on validation set
        val_metrics = self._evaluate(self.model, X_val_scaled, y_val, "Validation")
        
        # Evaluate on test set
        test_metrics = self._evaluate(self.model, X_test_scaled, y_test, "Test")
        
        # Save model
        self.save_model()
        
        # Combine metrics
        metrics = {**val_metrics, **{f"test_{k}": v for k, v in test_metrics.items()}}
        
        return metrics
    
    def _evaluate(self, model, X: np.ndarray, y: np.ndarray, dataset_name: str = "Test") -> Dict[str, float]:
        """
        Evaluate model on dataset
        """
        y_pred = model.predict(X)
        y_pred_proba = model.predict_proba(X)[:, 1]
        
        metrics = {
            f"{dataset_name.lower()}_accuracy": accuracy_score(y, y_pred),
            f"{dataset_name.lower()}_precision": precision_score(y, y_pred, zero_division=0),
            f"{dataset_name.lower()}_recall": recall_score(y, y_pred, zero_division=0),
            f"{dataset_name.lower()}_f1": f1_score(y, y_pred, zero_division=0),
            f"{dataset_name.lower()}_roc_auc": roc_auc_score(y, y_pred_proba),
        }
        
        logger.info(f"{dataset_name} Metrics:")
        for key, value in metrics.items():
            logger.info(f"  {key}: {value:.4f}")
        
        # Log confusion matrix
        tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
        logger.info(f"Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
        
        return metrics
    
    def save_model(self):
        """
        Save trained model and scaler
        """
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        self.scaler_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        logger.info(f"Model saved to {self.model_path}")
        logger.info(f"Scaler saved to {self.scaler_path}")
    
    def load_model(self):
        """
        Load trained model and scaler
        """
        if not self.model_path.exists() or not self.scaler_path.exists():
            logger.error("Model files not found")
            return False
        
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            with open(self.scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            
            logger.info("Model and scaler loaded successfully")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Make predictions on new data
        
        Returns:
            (predictions, probabilities)
        """
        if self.model is None or self.scaler is None:
            raise RuntimeError("Model not loaded")
        
        X_scaled = self.scaler.transform(X)
        y_pred = self.model.predict(X_scaled)
        y_pred_proba = self.model.predict_proba(X_scaled)[:, 1]
        
        return y_pred, y_pred_proba
    
    def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance from model coefficients
        """
        if self.model is None:
            return {}
        
        # Get coefficients
        coefficients = self.model.coef_[0]
        
        # Normalize to [0, 1]
        abs_coef = np.abs(coefficients)
        normalized = abs_coef / np.sum(abs_coef)
        
        importance = dict(zip(self.feature_names, normalized))
        
        return importance
