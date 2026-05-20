"""Prediction module for URL scoring."""
import joblib
import pandas as pd
import numpy as np
import os
from typing import Dict, Tuple, Optional

from .features import url_features, get_feature_names

# Global model cache
_model_cache = None

def get_model_path() -> str:
    """Get the path to the trained model file."""
    # First check environment variable
    if os.getenv("MODEL_PATH"):
        return os.getenv("MODEL_PATH")
    
    # Check for model in various locations
    possible_paths = [
        "model.joblib",
        "ml/model.joblib",
        "backend/ml/model.joblib",
        "../ml/model.joblib"
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            print(f"Found model at {path}")
            return path
    
    # Default path
    return "ml/model.joblib"

_model_path = get_model_path()


def load_model() -> Tuple[object, object, float]:
    """Load the trained model, scaler, and threshold."""
    global _model_cache
    
    if _model_cache is None:
        if not os.path.exists(_model_path):
            raise FileNotFoundError(
                f"Model not found at {_model_path}. "
                "Please run 'python -m ml.train' to train the model first."
            )
        
        # Load model artifact
        model_artifact = joblib.load(_model_path)
        
        if isinstance(model_artifact, dict):
            model = model_artifact['model']
            scaler = model_artifact['scaler']
            threshold = model_artifact.get('threshold', 0.85)
        else:
            # Backward compatibility - if just model was saved
            model = model_artifact
            scaler = None
            threshold = 0.85
        
        _model_cache = (model, scaler, threshold)
    
    return _model_cache


def score_url(url: str) -> float:
    """
    Score a URL for phishing risk.
    
    Args:
        url: The URL to score
        
    Returns:
        Float between 0 and 1 indicating phishing probability
    """
    try:
        # Load model
        model, scaler, _ = load_model()
        
        # Extract features
        features = url_features(url)
        
        # Create dataframe with expected feature order
        X = pd.DataFrame([features])
        
        # Ensure all expected features are present
        for feature in get_feature_names():
            if feature not in X.columns:
                X[feature] = 0.0
        
        # Select features in correct order
        X = X[get_feature_names()]
        
        # Scale features if scaler is available
        if scaler is not None:
            X_scaled = scaler.transform(X)
        else:
            X_scaled = X.values
        
        # Get probability
        prob = model.predict_proba(X_scaled)[0, 1]
        
        return float(prob)
        
    except Exception as e:
        print(f"Error scoring URL {url}: {e}")
        # Return neutral score on error
        return 0.5


def classify_url(url: str, threshold: Optional[float] = None) -> Dict[str, any]:
    """
    Classify a URL as phishing or legitimate.
    
    Args:
        url: The URL to classify
        threshold: Classification threshold (uses model default if None)
        
    Returns:
        Dictionary with classification results
    """
    # Score the URL
    score = score_url(url)
    
    # Get threshold
    if threshold is None:
        _, _, default_threshold = load_model()
        threshold = float(os.getenv("RISK_THRESHOLD", default_threshold))
    
    # Classify
    is_phishing = score >= threshold
    
    # Determine risk level
    if score >= 0.9:
        risk_level = "critical"
    elif score >= 0.7:
        risk_level = "high"
    elif score >= 0.5:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return {
        "url": url,
        "score": score,
        "threshold": threshold,
        "is_phishing": is_phishing,
        "risk_level": risk_level,
        "confidence": abs(score - 0.5) * 2  # Confidence in prediction
    }


def batch_score_urls(urls: list) -> pd.DataFrame:
    """
    Score multiple URLs in batch.
    
    Args:
        urls: List of URLs to score
        
    Returns:
        DataFrame with URLs and scores
    """
    results = []
    
    for url in urls:
        try:
            result = classify_url(url)
            results.append(result)
        except Exception as e:
            results.append({
                "url": url,
                "score": None,
                "error": str(e)
            })
    
    return pd.DataFrame(results)


def get_model_info() -> Dict[str, any]:
    """Get information about the loaded model."""
    try:
        model, scaler, threshold = load_model()
        
        # Load full artifact if available
        model_artifact = joblib.load(_model_path)
        
        info = {
            "model_type": type(model).__name__,
            "features": get_feature_names(),
            "n_features": len(get_feature_names()),
            "threshold": threshold,
            "has_scaler": scaler is not None
        }
        
        # Add metrics if available
        if isinstance(model_artifact, dict) and 'metrics' in model_artifact:
            info['metrics'] = model_artifact['metrics']
            
        if isinstance(model_artifact, dict) and 'trained_at' in model_artifact:
            info['trained_at'] = model_artifact['trained_at']
        
        return info
        
    except Exception as e:
        return {"error": str(e)}


# Preload model on module import for faster first prediction
try:
    load_model()
except:
    pass  # Model will be loaded on first use
