"""Drift detection for model monitoring."""
from river.drift import ADWIN
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json
import os
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
import numpy as np

# Import from parent package
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from api.models import Submission


class DriftDetector:
    """Monitor feature and score drift using ADWIN."""
    
    def __init__(self, drift_threshold: float = 0.002):
        """
        Initialize drift detector.
        
        Args:
            drift_threshold: ADWIN drift threshold (smaller = more sensitive)
        """
        self.detectors = {}
        self.drift_threshold = drift_threshold
        self.drift_history = []
        self.last_check = None
        
    def get_detector(self, feature_name: str) -> ADWIN:
        """Get or create ADWIN detector for a feature."""
        if feature_name not in self.detectors:
            self.detectors[feature_name] = ADWIN(delta=self.drift_threshold)
        return self.detectors[feature_name]
    
    def update_and_check(self, feature_name: str, value: float) -> Tuple[bool, Optional[Dict]]:
        """
        Update detector with new value and check for drift.
        
        Args:
            feature_name: Name of the feature or metric
            value: New value to add
            
        Returns:
            Tuple of (drift_detected, drift_info)
        """
        detector = self.get_detector(feature_name)
        
        # Update detector
        detector.update(value)
        
        # Check for drift
        if detector.drift_detected:
            drift_info = {
                "feature": feature_name,
                "timestamp": datetime.utcnow().isoformat(),
                "n_samples": detector.n_detected_changes,
                "width": detector.width
            }
            
            # Reset detector after drift
            self.detectors[feature_name] = ADWIN(delta=self.drift_threshold)
            
            # Record drift event
            self.drift_history.append(drift_info)
            
            return True, drift_info
        
        return False, None
    
    def check_batch(self, feature_values: Dict[str, List[float]]) -> Dict[str, bool]:
        """
        Check multiple features for drift.
        
        Args:
            feature_values: Dictionary mapping feature names to lists of values
            
        Returns:
            Dictionary indicating which features have drift
        """
        drift_results = {}
        
        for feature_name, values in feature_values.items():
            drift_detected = False
            
            for value in values:
                is_drift, _ = self.update_and_check(feature_name, value)
                if is_drift:
                    drift_detected = True
            
            drift_results[feature_name] = drift_detected
        
        self.last_check = datetime.utcnow()
        
        return drift_results
    
    def save_state(self, filepath: str):
        """Save detector state to file."""
        state = {
            "drift_threshold": self.drift_threshold,
            "drift_history": self.drift_history,
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "detector_stats": {
                name: {
                    "n_samples": det.width,
                    "n_changes": det.n_detected_changes
                }
                for name, det in self.detectors.items()
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2)
    
    def load_state(self, filepath: str):
        """Load detector state from file."""
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                state = json.load(f)
            
            self.drift_threshold = state.get("drift_threshold", 0.002)
            self.drift_history = state.get("drift_history", [])
            
            if state.get("last_check"):
                self.last_check = datetime.fromisoformat(state["last_check"])


def monitor_production_drift(
    db_url: str = None,
    lookback_hours: int = 24,
    feature_names: List[str] = None
) -> Dict[str, any]:
    """
    Monitor drift in production data.
    
    Args:
        db_url: Database URL (uses env var if not provided)
        lookback_hours: Hours of data to analyze
        feature_names: Features to monitor (default: scores and key features)
        
    Returns:
        Dictionary with drift detection results
    """
    # Setup database
    if db_url is None:
        db_url = os.getenv("DATABASE_URL", "sqlite:///storage/submissions.db")
    
    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    db = Session()
    
    # Default features to monitor
    if feature_names is None:
        feature_names = [
            "score",
            "url_len",
            "sus_token_count",
            "domain_entropy",
            "num_params"
        ]
    
    # Initialize detector
    detector = DriftDetector()
    
    # Load previous state if exists
    state_file = "ml/metrics/drift_state.json"
    detector.load_state(state_file)
    
    try:
        # Get recent submissions
        since = datetime.utcnow() - timedelta(hours=lookback_hours)
        submissions = db.query(Submission).filter(
            Submission.created_at >= since,
            Submission.score.isnot(None)
        ).all()
        
        if len(submissions) < 10:
            return {
                "status": "insufficient_data",
                "n_samples": len(submissions),
                "message": "Need at least 10 samples for drift detection"
            }
        
        # Collect feature values
        feature_values = {"score": []}
        
        for sub in submissions:
            # Always monitor score
            if sub.score is not None:
                feature_values["score"].append(sub.score)
            
            # Monitor other features if available
            if sub.features:
                for feat in feature_names:
                    if feat in sub.features:
                        if feat not in feature_values:
                            feature_values[feat] = []
                        feature_values[feat].append(sub.features[feat])
        
        # Check for drift
        drift_results = detector.check_batch(feature_values)
        
        # Calculate statistics
        stats = {}
        for feat, values in feature_values.items():
            if values:
                stats[feat] = {
                    "mean": np.mean(values),
                    "std": np.std(values),
                    "min": np.min(values),
                    "max": np.max(values),
                    "n_samples": len(values)
                }
        
        # Save state
        detector.save_state(state_file)
        
        # Prepare results
        drift_detected = any(drift_results.values())
        
        results = {
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat(),
            "n_samples": len(submissions),
            "lookback_hours": lookback_hours,
            "drift_detected": drift_detected,
            "drift_features": [k for k, v in drift_results.items() if v],
            "feature_stats": stats,
            "drift_history": detector.drift_history[-10:]  # Last 10 drift events
        }
        
        # Create alert if drift detected
        if drift_detected:
            create_drift_alert(results)
        
        return results
        
    finally:
        db.close()


def create_drift_alert(drift_info: Dict[str, any]):
    """Create alert for detected drift."""
    alert_file = f"ml/metrics/drift_alert_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    
    os.makedirs("ml/metrics", exist_ok=True)
    
    alert = {
        "type": "drift_detected",
        "severity": "high" if "score" in drift_info["drift_features"] else "medium",
        "timestamp": drift_info["timestamp"],
        "features_affected": drift_info["drift_features"],
        "recommendation": "Review recent submissions and consider model retraining",
        "details": drift_info
    }
    
    with open(alert_file, 'w') as f:
        json.dump(alert, f, indent=2)
    
    print(f"\n⚠️  DRIFT ALERT: {alert['severity']} severity drift detected in {len(drift_info['drift_features'])} features")
    print(f"Alert saved to: {alert_file}")


def run_drift_check():
    """Run drift detection as a scheduled job."""
    print(f"Running drift detection at {datetime.utcnow()}")
    
    results = monitor_production_drift()
    
    print(f"Drift check completed: {results['status']}")
    
    if results.get("drift_detected"):
        print(f"⚠️  Drift detected in: {results['drift_features']}")
    else:
        print("✅ No drift detected")
    
    # Save results
    results_file = "ml/metrics/latest_drift_check.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    return results


if __name__ == "__main__":
    # Run drift check when module is executed
    run_drift_check()
