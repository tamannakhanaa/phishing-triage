"""Model training script with MLflow tracking."""
import pandas as pd
import numpy as np
import joblib
import mlflow
import mlflow.sklearn
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    roc_auc_score, average_precision_score, f1_score,
    precision_score, recall_score, confusion_matrix,
    precision_recall_curve, roc_curve
)
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import os
import json

from .features import url_features, get_feature_names


def load_phiusiil_dataset(filepath: str) -> pd.DataFrame:
    """Load PhiUSIIL dataset from CSV."""
    # Assuming CSV format with columns: url, label
    # Adjust based on actual dataset format
    df = pd.read_csv(filepath)
    
    # Ensure we have the required columns
    if 'url' not in df.columns or 'label' not in df.columns:
        # Try to infer columns
        if len(df.columns) == 2:
            df.columns = ['url', 'label']
        else:
            raise ValueError("Dataset must have 'url' and 'label' columns")
    
    # Ensure label is binary (0 or 1)
    df['label'] = df['label'].astype(int)
    
    return df


def prepare_features(df: pd.DataFrame) -> tuple:
    """Extract features from URLs."""
    print("Extracting features from URLs...")
    
    # Extract features for each URL
    feature_dicts = []
    valid_indices = []
    
    for idx, url in enumerate(df['url']):
        if idx % 1000 == 0:
            print(f"Processing URL {idx}/{len(df)}")
        
        try:
            features = url_features(str(url))
            feature_dicts.append(features)
            valid_indices.append(idx)
        except Exception as e:
            print(f"Error processing URL at index {idx}: {e}")
    
    # Create feature matrix
    X = pd.DataFrame(feature_dicts)
    y = df.iloc[valid_indices]['label'].values
    
    # Ensure all expected features are present
    for feature in get_feature_names():
        if feature not in X.columns:
            X[feature] = 0.0
    
    # Select only the expected features in the correct order
    X = X[get_feature_names()]
    
    print(f"Feature extraction complete. Shape: {X.shape}")
    
    return X, y


def train_model(X: pd.DataFrame, y: np.ndarray, model_type: str = "gb") -> tuple:
    """Train and evaluate model with MLflow tracking."""
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Initialize MLflow
    mlflow.set_experiment("phish-triage")
    
    with mlflow.start_run():
        # Log dataset info
        mlflow.log_param("dataset_size", len(X))
        mlflow.log_param("n_features", X.shape[1])
        mlflow.log_param("train_size", len(X_train))
        mlflow.log_param("test_size", len(X_test))
        mlflow.log_param("model_type", model_type)
        
        # Select and train model
        if model_type == "gb":
            model = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            )
        else:
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
        
        print(f"Training {model_type} model...")
        model.fit(X_train_scaled, y_train)
        
        # Predictions
        y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
        y_pred = (y_pred_proba >= 0.5).astype(int)
        
        # Calculate metrics
        metrics = {
            "roc_auc": roc_auc_score(y_test, y_pred_proba),
            "pr_auc": average_precision_score(y_test, y_pred_proba),
            "f1": f1_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred),
            "recall": recall_score(y_test, y_pred)
        }
        
        # Log metrics
        for name, value in metrics.items():
            mlflow.log_metric(name, value)
        
        print("\nModel Performance:")
        for name, value in metrics.items():
            print(f"{name}: {value:.4f}")
        
        # Feature importance
        if hasattr(model, 'feature_importances_'):
            feature_importance = pd.DataFrame({
                'feature': X.columns,
                'importance': model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            print("\nTop 10 Important Features:")
            print(feature_importance.head(10))
            
            # Save feature importance
            feature_importance.to_csv("ml/metrics/feature_importance.csv", index=False)
            mlflow.log_artifact("ml/metrics/feature_importance.csv")
        
        # Create and save plots
        os.makedirs("ml/metrics", exist_ok=True)
        
        # ROC Curve
        fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {metrics["roc_auc"]:.3f})')
        plt.plot([0, 1], [0, 1], 'k--')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curve')
        plt.legend()
        plt.savefig("ml/metrics/roc_curve.png")
        mlflow.log_artifact("ml/metrics/roc_curve.png")
        plt.close()
        
        # Precision-Recall Curve
        precision, recall, _ = precision_recall_curve(y_test, y_pred_proba)
        plt.figure(figsize=(8, 6))
        plt.plot(recall, precision, label=f'PR Curve (AUC = {metrics["pr_auc"]:.3f})')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.legend()
        plt.savefig("ml/metrics/pr_curve.png")
        mlflow.log_artifact("ml/metrics/pr_curve.png")
        plt.close()
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix')
        plt.savefig("ml/metrics/confusion_matrix.png")
        mlflow.log_artifact("ml/metrics/confusion_matrix.png")
        plt.close()
        
        # Save model and scaler
        model_artifact = {
            'model': model,
            'scaler': scaler,
            'features': get_feature_names(),
            'threshold': 0.5,
            'metrics': metrics,
            'trained_at': datetime.utcnow().isoformat()
        }
        
        # Save model to multiple locations for compatibility
        os.makedirs("ml", exist_ok=True)
        joblib.dump(model_artifact, "ml/model.joblib")
        joblib.dump(model_artifact, "model.joblib")  # Root directory
        
        # Log with MLflow
        mlflow.log_artifact("ml/model.joblib")
        
        # Log model with MLflow
        mlflow.sklearn.log_model(
            model,
            "model",
            registered_model_name="phish-triage-classifier"
        )
        
        # Find optimal threshold
        optimal_threshold = find_optimal_threshold(y_test, y_pred_proba)
        mlflow.log_metric("optimal_threshold", optimal_threshold)
        print(f"\nOptimal threshold for high precision: {optimal_threshold:.3f}")
        
        # Save model card
        create_model_card(model_type, metrics, optimal_threshold)
        mlflow.log_artifact("ml/model_card.md")
        
    return model, scaler, metrics


def find_optimal_threshold(y_true: np.ndarray, y_scores: np.ndarray, target_precision: float = 0.95) -> float:
    """Find threshold that achieves target precision."""
    precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
    
    # Find threshold that gives us at least target_precision
    valid_indices = np.where(precision >= target_precision)[0]
    
    if len(valid_indices) > 0:
        # Get the threshold with highest recall while maintaining target precision
        best_idx = valid_indices[np.argmax(recall[valid_indices])]
        return float(thresholds[best_idx])
    else:
        # If we can't achieve target precision, return default
        return 0.5


def create_model_card(model_type: str, metrics: dict, threshold: float):
    """Create model card with information about the model."""
    card_content = f"""# Phishing Detection Model Card

## Model Details
- **Model Type**: {model_type}
- **Training Date**: {datetime.utcnow().strftime('%Y-%m-%d')}
- **Framework**: scikit-learn

## Performance Metrics
- **ROC-AUC**: {metrics['roc_auc']:.4f}
- **PR-AUC**: {metrics['pr_auc']:.4f}
- **F1 Score**: {metrics['f1']:.4f}
- **Precision**: {metrics['precision']:.4f}
- **Recall**: {metrics['recall']:.4f}

## Recommended Threshold
- **High Precision Threshold**: {threshold:.3f}
- This threshold is optimized for high precision (≥95%) to minimize false positives in production.

## Training Data
- **Dataset**: PhiUSIIL Phishing URL Dataset (or custom dataset)
- **Features**: {len(get_feature_names())} URL-based features including:
  - URL structure and length metrics
  - Domain characteristics
  - Suspicious token presence
  - Entropy calculations
  - TLD and subdomain analysis

## Limitations
- Model is trained on URL features only
- May not detect sophisticated phishing using legitimate services
- Should be combined with other signals (email headers, reputation services)
- Requires periodic retraining to adapt to new phishing patterns

## Usage
```python
from ml.predict import score_url
risk_score = score_url("http://suspicious-site.com/verify-account")
```
"""
    
    with open("ml/model_card.md", "w") as f:
        f.write(card_content)


def main():
    """Main training pipeline."""
    # Create necessary directories
    os.makedirs("ml/metrics", exist_ok=True)
    os.makedirs("data", exist_ok=True)
    
    # Check if dataset exists
    dataset_path = "data/phiusiil.csv"
    
    if not os.path.exists(dataset_path):
        print(f"\nDataset not found at {dataset_path}")
        print("Please download the PhiUSIIL dataset from:")
        print("https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset")
        print("\nOr create a sample dataset for testing:")
        
        # Create a small sample dataset for testing
        sample_data = pd.DataFrame({
            'url': [
                'https://www.google.com/search?q=python',
                'https://www.amazon.com/products/item123',
                'http://suspicious-login-verify.tk/account/update',
                'http://192.168.1.1/admin/login.php',
                'https://paypal-verification.suspicious-domain.com/verify',
                'https://github.com/user/repo',
                'http://bit.ly/2xK9Qr',
                'https://secure-bank-update.phishing-site.com/login',
            ],
            'label': [0, 0, 1, 1, 1, 0, 1, 1]  # 0 = legitimate, 1 = phishing
        })
        
        sample_data.to_csv("data/sample_dataset.csv", index=False)
        print(f"\nCreated sample dataset at data/sample_dataset.csv")
        dataset_path = "data/sample_dataset.csv"
    
    # Load dataset
    print(f"Loading dataset from {dataset_path}...")
    df = load_phiusiil_dataset(dataset_path)
    print(f"Loaded {len(df)} URLs ({sum(df['label']==1)} phishing, {sum(df['label']==0)} legitimate)")
    
    # Prepare features
    X, y = prepare_features(df)
    
    # Train model
    print("\nTraining model...")
    model, scaler, metrics = train_model(X, y, model_type="gb")
    
    print("\nTraining complete! Model saved to ml/model.joblib")
    print("Check MLflow UI for detailed metrics: mlflow ui")


if __name__ == "__main__":
    main()
