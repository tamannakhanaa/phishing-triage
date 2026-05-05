# Phishing Detection Model Card

## Model Details
- **Model Type**: gb
- **Training Date**: 2025-08-30
- **Framework**: scikit-learn

## Performance Metrics
- **ROC-AUC**: 1.0000
- **PR-AUC**: 1.0000
- **F1 Score**: 1.0000
- **Precision**: 1.0000
- **Recall**: 1.0000

## Recommended Threshold
- **High Precision Threshold**: 1.000
- This threshold is optimized for high precision (≥95%) to minimize false positives in production.

## Training Data
- **Dataset**: PhiUSIIL Phishing URL Dataset (or custom dataset)
- **Features**: 35 URL-based features including:
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
