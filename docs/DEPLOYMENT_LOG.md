# Deployment Log & Troubleshooting

This document chronicles the process of deploying the Phish Triage application to Render, highlighting the challenges encountered and the solutions implemented.

---

### Initial Problem: `numpy` Version Mismatch

After a successful deployment, the application failed at runtime when scoring a URL. The Render logs showed a critical error:

```
Error scoring URL: <class 'numpy.random._mt19937.MT19937'> is not a known BitGenerator module.
```

### Investigation & Root Cause Analysis

1.  **Hypothesis**: This specific error is a classic sign of a library version mismatch. It occurs when a machine learning model (like our scikit-learn classifier) is saved (`pickled`) with one version of `numpy` and then loaded (`un-pickled`) with an incompatible version. The internal data structures of `numpy` changed significantly between versions `1.x` and `2.x`.

2.  **Local vs. Deployed Environment**:
    *   **Local Environment**: A check revealed that the local machine was running `numpy==2.3.2`. The model (`ml/model.joblib`) was trained and saved using this version.
    *   **Deployed Environment (`requirements.txt`)**: The project's `requirements.txt` file specified `numpy==1.26.4`. This was a necessary constraint because another dependency, `river` (used for drift detection), was not yet compatible with `numpy 2.x` and required a version `<2.0`.

3.  **The Core Conflict**: The application was trying to load a `numpy 2.x`-pickled model in a `numpy 1.x` runtime environment, causing the `BitGenerator` error.

### Resolution Steps

To fix this, we needed to ensure that the `numpy` version was consistent across the entire lifecycle of the model—from training to deployment. Since we were constrained by `river`'s requirement, the only path forward was to downgrade to `numpy 1.x`.

1.  **Add Runtime Version Logging**: To get full visibility, a logging snippet was added to `backend/api/main.py`. This code runs on application startup and prints the exact versions of all critical data science libraries (`numpy`, `pandas`, `scikit-learn`, etc.) directly into the Render logs, making future debugging easier.

2.  **Confirm the Incompatibility Locally**: We downgraded the local Python environment to `numpy==1.26.4`. As expected, attempting to load the existing `model.joblib` file immediately failed with the same `BitGenerator` error, confirming our hypothesis.

3.  **Retrain the Model**: With `numpy==1.26.4` active in the local environment, the model training script (`backend/ml/train.py`) was executed again. This generated a new `model.joblib` file, this time pickled with the correct `numpy` version.

4.  **Enforce Strict Version Pinning**: To prevent `pip` from ignoring our version pin in the face of a conflicting transitive dependency, we implemented a stricter method:
    *   A `constraints.txt` file was created to explicitly lock `numpy` to `1.26.4`.
    *   The `Dockerfile` was updated. The `pip install` command was modified from `pip install -r requirements.txt` to `pip install -c constraints.txt -r requirements.txt`. This tells `pip` to use the versions in `constraints.txt` as the single source of truth, overriding any other requirements.

5.  **Commit & Redeploy**: All changes—the updated `main.py`, the new `constraints.txt`, the modified `Dockerfile`, and crucially, the **newly retrained `model.joblib` file**—were committed to the repository and pushed to GitHub.

6.  **Final Step**: A manual deployment was triggered on Render to apply the changes. The application started successfully, the logs confirmed the correct library versions were in use, and the URL scoring functionality was restored.
