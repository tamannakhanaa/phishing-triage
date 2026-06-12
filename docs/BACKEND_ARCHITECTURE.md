# Backend Architecture: A Verified, In-Depth Analysis

This document provides a definitive, in-depth analysis of every file and directory within the backend codebase. It has been fact-checked against the source code to serve as an accurate technical reference for understanding the specific responsibilities and interactions of each component.

---

## Directory 1: `api/` - The Application Core & Web Layer

This directory is the heart of the application. It handles incoming web requests, manages the database, orchestrates the analysis process, and defines the data structures for communication.

### ➤ `api/main.py`
*   **Primary Responsibility**: **API Server Entrypoint**. This file defines and runs the main FastAPI application.
*   **Verified Details**:
    *   **Environment Loading**: Crucially, this file begins by calling `load_dotenv(...)` to ensure that environment variables (like the `OPENAI_API_KEY`) from the root `.env` file are loaded into the application's memory at startup.
    *   **Database Initialization**: The `@app.on_event("startup")` decorator correctly registers the `init_db()` function to run once when the server starts, ensuring all necessary database tables are created before any requests are handled.
    *   **Endpoint Logic**:
        *   `/submit-url`: The logic correctly follows the "create first, then process" pattern. It immediately creates a `Submission` record with a `"queued"` status and commits it to the database. Only then does it call the `handle_url_submission` pipeline. This is a robust design that prevents losing track of submissions if the analysis fails. Upon completion, it updates the same database record with the results.
        *   **Email & Legacy Endpoints**: It also includes `/submit-email` and a legacy `/submit` endpoint, demonstrating support for multiple submission types.
    *   **Static File Serving**: The `app.mount(...)` directive is correctly placed at the **end of the file**. This is a critical detail in FastAPI, as it ensures the static file server doesn't intercept and block requests meant for the API endpoints defined above it.

### ➤ `api/pipeline.py`
*   **Primary Responsibility**: **Analysis Orchestrator**. This module acts as a "conductor," coordinating the various analysis tasks in sequence.
*   **Verified Details**:
    *   **Graceful Fallbacks**: The file is designed with resilience in mind. It uses `try...except ImportError` blocks when importing the machine learning modules (`ml.predict`, `ml.features`). If the ML components are missing, it defines simple, rule-based fallback functions (e.g., `score_url` that checks for keywords) so that the application can still provide a basic analysis instead of crashing.
    *   **Orchestration Flow in `handle_url_submission`**: The sequence of operations described in the previous version is correct. It calls `url_features`, `score_url`, `ThreatIntelAggregator`, `extract_iocs`, `enhance_report_with_openai`, and finally `build_report`.
    *   **Detonation Logic**: It contains logic to trigger a sandbox detonation (`detonate_in_sandbox`) only if certain conditions are met: the request explicitly asks for it (`req.get("detonate")`) AND the risk is high (either from the ML score or a URLhaus hit).

### ➤ `api/models.py`
*   **Primary Responsibility**: **Database Schema Definition**. Defines the database tables using SQLAlchemy's ORM.
*   **Verified Details**:
    *   **Engine Configuration**: The SQLAlchemy engine is configured with `connect_args={"check_same_thread": False}`. This is a specific and necessary configuration for using SQLite in a multi-threaded application like FastAPI.
    *   **`Submission` Model**: The model accurately represents all the data points collected during the analysis, including fields for the final `report_markdown`, `iocs`, raw `enrichment` data, `features`, and `sandbox_data`.

### ➤ `api/schemas.py`
*   **Primary Responsibility**: **Data Validation and Serialization**. Defines API data contracts using Pydantic.
*   **Verified Details**:
    *   **Strict Typing**: The schemas use specific Pydantic types like `HttpUrl` to enforce strong validation. For example, a request to `/submit-url` will be rejected if the provided `url` is not a well-formed web address.
    *   **Field Constraints**: The `SubmitURL` schema uses `Field(..., pattern="...")` to constrain the `provider` string to only "anyrun" or "joe", preventing invalid sandbox provider names.

---
## Directory 2: `ml/` - The Machine Learning Engine

This directory contains all code and assets related to the phishing prediction model.

### ➤ `ml/train.py`
*   **Primary Responsibility**: **Model Training and Evaluation**. This is an offline script for creating the `model.joblib` artifact.
*   **Verified Details**:
    *   **MLflow Integration**: This script is heavily integrated with `MLflow`. It logs parameters, metrics (ROC-AUC, F1-score, etc.), and artifacts (like feature importance plots and a `model_card.md`) for each training run, enabling experiment tracking and reproducibility.
    *   **Artifact Bundling**: It doesn't just save the raw model. It creates a dictionary `model_artifact` that bundles the trained `model`, the `scaler` used for feature normalization, the list of `features`, performance `metrics`, and the training timestamp. This entire dictionary is what gets saved to `model.joblib`, ensuring all necessary components for prediction are stored together.

### ➤ `ml/predict.py`
*   **Primary Responsibility**: **Model Inference for the Live API**.
*   **Verified Details**:
    *   **Model Caching**: The script uses a global variable `_model_cache`. The `load_model()` function ensures the `model.joblib` file is read from disk only once when the first request comes in. For all subsequent requests, the model is served directly from memory, which significantly improves performance.
    *   **Robust Path Finding**: The `get_model_path()` function intelligently searches in multiple common locations for `model.joblib`, making the application less brittle to changes in the current working directory.
    *   **Feature Consistency**: Before making a prediction, `score_url` explicitly re-orders the columns of the input DataFrame to match the exact order of features the model was trained on (`get_feature_names()`), preventing subtle prediction errors.

### ➤ `ml/features.py`
*   **Primary Responsibility**: **URL Feature Engineering**. Converts a URL string into a numerical vector.
*   **Verified Details**:
    *   **Rich Feature Set**: The `url_features` function is comprehensive, extracting over 30 distinct features. It correctly uses libraries like `tldextract` for robust domain parsing and calculates complex features like Shannon `entropy` to detect randomness in domain names.
    *   **Error Handling**: The entire feature extraction process is wrapped in a `try...except` block. If an unexpected error occurs with a malformed URL, it returns a vector of zeros, preventing the entire analysis pipeline from crashing.

---
## Directory 3: `enrich/` - External Data Enrichment

This directory contains clients for querying third-party threat intelligence services.

### ➤ `enrich/advanced_intel.py`
*   **Primary Responsibility**: **Intelligence Aggregation**.
*   **Verified Details**:
    *   **Extensible Design**: The `ThreatIntelAggregator` class uses a dictionary of functions (`self.sources`) to manage its different intelligence providers. This is a clean design pattern that makes it easy to add a new provider by simply adding a new key-value pair and a corresponding `_check_...` function.
    *   **Risk Calculation**: It includes logic (`_calculate_overall_risk`) to synthesize the results from multiple sources into a single, high-level verdict ("high", "medium", "low") and a confidence score.

### ➤ `enrich/urlhaus.py`
*   **Primary Responsibility**: **URLhaus API Client**.
*   **Verified Details**:
    *   **API Interaction**: The `lookup_url` function correctly sends a `POST` request with the URL in the request body, as required by the URLhaus API v1.
    *   **Data Parsing**: It does more than just return the raw API response. The `parse_urlhaus_response` function structures the important data, such as payload information and blacklist status, into a cleaner format.

---
## Directory 4: `reports/` - Report Generation & Formatting

This directory assembles all collected data into the final output.

### ➤ `reports/render.py`
*   **Primary Responsibility**: **Report Assembly using Templates**.
*   **Verified Details**:
    *   **Jinja2 Environment**: The `get_template_env` function correctly configures the Jinja2 templating engine to load templates from the `reports/templates/` directory.
    *   **Context Preparation**: The `build_report` function acts as a data pre-processor for the template. It performs calculations (like `confidence`), formats data (like creating a `sandbox_data` dictionary), and generates lists of `risk_factors` before passing the final, clean `context` dictionary to the template for rendering.

### ➤ `reports/openai_enhancer.py`
*   **Primary Responsibility**: **AI-Powered Summarization**.
*   **Verified Details**:
    *   **Prompt Engineering**: This module contains the "prompt engineering" for the application. The `system_prompt` explicitly instructs the AI on its role ("Tier 3 SOC analyst") and the desired output format (Markdown, key findings, IOCs, verdict).
    *   **Data Sanitization**: Before sending data to OpenAI, the code creates a copy (`prompt_data = report_data.copy()`) to avoid modifying the original data object. This is good practice.

### ➤ `reports/templates/report.md.j2`
*   **Primary Responsibility**: **Report Structure and Layout**.
*   **Verified Details**:
    *   **Conditional Logic**: The template uses Jinja2 control structures extensively. For example, `{% if score >= threshold %}` is used to change the color and text of the risk level, and `{% if sandbox %}` ensures the entire sandbox section is omitted from the report if no sandbox analysis was performed. This makes the final report dynamic and clean.
