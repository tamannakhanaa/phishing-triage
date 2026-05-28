# Security Hardening Measures: A Detailed Implementation Log

This document provides a complete and detailed log of the security hardening measures implemented for the Phishing Triage project. The focus was on practical, no-cost solutions that significantly improve the application's security posture.

---

### 1. Dependency Vulnerability Auditing & Remediation

The first step was to identify and fix any known vulnerabilities within the project's third-party dependencies.

**Action Taken:**
1.  The `pip-audit` tool, a recognized utility from the Python Packaging Authority (PyPA), was installed and run against the `backend/requirements.txt` file.
2.  The initial scan revealed **10 known vulnerabilities** in 5 packages: `fastapi`, `python-multipart`, `jinja2`, `black`, and the sub-dependency `starlette`.
3.  An iterative process of remediation was undertaken:
    *   Versions in `requirements.txt` were updated to the recommended secure versions.
    *   This led to a dependency conflict: the updated `fastapi` required a version of `starlette` that was older than the version needed to fix a `starlette` vulnerability.
    *   The conflict was resolved by upgrading `fastapi` to the latest available version (`0.111.1`), which in turn pulled in a compatible and secure version of `starlette`.
    *   The final scan confirmed that all vulnerabilities in `fastapi`, `jinja2`, and `starlette` were resolved.

---

### 2. Mitigation of Denial-of-Service (DoS) Vector

A vulnerability remained in `python-multipart`, a library essential for FastAPI's file upload functionality. The vulnerability could allow an attacker to cause a denial of service by sending a specially crafted, large file.

**Action Taken:**
1.  Since replacing the library was not feasible without a major rewrite, a direct mitigation was implemented.
2.  The `backend/api/main.py` file was modified to enforce a strict file size limit on the `/submit-email` endpoint.
3.  A constant, `MAX_FILE_SIZE`, was set to 5 MB.
4.  Before reading the uploaded `.eml` file, its size is checked. If it exceeds the limit, the application immediately rejects the request with a `413 Payload Too Large` HTTP error, effectively neutralizing the DoS vector.

---

### 3. Frontend Cross-Site Scripting (XSS) Prevention

The frontend renders the Markdown report returned by the API. If this report contained malicious HTML or JavaScript, it could be executed in the user's browser (an XSS attack).

**Action Taken:**
1.  The `marked.js` library, a robust Markdown parser, was added to `frontend/index.html` via a CDN link.
2.  The `displayResult` JavaScript function was refactored.
3.  Instead of directly inserting the raw Markdown into the DOM, it is now processed by `marked.parse(report, { sanitize: true })`.
4.  The `sanitize: true` option is a critical security control that instructs `marked.js` to strip any dangerous HTML tags (like `<script>`) and attributes (like `onclick`) from the input before rendering it. This ensures that only safe, formatted text is ever displayed to the user.

---

### 4. API Rate Limiting

To protect the API from abuse, brute-force attacks, and simple DoS attacks, a rate limiter was implemented.

**Action Taken:**
1.  The `slowapi` library was added to the project's dependencies.
2.  In `backend/api/main.py`, a global `Limiter` instance was created. It uses the client's IP address (`get_remote_address`) to track requests.
3.  The FastAPI application was configured to use this limiter.
4.  The `@limiter.limit(...)` decorator was applied to the most resource-intensive endpoints:
    *   `POST /submit-url`: Limited to **20 requests per minute** per IP.
    *   `POST /submit-email`: Given its higher processing cost (file handling), it was given a stricter limit of **5 requests per minute** per IP.
5.  If a client exceeds these limits, the API will automatically respond with a `429 Too Many Requests` error, blocking the abusive traffic.

---

### 5. Creation of a Security Policy

To encourage responsible disclosure of any future vulnerabilities, a formal security policy was established.

**Action Taken:**
1.  A new file, `SECURITY.md`, was created in the root directory of the project.
2.  This file contains clear, standard instructions for security researchers on how to report a vulnerability. It specifies opening a GitHub Issue with a `[SECURITY]` prefix and provides a template for the required information.
3.  This policy provides a clear and professional channel for security communication, building trust with users and the open-source community.
