# Multi-stage build for efficiency
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and constraints
COPY backend/requirements.txt .
COPY constraints.txt .

# Install Python dependencies with constraints to enforce version pinning
RUN pip install --no-cache-dir --user -c constraints.txt -r requirements.txt

# Runtime stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 appuser

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY --chown=appuser:appuser . .

# Copy frontend files (FastAPI will serve these)
COPY --chown=appuser:appuser frontend /app/frontend

# Copy ML model
COPY --chown=appuser:appuser ml/model.joblib /app/ml/model.joblib

# Create necessary directories and set permissions
RUN mkdir -p data storage ml/metrics logs && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Add user's local bin to PATH
ENV PATH=/home/appuser/.local/bin:$PATH

# Expose port (FastAPI will listen on this port)
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Run the application
CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8001"]
