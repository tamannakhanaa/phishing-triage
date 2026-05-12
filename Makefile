.PHONY: help setup install train serve test clean drift lint format

# Default target
help:
	@echo "Phishing Triage System - Available commands:"
	@echo "  make setup      - Set up the development environment"
	@echo "  make install    - Install dependencies"
	@echo "  make train      - Train the ML model"
	@echo "  make serve      - Start the API server"
	@echo "  make test       - Run API tests"
	@echo "  make drift      - Check for model drift"
	@echo "  make clean      - Clean temporary files"
	@echo "  make lint       - Run code linting"
	@echo "  make format     - Format code with black"

# Setup development environment
setup:
	python setup.py

# Install dependencies
install:
	pip install -r requirements.txt

# Train the model
train:
	python -m ml.train

# Start the API server
serve:
	uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Run tests
test:
	python test_api.py

# Check for drift
drift:
	python -m ml.drift

# Clean temporary files
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name ".DS_Store" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf mlruns

# Run linting
lint:
	flake8 api/ ml/ enrich/ reports/ --max-line-length=120

# Format code
format:
	black api/ ml/ enrich/ reports/ --line-length=120

# Development server with environment loading
dev:
	@if [ -f .env ]; then \
		export $$(cat .env | xargs) && uvicorn api.main:app --reload; \
	else \
		echo "No .env file found. Running with defaults..."; \
		uvicorn api.main:app --reload; \
	fi

# Run MLflow UI
mlflow-ui:
	mlflow ui --host 0.0.0.0 --port 5000

# Create directories
dirs:
	mkdir -p data storage ml/metrics logs

# Download sample dataset
dataset:
	@echo "Please download the PhiUSIIL dataset from:"
	@echo "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset"
	@echo "And place it in data/phiusiil.csv"

# Full setup and run
all: setup train serve
