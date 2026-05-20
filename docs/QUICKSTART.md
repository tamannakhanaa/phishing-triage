# Quick Start Guide

Get the Phishing Triage System up and running in 5 minutes!

## 🚀 Fastest Setup (Using Make)

```bash
# 1. Clone and enter directory
git clone <repository-url>
cd phish-triage

# 2. Set up environment
make setup

# 3. Train model with sample data
make train

# 4. Start the service
make serve
```

Visit http://localhost:8000/docs for the API documentation.

## 🐳 Docker Setup

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Build and run with Docker Compose
docker-compose up -d

# 3. Train model inside container (first time only)
docker-compose exec phish-triage python -m ml.train
```

## 🧪 Test the API

### Submit a URL for analysis:

```bash
curl -X POST http://localhost:8000/submit \
  -H "Content-Type: application/json" \
  -d '{"url": "http://suspicious-site.com/verify-account"}'
```

### Get the report:

```bash
curl http://localhost:8000/report/{submission_id}
```

### Submit an email file:

```bash
curl -X POST http://localhost:8000/submit \
  -F "eml=@phishing_email.eml"
```

## 📊 View Metrics

- API Metrics: http://localhost:8000/metrics
- MLflow UI: http://localhost:5000 (if using docker-compose)
- API Docs: http://localhost:8000/docs

## 🔑 API Keys (Optional)

Edit `.env` file to add enrichment service API keys:

```env
URLHAUS_AUTH_KEY=your_key_here
ANYRUN_API_KEY=your_key_here
JOE_API_KEY=your_key_here
```

## 🎯 Example Python Client

```python
import httpx

# Submit URL
response = httpx.post(
    "http://localhost:8000/submit",
    json={
        "url": "http://phishing-test.com/login",
        "detonate": True,  # Enable sandbox analysis
        "provider": "anyrun"  # or "joe"
    }
)

submission = response.json()
print(f"Submission ID: {submission['id']}")

# Get report
report = httpx.get(f"http://localhost:8000/report/{submission['id']}").json()
print(f"Risk Score: {report['score']}")
print(f"Report:\n{report['report_markdown']}")
```

## 🛠️ Common Operations

```bash
# Check system health
curl http://localhost:8000/health

# Run drift detection
make drift

# View logs
docker-compose logs -f phish-triage

# Stop services
docker-compose down

# Clean up
make clean
```

## 📚 Next Steps

1. **Production Dataset**: Download [PhiUSIIL dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) for better model performance
2. **Configure Enrichment**: Add API keys for URLhaus, ANY.RUN, or Joe Sandbox
3. **Set up Monitoring**: Configure alerts for drift detection
4. **Scale**: Use PostgreSQL instead of SQLite for production

## 🆘 Troubleshooting

### Model not found error
```bash
python -m ml.train  # Train with sample data
```

### Port already in use
```bash
# Change port in docker-compose.yml or use:
uvicorn api.main:app --port 8001
```

### Database errors
```bash
# Reset database
rm storage/submissions.db
python -c "from api.models import init_db; init_db()"
```

### Missing dependencies
```bash
pip install -r requirements.txt
```

For more help, see the full [README.md](README.md) or open an issue!
