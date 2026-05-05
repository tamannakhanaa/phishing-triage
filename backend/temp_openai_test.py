import os
import sys
import json

# Removed explicit sys.path.append - relying on external PYTHONPATH

from backend.reports.openai_enhancer import enhance_report_with_openai

# Manually load .env file if it exists (for isolated testing)
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

print(f"DEBUG: OS environment OPENAI_API_KEY: {os.getenv("OPENAI_API_KEY")[:5] + '...' if os.getenv("OPENAI_API_KEY") else 'None'}")

sample_report = {
    "url": "http://evil-phish.com/login",
    "score": 0.98,
    "is_phishing": True,
    "risk_level": "critical",
    "threat_intel": {
        "urlhaus": {"status": "malicious", "threat": "phishing"},
        "virustotal": {"positives": 7, "total": 90}
    },
    "iocs": {
        "ips": ["192.0.2.100"],
        "urls": ["http://another-malicious-domain.net/payload.exe"]
    }
}

print("\n--- Calling enhance_report_with_openai --- ")
enhanced_summary = enhance_report_with_openai(sample_report)

print("\n--- Resulting AI-Generated Summary ---")
if enhanced_summary:
    print(enhanced_summary)
else:
    print("No summary returned from OpenAI enhancer.")
    print("Check for errors above or API key issues.")
