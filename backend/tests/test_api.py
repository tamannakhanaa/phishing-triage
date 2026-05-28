"""Test script for the Phishing Triage API."""
import httpx
import json
import time
import sys
from pathlib import Path

# API base URL
BASE_URL = "http://localhost:8000"

# Test data
TEST_URLS = [
    {
        "url": "https://www.google.com",
        "expected": "low_risk",
        "description": "Legitimate Google homepage"
    },
    {
        "url": "http://suspicious-login-verify.tk/account/update",
        "expected": "high_risk",
        "description": "Suspicious URL with phishing indicators"
    },
    {
        "url": "http://192.168.1.1/admin/login.php",
        "expected": "high_risk",
        "description": "IP-based URL with login page"
    },
    {
        "url": "https://paypal-verification.suspicious-domain.com/verify",
        "expected": "high_risk",
        "description": "Phishing attempt mimicking PayPal"
    },
    {
        "url": "https://github.com/user/repo",
        "expected": "low_risk",
        "description": "Legitimate GitHub repository"
    }
]

# Sample email content
SAMPLE_EMAIL = """From: phishing@suspicious-sender.com
To: victim@example.com
Subject: Urgent: Verify Your Account
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset=UTF-8

Dear Customer,

Your account has been temporarily suspended. Please click the link below to verify your identity:

http://verify-account.phishing-site.com/login?user=victim

This is urgent and requires immediate action.

Best regards,
Security Team
"""


def test_health():
    """Test health endpoint."""
    print("Testing health endpoint...")
    response = httpx.get(f"{BASE_URL}/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    print("✓ Health check passed")


def test_submit_url(url_data):
    """Test URL submission."""
    print(f"\nTesting URL submission: {url_data['description']}")
    print(f"URL: {url_data['url']}")
    
    # Submit URL
    response = httpx.post(
        f"{BASE_URL}/submit",
        json={"url": url_data["url"], "detonate": False},
        timeout=30
    )
    
    assert response.status_code == 200
    data = response.json()
    submission_id = data["id"]
    
    print(f"✓ Submission created: {submission_id}")
    
    # Wait a bit for processing
    time.sleep(2)
    
    # Get report
    response = httpx.get(f"{BASE_URL}/report/{submission_id}")
    assert response.status_code == 200
    report = response.json()
    
    print(f"Score: {report.get('score', 'N/A')}")
    print(f"Status: {report['status']}")
    
    # Check if risk assessment matches expectation
    score = report.get("score", 0)
    if url_data["expected"] == "high_risk" and score >= 0.7:
        print("✓ Correctly identified as high risk")
    elif url_data["expected"] == "low_risk" and score < 0.5:
        print("✓ Correctly identified as low risk")
    else:
        print(f"⚠ Risk assessment mismatch. Expected: {url_data['expected']}, Score: {score}")
    
    return submission_id, report


def test_submit_email():
    """Test email submission."""
    print("\nTesting email submission...")
    
    # Create temp email file
    email_path = Path("test_email.eml")
    email_path.write_text(SAMPLE_EMAIL)
    
    try:
        # Submit email
        with open(email_path, "rb") as f:
            files = {"eml": ("test.eml", f, "message/rfc822")}
            response = httpx.post(f"{BASE_URL}/submit", files=files, timeout=30)
        
        assert response.status_code == 200
        data = response.json()
        submission_id = data["id"]
        
        print(f"✓ Email submission created: {submission_id}")
        
        # Wait for processing
        time.sleep(2)
        
        # Get report
        response = httpx.get(f"{BASE_URL}/report/{submission_id}")
        assert response.status_code == 200
        report = response.json()
        
        print(f"Status: {report['status']}")
        if report.get("score"):
            print(f"Score: {report['score']}")
        
        return submission_id, report
        
    finally:
        # Clean up
        if email_path.exists():
            email_path.unlink()


def test_metrics():
    """Test metrics endpoint."""
    print("\nTesting metrics endpoint...")
    response = httpx.get(f"{BASE_URL}/metrics")
    assert response.status_code == 200
    data = response.json()
    
    print(f"Total submissions: {data['total_submissions']}")
    print(f"Submissions (last 24h): {data['submissions_last_24h']}")
    print(f"Average score: {data['average_score']:.3f}")
    print(f"High risk count: {data['high_risk_count']}")
    print("✓ Metrics retrieved successfully")


def test_report_rendering(submission_id):
    """Test report rendering."""
    print(f"\nTesting report rendering for {submission_id}...")
    response = httpx.get(f"{BASE_URL}/report/{submission_id}")
    assert response.status_code == 200
    report = response.json()
    
    if report.get("report_markdown"):
        print("✓ Markdown report generated")
        print("\n--- Report Preview (first 500 chars) ---")
        print(report["report_markdown"][:500] + "...")
    else:
        print("⚠ No markdown report generated")


def run_all_tests():
    """Run all API tests."""
    print("=== Phishing Triage API Test Suite ===\n")
    
    try:
        # Test health
        test_health()
        
        # Test URL submissions
        submission_ids = []
        for url_data in TEST_URLS:
            sid, report = test_submit_url(url_data)
            submission_ids.append(sid)
            time.sleep(1)  # Rate limiting
        
        # Test email submission
        email_sid, email_report = test_submit_email()
        submission_ids.append(email_sid)
        
        # Test metrics
        test_metrics()
        
        # Test report rendering
        if submission_ids:
            test_report_rendering(submission_ids[0])
        
        print("\n=== All tests completed ===")
        
    except httpx.ConnectError:
        print("\n❌ Error: Cannot connect to API. Is the server running?")
        print("Start the server with: uvicorn api.main:app --reload")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)


def check_model_exists():
    """Check if model file exists."""
    model_path = Path("ml/model.joblib")
    if not model_path.exists():
        print("\n⚠️  Model not found. Training a sample model...")
        print("Run: python -m ml.train")
        return False
    return True


if __name__ == "__main__":
    # Check prerequisites
    if not check_model_exists():
        print("\nPlease train the model first before running tests.")
        sys.exit(1)
    
    # Run tests
    run_all_tests()
