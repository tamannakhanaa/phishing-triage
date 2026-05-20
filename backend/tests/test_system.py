#!/usr/bin/env python3
"""Test the phishing triage system."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import config
import httpx
import time
import json

def test_api_functionality():
    """Test the API functionality without starting server."""
    print("🧪 Testing Core Functionality...")
    
    # Test scoring
    from api.pipeline import score_url
    test_urls = [
        "http://phishing-test.com/login",
        "https://www.google.com",
        "http://192.168.1.1/admin/login.php",
        "https://verify-account.suspicious-site.tk/update"
    ]
    
    for url in test_urls:
        score = score_url(url)
        risk = "HIGH" if score >= 0.5 else "LOW"
        print(f"  {url[:50]:50} Score: {score:.3f} Risk: {risk}")
    
    # Test URLhaus
    print("\n🔍 Testing URLhaus API...")
    from enrich.urlhaus import lookup_url
    result = lookup_url("http://example.com")
    print(f"  URLhaus Status: {result.get('query_status')}")
    
    # Test VirusTotal
    print("\n🛡️ Testing VirusTotal API...")
    from enrich.free_intel import check_virustotal_public
    result = check_virustotal_public("http://example.com")
    print(f"  VirusTotal Status: {result.get('source')} - Found: {result.get('found')}")
    
    return True

def start_server():
    """Start the API server."""
    print("\n🚀 Starting API Server...")
    import uvicorn
    from api.main import app
    
    try:
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")

def test_server_endpoints():
    """Test server endpoints."""
    print("\n🌐 Testing Server Endpoints...")
    base_url = "http://localhost:8000"
    
    # Test health
    try:
        response = httpx.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health endpoint working")
        else:
            print(f"❌ Health endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Health endpoint error: {e}")
        return False
    
    # Test submit URL
    try:
        test_data = {"url": "http://phishing-test.com/login"}
        response = httpx.post(f"{base_url}/submit", json=test_data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            submission_id = result.get("id")
            print(f"✅ Submit endpoint working: {submission_id}")
            
            # Test get report
            time.sleep(1)  # Let processing complete
            response = httpx.get(f"{base_url}/report/{submission_id}", timeout=5)
            if response.status_code == 200:
                report = response.json()
                print(f"✅ Report endpoint working: Score {report.get('score', 'N/A')}")
            else:
                print(f"❌ Report endpoint failed: {response.status_code}")
        else:
            print(f"❌ Submit endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Submit endpoint error: {e}")
    
    return True

def main():
    """Main test function."""
    print("🛡️ Phishing Triage System - Testing Suite")
    print("=" * 60)
    
    # Test core functionality
    test_api_functionality()
    
    print("\n" + "=" * 60)
    print("🎯 What would you like to do?")
    print("1. Start API Server")
    print("2. Test Server Endpoints (requires server running)")
    print("3. Exit")
    
    choice = input("\nChoice (1-3): ").strip()
    
    if choice == "1":
        start_server()
    elif choice == "2":
        test_server_endpoints()
    elif choice == "3":
        print("👋 Goodbye!")
    else:
        print("❌ Invalid choice")

if __name__ == "__main__":
    main()

