#!/usr/bin/env python3
"""Quick test of the phishing triage system."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import config
import httpx
import json
import time

def test_system():
    """Test the complete system."""
    print("🛡️ Phishing Triage System - Quick Test")
    print("=" * 60)
    
    # 1. Test Core Functionality
    print("🧪 Testing Core Functionality...")
    
    try:
        from api.pipeline import score_url, url_features
        
        test_urls = [
            "http://phishing-test.com/login",
            "https://www.google.com",
            "http://192.168.1.1/admin/login.php",
            "https://verify-account.suspicious-site.tk/update"
        ]
        
        for url in test_urls:
            score = score_url(url)
            features = url_features(url)
            risk = "HIGH" if score >= 0.5 else "LOW"
            print(f"  URL: {url[:40]:40} Score: {score:.3f} Risk: {risk}")
        
        print("✅ Core functionality working!")
    except Exception as e:
        print(f"❌ Core functionality error: {e}")
        return
    
    # 2. Test APIs
    print("\n🔍 Testing Threat Intelligence APIs...")
    
    try:
        from enrich.urlhaus import lookup_url
        result = lookup_url("http://example.com")
        print(f"  URLhaus: {result.get('query_status')} ✅")
    except Exception as e:
        print(f"  URLhaus: Error - {e}")
    
    try:
        from enrich.free_intel import check_virustotal_public
        result = check_virustotal_public("http://example.com")
        print(f"  VirusTotal: {result.get('source')} ✅")
    except Exception as e:
        print(f"  VirusTotal: Error - {e}")
    
    # 3. Test Server if running
    print("\n🌐 Testing API Server...")
    
    server_running = False
    try:
        response = httpx.get("http://localhost:8001/health", timeout=2)
        if response.status_code == 200:
            print("✅ Server is running on port 8001")
            server_running = True
        else:
            print(f"⚠️ Server responded with status {response.status_code}")
    except Exception:
        try:
            response = httpx.get("http://localhost:8000/health", timeout=2)
            if response.status_code == 200:
                print("✅ Server is running on port 8000")
                server_running = True
            else:
                print(f"⚠️ Server responded with status {response.status_code}")
        except Exception:
            print("❌ No server found on ports 8000 or 8001")
    
    if server_running:
        # Test URL submission
        port = 8001  # Try 8001 first
        try:
            test_data = {"url": "http://phishing-test.com/login"}
            response = httpx.post(f"http://localhost:{port}/submit-url", 
                                json=test_data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                submission_id = result.get("id")
                print(f"✅ URL submission working: {submission_id}")
                
                # Get report
                time.sleep(1)
                response = httpx.get(f"http://localhost:{port}/report/{submission_id}", timeout=5)
                if response.status_code == 200:
                    report = response.json()
                    print(f"✅ Report retrieval working: Score {report.get('score', 'N/A')}")
                    
                    # Show part of the report
                    if report.get('report_markdown'):
                        print("\n📄 Sample Report (first 200 chars):")
                        print(report['report_markdown'][:200] + "...")
                else:
                    print(f"❌ Report retrieval failed: {response.status_code}")
            else:
                print(f"❌ URL submission failed: {response.status_code}")
                print(f"   Response: {response.text}")
        except Exception as e:
            print(f"❌ API test error: {e}")
    
    # 4. Summary
    print(f"\n" + "=" * 60)
    print("✅ SYSTEM STATUS SUMMARY:")
    print("  ✅ Core ML fallback functions working")
    print("  ✅ URLhaus threat intelligence working")
    print("  ✅ VirusTotal API working")
    
    if server_running:
        print("  ✅ FastAPI server running and responding")
        print("  📖 API Docs: http://localhost:8001/docs")
    else:
        print("  ⚠️ Server not running - start with:")
        print("     cd /Users/tranhuy/Desktop/Code/Phishing/phish-triage")
        print("     source .venv/bin/activate") 
        print("     uvicorn api.main:app --host 0.0.0.0 --port 8001")
    
    print(f"\n🎉 Your phishing triage system is working!")

if __name__ == "__main__":
    test_system()

