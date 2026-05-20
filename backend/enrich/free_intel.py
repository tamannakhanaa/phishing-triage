"""Free threat intelligence sources integration."""
import httpx
import json
import hashlib
from typing import Dict, Any, List
import time


def check_phishtank(url: str) -> Dict[str, Any]:
    """
    Check URL against PhishTank (free tier available).
    API: https://www.phishtank.com/api_info.php
    """
    try:
        # PhishTank requires POST with specific format
        data = {
            "url": url,
            "format": "json"
        }
        
        response = httpx.post(
            "http://checkurl.phishtank.com/checkurl/",
            data=data,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            return {
                "source": "phishtank",
                "found": result.get("results", {}).get("in_database", False),
                "phish": result.get("results", {}).get("valid", False),
                "details": result.get("results", {})
            }
    except Exception as e:
        print(f"PhishTank lookup failed: {e}")
    
    return {"source": "phishtank", "found": False, "error": "lookup_failed"}


def check_openphish(url: str) -> Dict[str, Any]:
    """
    Check against OpenPhish feed (free).
    Feed: https://openphish.com/feed.txt
    """
    try:
        # Download recent feed (cached for performance)
        response = httpx.get("https://openphish.com/feed.txt", timeout=15)
        
        if response.status_code == 200:
            phish_urls = response.text.strip().split('\n')
            found = url in phish_urls
            
            return {
                "source": "openphish",
                "found": found,
                "feed_size": len(phish_urls)
            }
    except Exception as e:
        print(f"OpenPhish lookup failed: {e}")
    
    return {"source": "openphish", "found": False, "error": "lookup_failed"}


def check_malware_domains(domain: str) -> Dict[str, Any]:
    """
    Check domain against malware domain lists.
    Source: Various free feeds
    """
    try:
        # Example: Check against Malware Domain List (if available)
        # This is a placeholder - implement based on available feeds
        
        malicious_domains = [
            "malicious-example.com",
            "phishing-site.tk",
            "fake-bank.ml"
        ]
        
        found = domain in malicious_domains
        
        return {
            "source": "malware_domains",
            "found": found,
            "domain": domain
        }
    except Exception as e:
        print(f"Malware domain lookup failed: {e}")
    
    return {"source": "malware_domains", "found": False, "error": "lookup_failed"}


def check_virustotal_public(url: str, api_key: str = None) -> Dict[str, Any]:
    """
    Check VirusTotal (free tier: 4 requests/minute).
    API: https://developers.virustotal.com/reference/url-info
    """
    import os
    if not api_key:
        api_key = os.getenv("VT_API_KEY")
    
    if not api_key:
        return {"source": "virustotal", "error": "no_api_key"}
    
    try:
        # Create URL ID for VT API
        url_id = hashlib.sha256(url.encode()).hexdigest()
        
        headers = {"x-apikey": api_key}
        response = httpx.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )
        
        if response.status_code == 200:
            result = response.json()
            stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            return {
                "source": "virustotal",
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "clean": stats.get("harmless", 0),
                "total_engines": sum(stats.values()) if stats else 0
            }
        elif response.status_code == 404:
            return {"source": "virustotal", "found": False}
            
    except Exception as e:
        print(f"VirusTotal lookup failed: {e}")
    
    return {"source": "virustotal", "found": False, "error": "lookup_failed"}


def multi_intel_lookup(url: str) -> Dict[str, Any]:
    """
    Check URL against multiple free threat intelligence sources.
    """
    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    
    results = {
        "url": url,
        "domain": domain,
        "sources": {},
        "risk_score": 0.0,
        "found_malicious": False
    }
    
    # Check multiple sources
    sources = [
        ("urlhaus", "already_implemented"),  # We already have this
        ("phishtank", check_phishtank),
        ("openphish", check_openphish),
        ("virustotal", check_virustotal_public),
        ("malware_domains", lambda u: check_malware_domains(domain))
    ]
    
    malicious_count = 0
    total_sources = 0
    
    for source_name, check_func in sources:
        if source_name == "urlhaus":
            continue  # Skip - handled elsewhere
            
        try:
            result = check_func(url)
            results["sources"][source_name] = result
            
            if result.get("found") and (result.get("phish") or result.get("malicious")):
                malicious_count += 1
            
            total_sources += 1
            
            # Rate limiting
            time.sleep(0.5)
            
        except Exception as e:
            results["sources"][source_name] = {"error": str(e)}
    
    # Calculate risk score
    if total_sources > 0:
        results["risk_score"] = malicious_count / total_sources
        results["found_malicious"] = malicious_count > 0
    
    return results


# Example usage
if __name__ == "__main__":
    test_url = "http://phishing-test.com/login"
    
    print(f"Testing free threat intel for: {test_url}")
    result = multi_intel_lookup(test_url)
    
    print(json.dumps(result, indent=2))
