"""URLhaus API client for URL reputation lookup."""
import httpx
import os
from typing import Dict, Any, Optional
from datetime import datetime
import json

BASE_URL = "https://urlhaus-api.abuse.ch"


def lookup_url(url: str, timeout: int = 20) -> Dict[str, Any]:
    """
    Look up a URL in URLhaus database.
    
    Args:
        url: The URL to look up
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary with URLhaus response data
    """
    # Get auth key from environment
    auth_key = os.getenv("URLHAUS_AUTH_KEY")
    
    headers = {}
    if auth_key:
        headers["Auth-Key"] = auth_key
    
    try:
        # URLhaus API endpoint for URL lookup
        response = httpx.post(
            f"{BASE_URL}/v1/url/",
            headers=headers,
            data={"url": url},
            timeout=timeout
        )
        
        response.raise_for_status()
        
        data = response.json()
        
        # Parse and enhance the response
        if data.get("query_status") == "ok":
            return parse_urlhaus_response(data)
        else:
            return {
                "query_status": data.get("query_status", "error"),
                "message": data.get("message", "No data found")
            }
            
    except httpx.TimeoutException:
        return {
            "query_status": "error",
            "error": "Request timeout"
        }
    except httpx.HTTPError as e:
        return {
            "query_status": "error",
            "error": f"HTTP error: {str(e)}"
        }
    except Exception as e:
        return {
            "query_status": "error",
            "error": f"Unexpected error: {str(e)}"
        }


def parse_urlhaus_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse and structure URLhaus response data."""
    result = {
        "query_status": "ok",
        "url": data.get("url"),
        "url_id": data.get("url_id"),
        "url_status": data.get("url_status"),  # online/offline/unknown
        "date_added": data.get("date_added"),
        "threat": data.get("threat"),  # malware distribution type
        "reporter": data.get("reporter"),
        "tags": data.get("tags", []),
        "urlhaus_reference": data.get("urlhaus_reference"),
        "payloads": []
    }
    
    # Parse payload information if available
    if data.get("payloads"):
        for payload in data["payloads"]:
            result["payloads"].append({
                "filename": payload.get("filename"),
                "file_type": payload.get("file_type"),
                "response_md5": payload.get("response_md5"),
                "response_sha256": payload.get("response_sha256"),
                "response_size": payload.get("response_size"),
                "signature": payload.get("signature"),
                "firstseen": payload.get("firstseen")
            })
    
    # Parse blacklist information
    if data.get("blacklists"):
        result["blacklists"] = data["blacklists"]
    
    # Risk assessment based on URLhaus data
    result["risk_score"] = calculate_urlhaus_risk_score(result)
    
    return result


def calculate_urlhaus_risk_score(data: Dict[str, Any]) -> float:
    """Calculate risk score based on URLhaus data."""
    score = 0.0
    
    # Status scoring
    if data.get("url_status") == "online":
        score += 0.4
    elif data.get("url_status") == "offline":
        score += 0.2
    
    # Threat type scoring
    threat = (data.get("threat") or "").lower()
    if "malware" in threat:
        score += 0.3
    elif "phishing" in threat:
        score += 0.3
    
    # Payload scoring
    if data.get("payloads"):
        score += min(0.2, len(data["payloads"]) * 0.05)
    
    # Blacklist scoring
    blacklists = data.get("blacklists", {})
    if blacklists:
        # Count active blacklists
        active_blacklists = sum(1 for v in blacklists.values() if v == "listed")
        score += min(0.1, active_blacklists * 0.02)
    
    return min(1.0, score)


def lookup_batch(urls: list, max_batch_size: int = 100) -> Dict[str, Dict[str, Any]]:
    """
    Look up multiple URLs in URLhaus.
    
    Args:
        urls: List of URLs to look up
        max_batch_size: Maximum URLs per batch
        
    Returns:
        Dictionary mapping URLs to their URLhaus data
    """
    results = {}
    
    # URLhaus doesn't have a native batch endpoint, so we'll process individually
    # In production, you might want to implement parallel requests
    for url in urls[:max_batch_size]:
        results[url] = lookup_url(url)
    
    return results


def get_recent_urls(limit: int = 100) -> Optional[list]:
    """
    Get recently added URLs from URLhaus feed.
    
    Args:
        limit: Maximum number of URLs to retrieve
        
    Returns:
        List of recent malicious URLs or None on error
    """
    try:
        # URLhaus provides various feeds
        # Using the recent URLs feed (CSV format)
        response = httpx.get(
            f"{BASE_URL}/downloads/csv_recent/",
            timeout=30
        )
        
        response.raise_for_status()
        
        # Parse CSV response
        lines = response.text.strip().split('\n')
        
        # Skip header and comments
        urls = []
        for line in lines:
            if line.startswith('#') or not line.strip():
                continue
            
            # CSV format: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
            parts = line.split('","')
            if len(parts) >= 3:
                url = parts[2].strip('"')
                urls.append(url)
                
                if len(urls) >= limit:
                    break
        
        return urls
        
    except Exception as e:
        print(f"Error fetching recent URLs: {e}")
        return None


def check_url_status(url: str) -> Dict[str, Any]:
    """
    Quick check if URL is in URLhaus database.
    
    Args:
        url: URL to check
        
    Returns:
        Simplified status response
    """
    result = lookup_url(url)
    
    if result.get("query_status") == "ok":
        return {
            "found": True,
            "status": result.get("url_status"),
            "threat": result.get("threat"),
            "risk_score": result.get("risk_score", 0)
        }
    else:
        return {
            "found": False,
            "status": "not_found",
            "threat": None,
            "risk_score": 0
        }


# Example usage and testing
if __name__ == "__main__":
    # Test URL lookup
    test_url = "http://malicious-example.com/phishing"
    
    print(f"Looking up: {test_url}")
    result = lookup_url(test_url)
    
    print(f"\nResult: {json.dumps(result, indent=2)}")
    
    # Test status check
    status = check_url_status(test_url)
    print(f"\nStatus check: {json.dumps(status, indent=2)}")
