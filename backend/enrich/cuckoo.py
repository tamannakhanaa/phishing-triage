"""Cuckoo Sandbox integration for free self-hosted analysis."""
import httpx
import json
import time
from typing import Dict, Any, Optional
import os


class CuckooClient:
    """Client for Cuckoo Sandbox API."""
    
    def __init__(self, api_url: str = None, api_key: str = None):
        """Initialize Cuckoo client."""
        self.api_url = api_url or os.getenv("CUCKOO_API_URL", "http://localhost:8090")
        self.api_key = api_key or os.getenv("CUCKOO_API_KEY")
        
        self.headers = {}
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"
    
    def submit_url(self, url: str, **options) -> Dict[str, Any]:
        """Submit URL for analysis."""
        data = {
            "url": url,
            "package": "ie",  # Internet Explorer package
            "timeout": options.get("timeout", 120),
            "options": "procmemdump=yes,procdump=yes",
            "tags": "phishing,url"
        }
        
        try:
            response = httpx.post(
                f"{self.api_url}/tasks/create/url",
                headers=self.headers,
                data=data,
                timeout=30
            )
            
            response.raise_for_status()
            result = response.json()
            
            return {
                "task_id": result.get("task_id"),
                "status": "submitted"
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    def get_report(self, task_id: int, format: str = "json") -> Dict[str, Any]:
        """Get analysis report."""
        try:
            response = httpx.get(
                f"{self.api_url}/tasks/report/{task_id}/{format}",
                headers=self.headers,
                timeout=30
            )
            
            response.raise_for_status()
            
            if format == "json":
                return response.json()
            else:
                return {"report": response.text}
                
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    def wait_for_completion(self, task_id: int, timeout: int = 300) -> Dict[str, Any]:
        """Wait for analysis completion."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = httpx.get(
                    f"{self.api_url}/tasks/view/{task_id}",
                    headers=self.headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    task_info = response.json()
                    status = task_info.get("task", {}).get("status")
                    
                    if status == "reported":
                        return self.get_report(task_id)
                    elif status == "failure":
                        return {
                            "status": "failed",
                            "error": "Analysis failed"
                        }
                
            except Exception:
                pass
            
            time.sleep(10)
        
        return {
            "status": "timeout",
            "error": f"Analysis did not complete within {timeout} seconds"
        }


def submit_url(url: str, **options) -> Dict[str, Any]:
    """Submit URL to Cuckoo Sandbox."""
    client = CuckooClient()
    return client.submit_url(url, **options)


def wait_report(task_id: int, timeout_s: int = 300) -> Dict[str, Any]:
    """Wait for Cuckoo analysis completion."""
    client = CuckooClient()
    return client.wait_for_completion(task_id, timeout_s)


# Example usage
if __name__ == "__main__":
    # Test Cuckoo connection
    client = CuckooClient()
    print("Testing Cuckoo Sandbox connection...")
    
    # Note: This requires a running Cuckoo instance
    test_url = "http://example.com"
    result = client.submit_url(test_url)
    print(f"Submission result: {json.dumps(result, indent=2)}")
