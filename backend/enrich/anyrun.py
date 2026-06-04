"""ANY.RUN sandbox integration for URL detonation."""
import os
import httpx
import time
from typing import Dict, Any, Optional
from datetime import datetime
import json

# ANY.RUN API base URL (as documented in integrations)
API_BASE = "https://api.any.run/v1"


def get_headers() -> Dict[str, str]:
    """Get API headers with authentication."""
    api_key = os.getenv("ANYRUN_API_KEY")
    if not api_key:
        raise ValueError("ANYRUN_API_KEY environment variable not set")
    
    return {
        "Authorization": f"API-Key {api_key}",
        "Content-Type": "application/json"
    }


def submit_url(url: str, environment: str = "windows") -> Optional[str]:
    """
    Submit a URL for analysis in ANY.RUN sandbox.
    
    Args:
        url: URL to analyze
        environment: Environment to use (windows/linux)
        
    Returns:
        Task ID if successful, None otherwise
    """
    try:
        # Prepare submission data
        data = {
            "obj_type": "url",
            "obj_url": url,
            "env_os": environment,
            "env_version": "10" if environment == "windows" else "ubuntu",
            "env_bitness": 64,
            "opt_network_connect": True,
            "opt_kernel_heavyevasion": True,
            "opt_privacy_type": "bylink",  # Results accessible by link
            "opt_timeout": 120  # 2 minutes timeout
        }
        
        response = httpx.post(
            f"{API_BASE}/analysis",
            headers=get_headers(),
            json=data,
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        # Extract task ID from response
        task_id = result.get("data", {}).get("taskid")
        
        if task_id:
            print(f"Submitted URL to ANY.RUN: Task ID {task_id}")
            return task_id
        else:
            print(f"Failed to get task ID from response: {result}")
            return None
            
    except httpx.HTTPError as e:
        print(f"HTTP error submitting to ANY.RUN: {e}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None
    except Exception as e:
        print(f"Error submitting to ANY.RUN: {e}")
        return None


def get_report(task_id: str) -> Dict[str, Any]:
    """
    Get analysis report for a task.
    
    Args:
        task_id: ANY.RUN task ID
        
    Returns:
        Analysis report data
    """
    try:
        response = httpx.get(
            f"{API_BASE}/report/{task_id}/summary",
            headers=get_headers(),
            timeout=30
        )
        
        response.raise_for_status()
        data = response.json()
        
        if data.get("data"):
            return parse_anyrun_report(data["data"])
        else:
            return {
                "status": "error",
                "error": "No report data available"
            }
            
    except httpx.HTTPError as e:
        return {
            "status": "error",
            "error": f"HTTP error: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "error": f"Unexpected error: {str(e)}"
        }


def wait_report(task_id: str, timeout_s: int = 300, poll_interval: int = 10) -> Dict[str, Any]:
    """
    Wait for analysis to complete and get report.
    
    Args:
        task_id: ANY.RUN task ID
        timeout_s: Maximum time to wait in seconds
        poll_interval: Time between status checks in seconds
        
    Returns:
        Analysis report when complete
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout_s:
        # Check task status
        try:
            response = httpx.get(
                f"{API_BASE}/report/{task_id}",
                headers=get_headers(),
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                status = data.get("data", {}).get("analysis", {}).get("status")
                
                if status == "done":
                    # Get full report
                    return get_report(task_id)
                elif status == "failed":
                    return {
                        "status": "failed",
                        "error": "Analysis failed"
                    }
            
        except Exception as e:
            print(f"Error checking status: {e}")
        
        # Wait before next check
        time.sleep(poll_interval)
    
    return {
        "status": "timeout",
        "error": f"Analysis did not complete within {timeout_s} seconds"
    }


def parse_anyrun_report(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse ANY.RUN report into structured format."""
    report = {
        "status": "done",
        "task_id": data.get("task", {}).get("uuid"),
        "url": data.get("task", {}).get("options", {}).get("obj_url"),
        "verdict": data.get("scores", {}).get("verdict", {}).get("verdict"),
        "threat_level": data.get("scores", {}).get("verdict", {}).get("threat_level"),
        "score": data.get("scores", {}).get("specs", {}).get("score", 0),
        "malicious": data.get("scores", {}).get("verdict", {}).get("malicious", False),
        "analysis_date": data.get("analysis", {}).get("date"),
        "public_link": data.get("task", {}).get("public_link"),
        "mitre_attacks": [],
        "network": {
            "domains": [],
            "ips": [],
            "http_requests": []
        },
        "processes": [],
        "threats": []
    }
    
    # Extract MITRE ATT&CK techniques
    mitre = data.get("mitre", [])
    for technique in mitre:
        report["mitre_attacks"].append({
            "id": technique.get("id"),
            "name": technique.get("name"),
            "tactics": technique.get("tactics", [])
        })
    
    # Extract network IOCs
    network = data.get("network", {})
    
    # Domains
    for domain in network.get("domains", []):
        report["network"]["domains"].append({
            "domain": domain.get("domain"),
            "ip": domain.get("ip"),
            "country": domain.get("country")
        })
    
    # IPs
    for ip_data in network.get("ips", []):
        report["network"]["ips"].append({
            "ip": ip_data.get("ip"),
            "country": ip_data.get("country"),
            "asn": ip_data.get("asn")
        })
    
    # HTTP requests
    for req in network.get("requests", []):
        if req.get("type") == "http":
            report["network"]["http_requests"].append({
                "method": req.get("method"),
                "url": req.get("url"),
                "status": req.get("status")
            })
    
    # Extract process information
    processes = data.get("processes", [])
    for proc in processes:
        if proc.get("malicious"):
            report["processes"].append({
                "name": proc.get("name"),
                "pid": proc.get("pid"),
                "command": proc.get("commandline"),
                "threats": proc.get("threats", [])
            })
    
    # Extract threat indicators
    threats = data.get("threats", [])
    for threat in threats:
        report["threats"].append({
            "category": threat.get("category"),
            "action": threat.get("action"),
            "malicious": threat.get("malicious", False)
        })
    
    return report


def get_iocs(report: Dict[str, Any]) -> Dict[str, list]:
    """Extract IOCs from ANY.RUN report."""
    iocs = {
        "urls": [],
        "domains": [],
        "ips": [],
        "hashes": []
    }
    
    # Extract URLs
    if report.get("url"):
        iocs["urls"].append(report["url"])
    
    # Extract from network activity
    network = report.get("network", {})
    
    for domain_info in network.get("domains", []):
        if domain_info.get("domain"):
            iocs["domains"].append(domain_info["domain"])
        if domain_info.get("ip"):
            iocs["ips"].append(domain_info["ip"])
    
    for ip_info in network.get("ips", []):
        if ip_info.get("ip"):
            iocs["ips"].append(ip_info["ip"])
    
    for request in network.get("http_requests", []):
        if request.get("url"):
            iocs["urls"].append(request["url"])
    
    # Deduplicate
    for key in iocs:
        iocs[key] = list(set(iocs[key]))
    
    return iocs


def check_quota() -> Dict[str, Any]:
    """Check API quota/limits."""
    try:
        response = httpx.get(
            f"{API_BASE}/user",
            headers=get_headers(),
            timeout=30
        )
        
        response.raise_for_status()
        data = response.json()
        
        user_data = data.get("data", {})
        
        return {
            "status": "ok",
            "limits": user_data.get("limits", {}),
            "usage": user_data.get("usage", {})
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


# Testing and example usage
if __name__ == "__main__":
    # Example: Submit a URL and wait for results
    test_url = "http://example.com"
    
    print(f"Checking ANY.RUN quota...")
    quota = check_quota()
    print(f"Quota: {json.dumps(quota, indent=2)}")
    
    if os.getenv("ANYRUN_API_KEY"):
        print(f"\nSubmitting URL: {test_url}")
        task_id = submit_url(test_url)
        
        if task_id:
            print(f"Task submitted: {task_id}")
            print("Waiting for analysis to complete...")
            
            report = wait_report(task_id, timeout_s=180)
            print(f"\nReport: {json.dumps(report, indent=2)}")
            
            # Extract IOCs
            iocs = get_iocs(report)
            print(f"\nExtracted IOCs: {json.dumps(iocs, indent=2)}")
    else:
        print("\nANYRUN_API_KEY not set - skipping submission test")
