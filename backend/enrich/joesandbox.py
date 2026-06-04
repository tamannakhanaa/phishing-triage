"""Joe Sandbox integration for URL detonation."""
import os
import time
import httpx
from typing import Dict, Any, Optional
import json

# Joe Sandbox API configuration
API_URL = os.getenv("JOE_API_URL", "https://jbxcloud.joesecurity.org/api")
API_KEY = os.getenv("JOE_API_KEY")


class JoeSandboxClient:
    """Client for Joe Sandbox API interactions."""
    
    def __init__(self, api_url: str = None, api_key: str = None):
        """Initialize Joe Sandbox client."""
        self.api_url = api_url or API_URL
        self.api_key = api_key or API_KEY
        
        if not self.api_key:
            raise ValueError("JOE_API_KEY environment variable not set")
    
    def _make_request(self, endpoint: str, method: str = "POST", **kwargs) -> Dict[str, Any]:
        """Make API request to Joe Sandbox."""
        url = f"{self.api_url}{endpoint}"
        
        # Add API key to data
        if "data" in kwargs:
            kwargs["data"]["apikey"] = self.api_key
        else:
            kwargs["data"] = {"apikey": self.api_key}
        
        try:
            if method == "POST":
                response = httpx.post(url, timeout=30, **kwargs)
            else:
                response = httpx.get(url, timeout=30, **kwargs)
            
            response.raise_for_status()
            
            # Joe Sandbox returns JSON
            return response.json()
            
        except httpx.HTTPError as e:
            print(f"HTTP error calling Joe Sandbox: {e}")
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                print(f"Response: {e.response.text}")
            raise
        except Exception as e:
            print(f"Error calling Joe Sandbox: {e}")
            raise
    
    def submit_url(self, url: str, **options) -> Dict[str, Any]:
        """
        Submit URL for analysis.
        
        Args:
            url: URL to analyze
            **options: Additional analysis options
            
        Returns:
            Submission response with webid
        """
        data = {
            "url": url,
            "accept-tac": "1",  # Accept terms and conditions
            "systems": options.get("systems", "w10x64"),  # Default Windows 10 64-bit
            "analysis-time": options.get("analysis_time", "120"),  # 2 minutes
            "internet": "1",
            "ssl-inspection": "1",
            "hybrid-code-analysis": "1",
            "hybrid-decompilation": "1"
        }
        
        # Add any additional options
        data.update(options)
        
        result = self._make_request("/v2/submission/new", data=data)
        
        if result.get("status") == "ok":
            return {
                "webid": result.get("data", {}).get("webid"),
                "submission_id": result.get("data", {}).get("submission_id"),
                "status": "submitted"
            }
        else:
            raise Exception(f"Submission failed: {result}")
    
    def get_status(self, webid: str) -> Dict[str, Any]:
        """Get analysis status."""
        data = {"webid": webid}
        
        result = self._make_request("/v2/analysis/info", data=data)
        
        if result.get("status") == "ok":
            analysis_info = result.get("data", {})
            return {
                "status": analysis_info.get("status"),
                "webid": webid,
                "runs": analysis_info.get("runs", [])
            }
        else:
            return {"status": "error", "error": result.get("error")}
    
    def get_report(self, webid: str, report_type: str = "json") -> Dict[str, Any]:
        """
        Get analysis report.
        
        Args:
            webid: Analysis web ID
            report_type: Type of report (json, html, pdf)
            
        Returns:
            Analysis report data
        """
        data = {
            "webid": webid,
            "type": report_type
        }
        
        result = self._make_request("/v2/analysis/download", data=data)
        
        if report_type == "json" and isinstance(result, dict):
            return parse_joe_report(result)
        else:
            return result
    
    def wait_for_completion(self, webid: str, timeout: int = 300, poll_interval: int = 15) -> Dict[str, Any]:
        """Wait for analysis to complete."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status_info = self.get_status(webid)
            status = status_info.get("status", "").lower()
            
            if status == "finished":
                return self.get_report(webid)
            elif status in ["failed", "error"]:
                return {
                    "status": "failed",
                    "error": f"Analysis failed with status: {status}"
                }
            
            time.sleep(poll_interval)
        
        return {
            "status": "timeout",
            "error": f"Analysis did not complete within {timeout} seconds"
        }


def submit_url(url: str, **options) -> Dict[str, Any]:
    """
    Submit URL to Joe Sandbox for analysis.
    
    Args:
        url: URL to analyze
        **options: Analysis options
        
    Returns:
        Submission info with webid
    """
    client = JoeSandboxClient()
    return client.submit_url(url, **options)


def wait_report(webid: str, timeout_s: int = 300, poll: int = 15) -> Dict[str, Any]:
    """
    Wait for analysis completion and get report.
    
    Args:
        webid: Joe Sandbox analysis ID
        timeout_s: Maximum wait time in seconds
        poll: Poll interval in seconds
        
    Returns:
        Analysis report
    """
    client = JoeSandboxClient()
    return client.wait_for_completion(webid, timeout_s, poll)


def parse_joe_report(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Joe Sandbox JSON report into structured format."""
    # Joe Sandbox has complex nested structure
    analysis = data.get("analysis", {})
    behavior = data.get("behavior", {})
    
    report = {
        "status": "finished",
        "webid": analysis.get("webid"),
        "score": analysis.get("score", 0),
        "detection": analysis.get("detection"),
        "malicious": analysis.get("score", 0) >= 60,  # Joe uses 0-100 scale
        "duration": analysis.get("duration"),
        "submitted_url": analysis.get("url"),
        "analysis_date": analysis.get("time"),
        "system": analysis.get("system"),
        "verdict": get_verdict(analysis.get("score", 0)),
        "signatures": [],
        "mitre_attack": [],
        "network": {
            "domains": [],
            "ips": [],
            "urls": []
        },
        "dropped_files": [],
        "processes": []
    }
    
    # Extract signatures
    for sig in behavior.get("signatures", []):
        if sig.get("score", 0) > 0:
            report["signatures"].append({
                "name": sig.get("name"),
                "score": sig.get("score"),
                "description": sig.get("description"),
                "marks": sig.get("marks", [])
            })
    
    # Extract MITRE ATT&CK
    for mitre in behavior.get("mitre_attack", []):
        report["mitre_attack"].append({
            "technique": mitre.get("technique"),
            "id": mitre.get("id"),
            "tactics": mitre.get("tactics", [])
        })
    
    # Extract network IOCs
    network = behavior.get("network", {})
    
    # Domains
    for domain in network.get("domains", []):
        report["network"]["domains"].append(domain)
    
    # IPs
    for ip in network.get("ips", []):
        report["network"]["ips"].append(ip)
    
    # URLs
    for url_entry in network.get("urls", []):
        report["network"]["urls"].append(url_entry.get("url", url_entry))
    
    # Extract dropped files
    for file_info in behavior.get("dropped_files", []):
        report["dropped_files"].append({
            "filename": file_info.get("name"),
            "path": file_info.get("path"),
            "size": file_info.get("size"),
            "md5": file_info.get("md5"),
            "sha256": file_info.get("sha256"),
            "type": file_info.get("type")
        })
    
    # Extract process information
    for proc in behavior.get("processes", []):
        if proc.get("malicious_confidence", 0) > 0:
            report["processes"].append({
                "name": proc.get("name"),
                "pid": proc.get("pid"),
                "parent_pid": proc.get("parent_pid"),
                "command_line": proc.get("command_line"),
                "malicious_confidence": proc.get("malicious_confidence")
            })
    
    # Add report link if webid exists
    if report["webid"]:
        report["report_url"] = f"https://jbxcloud.joesecurity.org/analysis/{report['webid']}"
    
    return report


def get_verdict(score: int) -> str:
    """Convert Joe Sandbox score to verdict."""
    if score >= 70:
        return "malicious"
    elif score >= 40:
        return "suspicious"
    elif score >= 10:
        return "unknown"
    else:
        return "clean"


def extract_iocs(report: Dict[str, Any]) -> Dict[str, list]:
    """Extract IOCs from Joe Sandbox report."""
    iocs = {
        "urls": [],
        "domains": [],
        "ips": [],
        "hashes": []
    }
    
    # Original URL
    if report.get("submitted_url"):
        iocs["urls"].append(report["submitted_url"])
    
    # Network IOCs
    network = report.get("network", {})
    iocs["domains"].extend(network.get("domains", []))
    iocs["ips"].extend(network.get("ips", []))
    iocs["urls"].extend(network.get("urls", []))
    
    # File hashes
    for file_info in report.get("dropped_files", []):
        if file_info.get("md5"):
            iocs["hashes"].append(file_info["md5"])
        if file_info.get("sha256"):
            iocs["hashes"].append(file_info["sha256"])
    
    # Deduplicate
    for key in iocs:
        iocs[key] = list(set(iocs[key]))
    
    return iocs


def check_quota() -> Dict[str, Any]:
    """Check API quota status."""
    try:
        client = JoeSandboxClient()
        result = client._make_request("/v2/account/info")
        
        if result.get("status") == "ok":
            quota_info = result.get("data", {}).get("quota", {})
            return {
                "status": "ok",
                "monthly_limit": quota_info.get("monthly", {}).get("limit"),
                "monthly_used": quota_info.get("monthly", {}).get("used"),
                "daily_limit": quota_info.get("daily", {}).get("limit"),
                "daily_used": quota_info.get("daily", {}).get("used")
            }
        else:
            return {"status": "error", "error": result.get("error")}
            
    except Exception as e:
        return {"status": "error", "error": str(e)}


# Example usage and testing
if __name__ == "__main__":
    if API_KEY:
        print("Checking Joe Sandbox quota...")
        quota = check_quota()
        print(f"Quota: {json.dumps(quota, indent=2)}")
        
        # Example submission (commented out to avoid consuming quota)
        # test_url = "http://example.com"
        # print(f"\nSubmitting URL: {test_url}")
        # submission = submit_url(test_url)
        # print(f"Submission: {json.dumps(submission, indent=2)}")
        
        # if submission.get("webid"):
        #     print("\nWaiting for analysis...")
        #     report = wait_report(submission["webid"])
        #     print(f"Report: {json.dumps(report, indent=2)}")
        #     
        #     iocs = extract_iocs(report)
        #     print(f"\nExtracted IOCs: {json.dumps(iocs, indent=2)}")
    else:
        print("JOE_API_KEY not set - cannot run tests")
