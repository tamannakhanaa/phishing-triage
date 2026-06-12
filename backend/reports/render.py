"""Report rendering module for phishing triage."""
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime
from typing import Dict, Any, List, Optional
import os
import json

# Initialize Jinja2 environment
def get_template_env():
    """Get Jinja2 environment with proper configuration."""
    return Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")),
        autoescape=select_autoescape(['html', 'xml']),
        trim_blocks=True,
        lstrip_blocks=True
    )


def build_report(
    url: str,
    score: float,
    urlhaus: Dict[str, Any],
    sandbox: Optional[Dict[str, Any]] = None,
    iocs: Optional[Dict[str, List[str]]] = None,
    features: Optional[Dict[str, Any]] = None,
    email_context: Optional[Dict[str, Any]] = None,
    submission_id: Optional[str] = None,
    processing_time: Optional[float] = None,
    note: Optional[str] = None
) -> str:
    """
    Build a comprehensive phishing triage report.
    
    Args:
        url: The analyzed URL
        score: ML classifier score (0-1)
        urlhaus: URLhaus lookup results
        sandbox: Sandbox analysis results
        iocs: Extracted IOCs
        features: URL features used for classification
        email_context: Email headers and metadata
        submission_id: Unique submission ID
        processing_time: Time taken to process
        note: Additional notes
        
    Returns:
        Rendered markdown report
    """
    env = get_template_env()
    template = env.get_template("report.md.j2")
    
    # Default values
    if iocs is None:
        iocs = {"urls": [], "ips": [], "domains": [], "hashes": []}
    
    # Process URLhaus data
    urlhaus_status = "hit" if (urlhaus and urlhaus.get("query_status") == "ok") else "no-hit"
    urlhaus_ref = None
    if urlhaus and urlhaus.get("urlhaus_reference"):
        urlhaus_ref = urlhaus["urlhaus_reference"]
    
    # Process sandbox data
    sandbox_data = None
    if sandbox:
        sandbox_data = {
            "provider": sandbox.get("provider", "unknown"),
            "verdict": get_sandbox_verdict(sandbox),
            "malicious": is_sandbox_malicious(sandbox),
            "score": sandbox.get("report", {}).get("score"),
            "link": get_sandbox_link(sandbox),
            "mitre_attacks": get_mitre_attacks(sandbox)
        }
    
    # Determine risk factors
    risk_factors = analyze_risk_factors(url, score, features, urlhaus, sandbox)
    
    # Calculate confidence
    confidence = abs(score - 0.5) * 2  # Distance from 0.5 normalized
    
    # Get threshold
    threshold = float(os.getenv("RISK_THRESHOLD", "0.85"))
    
    # Generate summary
    if note:
        summary = note
    elif score >= threshold:
        summary = "This URL exhibits multiple characteristics commonly associated with phishing attacks. Immediate action is recommended to protect users and systems."
    elif score >= 0.5:
        summary = "This URL shows some suspicious characteristics but does not meet the high-risk threshold. Further investigation may be warranted."
    else:
        summary = "Initial analysis suggests this URL is likely legitimate. However, continue monitoring for any unusual activity."
    
    # Prepare context
    context = {
        "url": url,
        "score": score,
        "threshold": threshold,
        "confidence": confidence,
        "summary": summary,
        "risk_factors": risk_factors,
        "urlhaus_status": urlhaus_status,
        "urlhaus": urlhaus or {},
        "urlhaus_ref": urlhaus_ref,
        "sandbox": sandbox_data,
        "iocs": iocs,
        "features": format_features(features) if features else {},
        "email_context": email_context,
        "submission_id": submission_id or "N/A",
        "report_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "model_version": "1.0.0",  # Could be dynamic
        "processing_time": f"{processing_time:.2f}" if processing_time else "N/A",
        "additional_notes": generate_additional_notes(url, score, urlhaus, sandbox)
    }
    
    return template.render(**context)


def analyze_risk_factors(
    url: str,
    score: float,
    features: Optional[Dict[str, Any]],
    urlhaus: Optional[Dict[str, Any]],
    sandbox: Optional[Dict[str, Any]]
) -> List[str]:
    """Analyze and list key risk factors."""
    factors = []
    
    # Feature-based factors
    if features:
        if features.get("has_ip_literal"):
            factors.append("URL contains IP address instead of domain name")
        
        if features.get("sus_token_count", 0) > 2:
            factors.append("Multiple suspicious keywords detected in URL")
        
        if features.get("url_len", 0) > 100:
            factors.append("Unusually long URL length")
        
        if features.get("num_params", 0) > 5:
            factors.append("Excessive number of URL parameters")
        
        if not features.get("scheme_https"):
            factors.append("Not using HTTPS encryption")
        
        if features.get("has_at"):
            factors.append("URL contains @ symbol (potential deception)")
        
        if features.get("domain_entropy", 0) > 4.0:
            factors.append("High domain entropy (possibly generated)")
    
    # URLhaus factors
    if urlhaus and urlhaus.get("query_status") == "ok":
        factors.append("Known malicious URL in threat intelligence database")
        
        if urlhaus.get("payloads"):
            factors.append(f"Associated with {len(urlhaus['payloads'])} malware payloads")
    
    # Sandbox factors
    if sandbox and is_sandbox_malicious(sandbox):
        factors.append("Sandbox analysis detected malicious behavior")
        
        mitre = get_mitre_attacks(sandbox)
        if mitre:
            factors.append(f"Exhibits {len(mitre)} MITRE ATT&CK techniques")
    
    # Score-based factor
    if score >= 0.9:
        factors.append("Extremely high phishing probability score")
    elif score >= 0.7:
        factors.append("High phishing probability score")
    
    return factors[:5]  # Limit to top 5 factors


def get_sandbox_verdict(sandbox: Dict[str, Any]) -> str:
    """Extract verdict from sandbox results."""
    if not sandbox or not sandbox.get("report"):
        return "No verdict"
    
    report = sandbox["report"]
    
    # Try different verdict fields based on provider
    if sandbox.get("provider") == "anyrun":
        return report.get("verdict", "Unknown")
    elif sandbox.get("provider") == "joe":
        score = report.get("score", 0)
        if score >= 70:
            return "Malicious"
        elif score >= 40:
            return "Suspicious"
        else:
            return "Clean"
    
    return "Analysis complete"


def is_sandbox_malicious(sandbox: Dict[str, Any]) -> bool:
    """Determine if sandbox detected malicious behavior."""
    if not sandbox or not sandbox.get("report"):
        return False
    
    report = sandbox["report"]
    
    # Check various malicious indicators
    if report.get("malicious"):
        return True
    
    if report.get("score", 0) >= 60:  # Joe Sandbox threshold
        return True
    
    if report.get("verdict", "").lower() in ["malicious", "harmful", "dangerous"]:
        return True
    
    return False


def get_sandbox_link(sandbox: Dict[str, Any]) -> Optional[str]:
    """Get link to full sandbox report."""
    if not sandbox:
        return None
    
    report = sandbox.get("report", {})
    
    # Try different link fields
    return (
        report.get("public_link") or
        report.get("report_url") or
        report.get("html") or
        None
    )


def get_mitre_attacks(sandbox: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract MITRE ATT&CK techniques from sandbox results."""
    if not sandbox or not sandbox.get("report"):
        return []
    
    report = sandbox["report"]
    attacks = []
    
    # Extract from different possible locations
    mitre_data = report.get("mitre_attacks") or report.get("mitre_attack") or []
    
    for attack in mitre_data[:5]:  # Limit to 5 for readability
        if isinstance(attack, dict):
            attacks.append({
                "id": attack.get("id") or attack.get("technique") or "Unknown",
                "name": attack.get("name") or attack.get("technique") or "Unknown technique"
            })
    
    return attacks


def format_features(features: Dict[str, Any]) -> Dict[str, str]:
    """Format features for display in report."""
    if not features:
        return {}
    
    # Select key features to display
    display_features = [
        "url_len", "host_len", "num_params", "sus_token_count",
        "domain_entropy", "has_ip_literal", "scheme_https"
    ]
    
    formatted = {}
    for key in display_features:
        if key in features:
            value = features[key]
            
            # Format boolean values
            if isinstance(value, bool):
                formatted[key.replace("_", " ").title()] = "Yes" if value else "No"
            # Format float values
            elif isinstance(value, float):
                formatted[key.replace("_", " ").title()] = f"{value:.3f}"
            else:
                formatted[key.replace("_", " ").title()] = str(value)
    
    return formatted


def generate_additional_notes(
    url: str,
    score: float,
    urlhaus: Optional[Dict[str, Any]],
    sandbox: Optional[Dict[str, Any]]
) -> str:
    """Generate additional context notes."""
    notes = []
    
    # Note about score interpretation
    if 0.4 <= score <= 0.6:
        notes.append("The score is in the uncertain range. Additional analysis or manual review is recommended.")
    
    # Note about missing enrichment
    if not urlhaus or urlhaus.get("query_status") != "ok":
        if not sandbox:
            notes.append("Consider submitting to a sandbox for behavioral analysis if high-risk indicators are present.")
    
    # Note about sandbox timeout
    if sandbox and sandbox.get("status") == "timeout":
        notes.append("Sandbox analysis timed out. Results may be incomplete.")
    
    return " ".join(notes)


def build_json_report(
    url: str,
    score: float,
    urlhaus: Dict[str, Any],
    sandbox: Optional[Dict[str, Any]] = None,
    iocs: Optional[Dict[str, List[str]]] = None,
    features: Optional[Dict[str, Any]] = None,
    **kwargs
) -> str:
    """Build a JSON format report for API/SOAR consumption."""
    report = {
        "url": url,
        "score": score,
        "risk_level": "high" if score >= float(os.getenv("RISK_THRESHOLD", "0.85")) else "medium" if score >= 0.5 else "low",
        "is_phishing": score >= float(os.getenv("RISK_THRESHOLD", "0.85")),
        "urlhaus": {
            "found": urlhaus and urlhaus.get("query_status") == "ok",
            "threat": urlhaus.get("threat") if urlhaus else None,
            "tags": urlhaus.get("tags", []) if urlhaus else []
        },
        "sandbox": {
            "analyzed": sandbox is not None,
            "provider": sandbox.get("provider") if sandbox else None,
            "malicious": is_sandbox_malicious(sandbox) if sandbox else None,
            "mitre_attacks": get_mitre_attacks(sandbox) if sandbox else []
        },
        "iocs": iocs or {"urls": [], "ips": [], "domains": [], "hashes": []},
        "features": features,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    return json.dumps(report, indent=2)


# Example usage
if __name__ == "__main__":
    # Test report generation
    test_data = {
        "url": "http://phishing-test.suspicious-domain.com/verify-account",
        "score": 0.92,
        "urlhaus": {
            "query_status": "ok",
            "threat": "phishing",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/",
            "tags": ["phishing", "credential-harvesting"]
        },
        "sandbox": {
            "provider": "anyrun",
            "report": {
                "verdict": "Malicious",
                "malicious": True,
                "public_link": "https://app.any.run/tasks/12345",
                "mitre_attacks": [
                    {"id": "T1566", "name": "Phishing"},
                    {"id": "T1598", "name": "Phishing for Information"}
                ]
            }
        },
        "iocs": {
            "urls": ["http://phishing-test.suspicious-domain.com/verify-account"],
            "ips": ["192.168.1.100"],
            "domains": ["phishing-test.suspicious-domain.com"],
            "hashes": []
        },
        "features": {
            "url_len": 52,
            "sus_token_count": 3,
            "has_ip_literal": False,
            "scheme_https": False,
            "domain_entropy": 4.2
        },
        "submission_id": "test-123",
        "processing_time": 2.5
    }
    
    # Generate markdown report
    report = build_report(**test_data)
    print("=== MARKDOWN REPORT ===")
    print(report)
    
    # Generate JSON report
    json_report = build_json_report(**test_data)
    print("\n=== JSON REPORT ===")
    print(json_report)
