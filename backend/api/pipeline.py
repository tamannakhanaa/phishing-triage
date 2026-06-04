"""Processing pipeline for phishing submissions."""
import os
import re
from typing import Dict, Any, List
from sqlalchemy.orm import Session
import traceback
import sys # Ensure sys is imported

# Explicitly add the backend directory to sys.path for module discovery
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    from iocextract import extract_urls, extract_ips, extract_hashes
except ImportError:
    # Fallback IOC extraction
    import re
    def extract_urls(text: str):
        return re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    
    def extract_ips(text: str):
        return re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
    
    def extract_hashes(text: str):
        return re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text)

# Import ML components (will be created next)
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ML imports - handle gracefully if not available
try:
    from ml.predict import score_url
    from ml.features import url_features, parse_eml_bytes
    ML_AVAILABLE = True
except ImportError as e:
    print(f"ML components not available: {e}")
    ML_AVAILABLE = False
    
    # Fallback functions
    def score_url(url: str) -> float:
        """Fallback URL scoring using basic rules."""
        suspicious_patterns = ['login', 'verify', 'update', 'secure', 'account']
        score = 0.0
        url_lower = url.lower()
        
        # Check for suspicious patterns
        score += sum(0.2 for pattern in suspicious_patterns if pattern in url_lower)
        
        # Check for IP address
        import re
        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            score += 0.3
            
        # Check for non-HTTPS
        if not url.startswith('https://'):
            score += 0.1
            
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.cf', '.ga']
        if any(tld in url for tld in suspicious_tlds):
            score += 0.2
            
        return min(1.0, score)
    
    def url_features(url: str) -> dict:
        """Basic URL features fallback."""
        import re
        return {
            'url_len': len(url),
            'has_suspicious_patterns': any(p in url.lower() for p in ['login', 'verify', 'update']),
            'is_https': url.startswith('https://'),
            'has_ip': bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))
        }
    
    def parse_eml_bytes(b: bytes) -> dict:
        """Basic email parsing fallback."""
        from email import policy
        from email.parser import BytesParser
        import re
        
        try:
            msg = BytesParser(policy=policy.default).parsebytes(b)
            headers = {k: str(v) for (k, v) in msg.items()}
            
            # Get body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            body += part.get_content()
                        except:
                            pass
            else:
                try:
                    body = msg.get_content()
                except:
                    body = str(msg.get_payload(decode=True), 'utf-8', errors='ignore')
            
            # Extract URLs with simple regex
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
            
            return {"headers": headers, "urls": urls}
        except Exception as e:
            return {"headers": {}, "urls": []}
from enrich.urlhaus import lookup_url
from enrich.advanced_intel import ThreatIntelAggregator
from reports.render import build_report

RISK_THRESHOLD = float(os.getenv("RISK_THRESHOLD", "0.85"))


async def handle_url_submission(submission_id: str, req: Dict[str, Any], db: Session) -> Dict[str, Any]:
    """Process URL submission through the analysis pipeline."""
    url = str(req["url"]) if hasattr(req["url"], '__str__') else req["url"]
    
    # Extract features and score
    features = url_features(url)
    score = score_url(url)
    
    # Enhanced threat intelligence
    try:
        aggregator = ThreatIntelAggregator()
        intel_results = aggregator.analyze_url(url)
        
        # Legacy URLhaus for backward compatibility
        urlhaus_data = lookup_url(url)
        urlhaus_hit = urlhaus_data.get("query_status") == "ok"
        
        enrichment = {
            "urlhaus": urlhaus_data,
            "advanced_intel": intel_results
        }
    except Exception as e:
        print(f"Threat intelligence lookup failed: {e}")
        urlhaus_data = {"query_status": "error", "error": str(e)}
        urlhaus_hit = False
        enrichment = {"urlhaus": urlhaus_data}
    sandbox_data = None
    
    # Sandbox detonation if high risk or requested
    if (score >= RISK_THRESHOLD or urlhaus_hit) and req.get("detonate"):
        sandbox_data = await detonate_in_sandbox(url, req.get("provider"))
        if sandbox_data:
            enrichment["sandbox"] = sandbox_data
    
    # Extract IOCs
    iocs = extract_iocs(url, urlhaus_data, sandbox_data)
    
    # --- Report Generation ---
    report_payload = {
        "url": url,
        "score": score,
        "features": features,
        "enrichment": enrichment,
        "sandbox": sandbox_data,
        "iocs": iocs,
        "status": "completed"
    }

    # Generate enhanced summary with AI
    try:
        from reports.openai_enhancer import enhance_report_with_openai
        enhanced_notes = enhance_report_with_openai(report_payload)
    except Exception as e:
        print(f"AI report enhancement failed: {e}")
        traceback.print_exc()
        enhanced_notes = ""
    
    # Final report rendering
    report_md = build_report(
        url=url,
        score=score,
        urlhaus=urlhaus_data,
        sandbox=sandbox_data,
        iocs=iocs,
        note=enhanced_notes
    )
    
    return {
        "status": "completed",
        "score": score,
        "features": features,
        "enrichment": enrichment,
        "sandbox": sandbox_data,
        "iocs": iocs,
        "report_markdown": report_md
    }


async def handle_eml_submission(submission_id: str, db: Session) -> Dict[str, Any]:
    """Process email submission through the analysis pipeline."""
    # Get submission from database
    from .models import Submission
    submission = db.query(Submission).filter(Submission.id == submission_id).first()
    
    if not submission or not submission.email_content:
        return {
            "status": "failed",
            "report_markdown": "# Error\n\nNo email content found."
        }
    
    # Parse email
    try:
        parsed = parse_eml_bytes(submission.email_content.encode('utf-8'))
        urls = parsed.get("urls", [])
        headers = parsed.get("headers", {})
    except Exception as e:
        return {
            "status": "failed",
            "report_markdown": f"# Error\n\nFailed to parse email: {str(e)}"
        }
    
    if not urls:
        report = build_report(
            url=None,
            score=0.0,
            urlhaus=None,
            sandbox=None,
            iocs={"urls": [], "ips": [], "hashes": []},
            note="No URLs found in email."
        )
        return {
            "status": "completed",
            "report_markdown": report
        }
    
    # Analyze first URL (or could analyze all)
    first_url = urls[0]
    req = {"url": first_url, "detonate": False}
    
    # Process as URL submission
    result = await handle_url_submission(submission_id, req, db)
    
    # Add email-specific context to report
    result["email_headers"] = headers
    result["all_urls"] = urls
    
    return result


async def detonate_in_sandbox(url: str, provider: str = None) -> Dict[str, Any]:
    """Detonate URL in specified sandbox."""
    # Check daily detonation limit
    if not check_detonation_quota():
        return {"status": "quota_exceeded", "message": "Daily detonation limit reached"}
    
    try:
        if provider == "joe":
            from enrich.joesandbox import submit_url, wait_report
            submission = submit_url(url)
            if submission and submission.get("webid"):
                report = wait_report(
                    submission["webid"],
                    timeout_s=int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "300"))
                )
                return {
                    "provider": "joe",
                    "submission_id": submission.get("webid"),
                    "report": report
                }
        else:
            # Default to ANY.RUN
            from enrich.anyrun import submit_url, wait_report
            task_id = submit_url(url)
            if task_id:
                report = wait_report(
                    task_id,
                    timeout_s=int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "300"))
                )
                return {
                    "provider": "anyrun",
                    "task_id": task_id,
                    "report": report
                }
    except Exception as e:
        print(f"Sandbox detonation failed: {e}")
        return {"status": "error", "error": str(e)}
    
    return None


def extract_iocs(url: str, urlhaus_data: Dict[str, Any], sandbox_data: Dict[str, Any]) -> Dict[str, List[str]]:
    """Extract IOCs from all available sources."""
    iocs = {
        "urls": [url],
        "ips": [],
        "hashes": []
    }
    
    # Extract from URLhaus data
    if urlhaus_data and urlhaus_data.get("query_status") == "ok":
        # URLhaus may provide payload hashes
        if urlhaus_data.get("payloads"):
            for payload in urlhaus_data["payloads"]:
                if payload.get("response_sha256"):
                    iocs["hashes"].append(payload["response_sha256"])
    
    # Extract from sandbox report
    if sandbox_data and sandbox_data.get("report"):
        report_str = str(sandbox_data["report"])
        
        # Extract additional URLs
        extracted_urls = list(extract_urls(report_str))
        iocs["urls"].extend([u for u in extracted_urls if u != url])
        
        # Extract IPs
        iocs["ips"] = list(set(extract_ips(report_str)))
        
        # Extract hashes
        extracted_hashes = list(extract_hashes(report_str))
        iocs["hashes"].extend(extracted_hashes)
    
    # Deduplicate
    iocs["urls"] = list(set(iocs["urls"]))
    iocs["ips"] = list(set(iocs["ips"]))
    iocs["hashes"] = list(set(iocs["hashes"]))
    
    return iocs


def check_detonation_quota() -> bool:
    """Check if we're within daily detonation quota."""
    from datetime import datetime
    from sqlalchemy import create_engine, func
    from .models import Submission
    
    # Get database session
    engine = create_engine(os.getenv("DATABASE_URL", "sqlite:///storage/submissions.db"))
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=engine)
    db = Session()
    
    try:
        # Count detonations today
        today = datetime.utcnow().date()
        count = db.query(func.count(Submission.id)).filter(
            Submission.detonate == True,
            func.date(Submission.created_at) == today
        ).scalar()
        
        max_daily = int(os.getenv("MAX_DAILY_DETONATIONS", "20"))
        return count < max_daily
    finally:
        db.close()
