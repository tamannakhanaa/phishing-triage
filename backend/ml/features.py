"""Feature extraction for URLs and emails."""
import re
import math
from urllib.parse import urlparse
import tldextract
from email import policy
from email.parser import BytesParser
from iocextract import extract_urls
from typing import Dict, List, Any

# Suspicious tokens commonly found in phishing URLs
SUS_TOKENS = [
    "login", "verify", "update", "secure", "invoice", "payment",
    "sso", "mfa", "reset", "password", "wallet", "account",
    "suspended", "confirm", "validate", "restore", "unlock",
    "refund", "prize", "winner", "click", "urgent", "expire"
]

# Legitimate domains whitelist (expandable)
LEGIT_DOMAINS = {
    "google.com", "facebook.com", "amazon.com", "microsoft.com",
    "apple.com", "twitter.com", "linkedin.com", "github.com",
    "stackoverflow.com", "wikipedia.org", "youtube.com"
}


def url_features(u: str) -> Dict[str, float]:
    """Extract features from a URL for ML classification."""
    try:
        p = urlparse(u.lower())
        ext = tldextract.extract(u)
        
        # Reconstruct host
        host_parts = [x for x in [ext.subdomain, ext.domain, ext.suffix] if x]
        host = ".".join(host_parts)
        
        # Base domain for checking against whitelist
        base_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ""
        
        features = {}
        
        # Protocol features
        features["scheme_https"] = float(p.scheme == "https")
        features["scheme_http"] = float(p.scheme == "http")
        
        # Length features
        features["url_len"] = len(u)
        features["host_len"] = len(host)
        features["path_len"] = len(p.path or "")
        features["query_len"] = len(p.query or "")
        
        # Host features
        features["num_dots_host"] = host.count(".")
        features["num_hyphens_host"] = host.count("-")
        features["num_underscores_host"] = host.count("_")
        features["num_slashes_path"] = (p.path or "").count("/")
        
        # Suspicious patterns
        features["has_at"] = float("@" in u)
        features["has_double_slash"] = float("//" in p.path if p.path else False)
        features["has_ip_literal"] = float(bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ext.domain or "")))
        
        # URL components
        features["num_params"] = p.query.count("&") + (1 if p.query else 0)
        features["has_fragment"] = float(bool(p.fragment))
        
        # Suspicious tokens
        features["sus_token_count"] = sum(tok in u for tok in SUS_TOKENS)
        features["sus_token_ratio"] = features["sus_token_count"] / len(SUS_TOKENS)
        
        # Domain features
        features["tld_len"] = len(ext.suffix or "")
        features["domain_len"] = len(ext.domain or "")
        features["subdomain_len"] = len(ext.subdomain or "")
        features["num_subdomains"] = ext.subdomain.count(".") + (1 if ext.subdomain else 0)
        
        # Character ratios
        if len(u) > 0:
            features["digit_ratio"] = sum(c.isdigit() for c in u) / len(u)
            features["upper_ratio"] = sum(c.isupper() for c in u) / len(u)
            features["special_char_ratio"] = sum(not c.isalnum() for c in u) / len(u)
        else:
            features["digit_ratio"] = 0.0
            features["upper_ratio"] = 0.0
            features["special_char_ratio"] = 0.0
        
        # Entropy (randomness) of domain
        if ext.domain:
            features["domain_entropy"] = calculate_entropy(ext.domain)
        else:
            features["domain_entropy"] = 0.0
        
        # Known legitimate domain
        features["is_known_legit"] = float(base_domain in LEGIT_DOMAINS)
        
        # Port features
        features["has_port"] = float(p.port is not None)
        features["is_standard_port"] = float(p.port in [80, 443] if p.port else True)
        
        # Homograph features (simple check for mixed scripts)
        features["has_punycode"] = float("xn--" in host)
        
        # Path features
        if p.path:
            path_parts = p.path.strip("/").split("/")
            features["path_depth"] = len(path_parts)
            features["avg_path_token_len"] = sum(len(part) for part in path_parts) / len(path_parts) if path_parts else 0
        else:
            features["path_depth"] = 0
            features["avg_path_token_len"] = 0
        
        # Keyword density in path
        if p.path:
            path_lower = p.path.lower()
            features["path_sus_density"] = sum(tok in path_lower for tok in SUS_TOKENS) / len(SUS_TOKENS)
        else:
            features["path_sus_density"] = 0.0
        
        # File extension features
        if p.path and "." in p.path:
            ext_match = re.search(r'\.([a-zA-Z0-9]+)$', p.path)
            if ext_match:
                file_ext = ext_match.group(1).lower()
                features["has_php"] = float(file_ext == "php")
                features["has_html"] = float(file_ext in ["html", "htm"])
                features["has_exe"] = float(file_ext in ["exe", "scr", "bat", "cmd", "com"])
            else:
                features["has_php"] = 0.0
                features["has_html"] = 0.0
                features["has_exe"] = 0.0
        else:
            features["has_php"] = 0.0
            features["has_html"] = 0.0
            features["has_exe"] = 0.0
        
        return features
        
    except Exception as e:
        print(f"Error extracting features from URL {u}: {e}")
        # Return zero features on error
        return {k: 0.0 for k in get_feature_names()}


def get_feature_names() -> List[str]:
    """Get list of all feature names for consistency."""
    return [
        "scheme_https", "scheme_http", "url_len", "host_len", "path_len",
        "query_len", "num_dots_host", "num_hyphens_host", "num_underscores_host",
        "num_slashes_path", "has_at", "has_double_slash", "has_ip_literal",
        "num_params", "has_fragment", "sus_token_count", "sus_token_ratio",
        "tld_len", "domain_len", "subdomain_len", "num_subdomains",
        "digit_ratio", "upper_ratio", "special_char_ratio", "domain_entropy",
        "is_known_legit", "has_port", "is_standard_port", "has_punycode",
        "path_depth", "avg_path_token_len", "path_sus_density",
        "has_php", "has_html", "has_exe"
    ]


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    
    # Calculate frequency of each character
    freq = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy


def parse_eml_bytes(b: bytes) -> Dict[str, Any]:
    """Parse email bytes and extract headers and URLs."""
    try:
        # Parse email
        msg = BytesParser(policy=policy.default).parsebytes(b)
        
        # Extract headers
        headers = {}
        for key, value in msg.items():
            headers[key.lower()] = str(value)
        
        # Extract body
        body_text = ""
        
        # Try to get text body
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        body_text += part.get_content()
                    except:
                        pass
                elif content_type == "text/html":
                    try:
                        # For HTML, we might want to extract text
                        html_content = part.get_content()
                        # Simple HTML tag removal (in production, use BeautifulSoup)
                        body_text += re.sub(r'<[^>]+>', ' ', html_content)
                    except:
                        pass
        else:
            try:
                body_text = msg.get_content()
            except:
                body_text = str(msg.get_payload(decode=True), 'utf-8', errors='ignore')
        
        # Extract URLs from body (handles defanged URLs too)
        urls = list(extract_urls(body_text))
        
        # Also check headers for URLs (e.g., in List-Unsubscribe)
        header_text = " ".join(headers.values())
        header_urls = list(extract_urls(header_text))
        urls.extend(header_urls)
        
        # Deduplicate URLs
        urls = list(set(urls))
        
        # Extract additional email features
        email_features = extract_email_features(headers, body_text)
        
        return {
            "headers": headers,
            "body": body_text[:1000],  # Truncate for storage
            "urls": urls,
            "features": email_features
        }
        
    except Exception as e:
        print(f"Error parsing email: {e}")
        return {
            "headers": {},
            "body": "",
            "urls": [],
            "features": {}
        }


def extract_email_features(headers: Dict[str, str], body: str) -> Dict[str, Any]:
    """Extract features from email headers and body."""
    features = {}
    
    # SPF/DKIM/DMARC results (if present)
    auth_results = headers.get("authentication-results", "")
    features["spf_pass"] = float("spf=pass" in auth_results.lower())
    features["dkim_pass"] = float("dkim=pass" in auth_results.lower())
    features["dmarc_pass"] = float("dmarc=pass" in auth_results.lower())
    
    # Sender features
    from_header = headers.get("from", "")
    features["from_has_display_name"] = float("<" in from_header and ">" in from_header)
    
    # Reply-To different from From
    reply_to = headers.get("reply-to", "")
    features["has_different_reply_to"] = float(reply_to and reply_to != from_header)
    
    # Subject line features
    subject = headers.get("subject", "")
    features["subject_len"] = len(subject)
    features["subject_has_re"] = float(subject.lower().startswith("re:"))
    features["subject_has_urgent"] = float(any(word in subject.lower() for word in ["urgent", "immediate", "action required"]))
    
    # Body features
    features["body_len"] = len(body)
    features["num_urls_in_body"] = body.lower().count("http://") + body.lower().count("https://")
    
    # Suspicious content
    sus_body_terms = ["verify your account", "suspended", "click here", "act now", "limited time", "congratulations"]
    features["sus_body_terms"] = sum(term in body.lower() for term in sus_body_terms)
    
    return features
