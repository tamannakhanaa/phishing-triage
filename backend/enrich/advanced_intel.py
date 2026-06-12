"""Advanced threat intelligence aggregation from multiple free sources."""
import httpx
import json
import time
from typing import Dict, Any, List
from urllib.parse import urlparse
import os
import hashlib
import re


class ThreatIntelAggregator:
    """Aggregate threat intelligence from multiple free sources."""
    
    def __init__(self):
        self.sources = {
            'urlhaus': self._check_urlhaus,
            'virustotal': self._check_virustotal,
            'openphish': self._check_openphish,
            'phishtank': self._check_phishtank,
            'malwaredomains': self._check_malware_domains,
            'hybridanalysis': self._check_hybrid_analysis,
            'alienvault': self._check_alienvault_otx,
        }
        
        # Cache for avoiding duplicate requests
        self.cache = {}
        
    def analyze_url(self, url: str, enable_all: bool = False) -> Dict[str, Any]:
        """
        Analyze URL across multiple threat intelligence sources.
        
        Args:
            url: URL to analyze
            enable_all: If True, checks all sources (may be slower)
            
        Returns:
            Aggregated threat intelligence results
        """
        domain = urlparse(url).netloc
        url_hash = hashlib.md5(url.encode()).hexdigest()
        
        # Check cache first
        if url_hash in self.cache:
            return self.cache[url_hash]
        
        results = {
            'url': url,
            'domain': domain,
            'sources': {},
            'summary': {
                'total_sources': 0,
                'malicious_count': 0,
                'clean_count': 0,
                'unknown_count': 0,
                'overall_risk': 'unknown',
                'confidence': 0.0
            },
            'indicators': [],
            'recommendations': []
        }
        
        # Select sources to check
        sources_to_check = ['urlhaus', 'virustotal', 'openphish']
        if enable_all:
            sources_to_check = list(self.sources.keys())
        
        # Check each source
        for source_name in sources_to_check:
            try:
                if source_name in self.sources:
                    source_result = self.sources[source_name](url)
                    results['sources'][source_name] = source_result
                    results['summary']['total_sources'] += 1
                    
                    # Categorize result
                    if source_result.get('malicious') or source_result.get('phishing'):
                        results['summary']['malicious_count'] += 1
                        results['indicators'].append(f"Flagged as malicious by {source_name}")
                    elif source_result.get('clean'):
                        results['summary']['clean_count'] += 1
                    else:
                        results['summary']['unknown_count'] += 1
                
                # Rate limiting - be respectful to free APIs
                time.sleep(0.5)
                
            except Exception as e:
                results['sources'][source_name] = {'error': str(e)}
        
        # Calculate overall risk
        results = self._calculate_overall_risk(results)
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        # Cache results
        self.cache[url_hash] = results
        
        return results
    
    def _check_urlhaus(self, url: str) -> Dict[str, Any]:
        """Check URLhaus (already implemented)."""
        from .urlhaus import lookup_url
        result = lookup_url(url)
        
        return {
            'source': 'urlhaus',
            'found': result.get('query_status') == 'ok',
            'malicious': result.get('query_status') == 'ok',
            'threat_type': result.get('threat'),
            'tags': result.get('tags', []),
            'reference': result.get('urlhaus_reference'),
            'raw': result
        }
    
    def _check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check VirusTotal."""
        api_key = os.getenv('VT_API_KEY')
        if not api_key:
            return {'source': 'virustotal', 'error': 'No API key'}
        
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
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0
                
                return {
                    'source': 'virustotal',
                    'found': True,
                    'malicious': malicious > 0,
                    'suspicious': suspicious > 0,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'clean_count': stats.get("harmless", 0),
                    'total_engines': total,
                    'detection_ratio': f"{malicious + suspicious}/{total}" if total > 0 else "0/0"
                }
            elif response.status_code == 404:
                return {'source': 'virustotal', 'found': False}
        except Exception as e:
            return {'source': 'virustotal', 'error': str(e)}
        
        return {'source': 'virustotal', 'found': False}
    
    def _check_openphish(self, url: str) -> Dict[str, Any]:
        """Check OpenPhish feed."""
        try:
            # Download recent feed (cache for performance)
            cache_file = "/tmp/openphish_feed.txt"
            cache_age = 0
            
            if os.path.exists(cache_file):
                cache_age = time.time() - os.path.getmtime(cache_file)
            
            # Refresh cache if older than 5 minutes
            if cache_age > 300:
                response = httpx.get("https://openphish.com/feed.txt", timeout=15)
                if response.status_code == 200:
                    with open(cache_file, 'w') as f:
                        f.write(response.text)
            
            # Check if URL is in feed
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    phish_urls = f.read().strip().split('\n')
                
                found = url in phish_urls
                return {
                    'source': 'openphish',
                    'found': found,
                    'phishing': found,
                    'feed_size': len(phish_urls)
                }
        except Exception as e:
            return {'source': 'openphish', 'error': str(e)}
        
        return {'source': 'openphish', 'found': False}
    
    def _check_phishtank(self, url: str) -> Dict[str, Any]:
        """Check PhishTank (if API key available)."""
        api_key = os.getenv('PHISHTANK_API_KEY')
        if not api_key:
            return {'source': 'phishtank', 'error': 'API discontinued'}
        
        # PhishTank API is largely discontinued for new users
        return {'source': 'phishtank', 'error': 'Service discontinued'}
    
    def _check_malware_domains(self, url: str) -> Dict[str, Any]:
        """Check against malware domain lists."""
        domain = urlparse(url).netloc
        
        # Known malicious domain patterns
        suspicious_patterns = [
            r'\.tk$', r'\.ml$', r'\.cf$', r'\.ga$',  # Suspicious TLDs
            r'bit\.ly', r'tinyurl\.com',  # URL shorteners
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
        ]
        
        # Check for suspicious patterns
        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                return {
                    'source': 'malware_domains',
                    'found': True,
                    'suspicious': True,
                    'reason': f'Matches suspicious pattern: {pattern}'
                }
        
        return {'source': 'malware_domains', 'found': False}
    
    def _check_hybrid_analysis(self, url: str) -> Dict[str, Any]:
        """Check Hybrid Analysis (free tier with limits)."""
        # Hybrid Analysis requires API key and has strict limits on free tier
        return {'source': 'hybrid_analysis', 'error': 'Requires API key'}
    
    def _check_alienvault_otx(self, url: str) -> Dict[str, Any]:
        """Check AlienVault OTX (now AT&T Cybersecurity)."""
        try:
            domain = urlparse(url).netloc
            
            # OTX has a public API for basic checks
            response = httpx.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                pulse_count = result.get('pulse_info', {}).get('count', 0)
                
                return {
                    'source': 'alienvault_otx',
                    'found': pulse_count > 0,
                    'malicious': pulse_count > 0,
                    'pulse_count': pulse_count,
                    'reputation': result.get('reputation', 0)
                }
        except Exception as e:
            return {'source': 'alienvault_otx', 'error': str(e)}
        
        return {'source': 'alienvault_otx', 'found': False}
    
    def _calculate_overall_risk(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk assessment."""
        summary = results['summary']
        
        if summary['total_sources'] == 0:
            summary['overall_risk'] = 'unknown'
            summary['confidence'] = 0.0
            return results
        
        malicious_ratio = summary['malicious_count'] / summary['total_sources']
        
        # Determine risk level
        if malicious_ratio >= 0.5:
            summary['overall_risk'] = 'high'
            summary['confidence'] = min(0.9, 0.5 + malicious_ratio)
        elif malicious_ratio >= 0.2:
            summary['overall_risk'] = 'medium'
            summary['confidence'] = 0.3 + malicious_ratio
        elif summary['clean_count'] > summary['unknown_count']:
            summary['overall_risk'] = 'low'
            summary['confidence'] = 0.6
        else:
            summary['overall_risk'] = 'unknown'
            summary['confidence'] = 0.1
        
        return results
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        summary = results['summary']
        
        if summary['overall_risk'] == 'high':
            recommendations.extend([
                "🚨 BLOCK this URL immediately at your web proxy/firewall",
                "🔍 Search for and quarantine any emails containing this URL",
                "📋 Add to your threat intelligence feeds and SIEM",
                "👥 Alert users who may have accessed this URL",
                "🕵️ Investigate any credential harvesting attempts"
            ])
        elif summary['overall_risk'] == 'medium':
            recommendations.extend([
                "⚠️ Consider blocking this URL as a precaution",
                "🔍 Monitor access logs for this URL",
                "📋 Add to watchlist for future monitoring",
                "👥 Brief security team on potential threat"
            ])
        elif summary['overall_risk'] == 'low':
            recommendations.extend([
                "✅ URL appears legitimate based on current intelligence",
                "🔍 Continue normal monitoring procedures",
                "📊 Re-assess if user reports become available"
            ])
        else:
            recommendations.extend([
                "❓ Insufficient intelligence data available",
                "🔍 Consider additional analysis if suspicious activity reported",
                "📊 Monitor for future threat intelligence updates"
            ])
        
        return recommendations


# Example usage and testing
if __name__ == "__main__":
    aggregator = ThreatIntelAggregator()
    
    test_urls = [
        "http://example.com",
        "http://phishing-test.com/login",
        "https://www.google.com"
    ]
    
    for url in test_urls:
        print(f"\n=== Analyzing: {url} ===")
        result = aggregator.analyze_url(url)
        
        print(f"Overall Risk: {result['summary']['overall_risk']}")
        print(f"Confidence: {result['summary']['confidence']:.2f}")
        print(f"Sources checked: {result['summary']['total_sources']}")
        print(f"Malicious detections: {result['summary']['malicious_count']}")
        
        if result['indicators']:
            print("Indicators:")
            for indicator in result['indicators']:
                print(f"  - {indicator}")
        
        print("Recommendations:")
        for rec in result['recommendations'][:3]:  # Show first 3
            print(f"  {rec}")

