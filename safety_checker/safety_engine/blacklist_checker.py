import requests
import logging
from typing import Dict, Any, List
from urllib.parse import urlparse
import tldextract
import hashlib
import time

logger = logging.getLogger(__name__)

class BlacklistChecker:
    """Check URLs and domains against various blacklists"""
    
    def __init__(self):
        # Known malicious domains (this would typically be a much larger list)
        self.known_malicious_domains = {
            'phishing-site.com',
            'malware-host.net',
            'scam-website.org',
            # Add more known malicious domains here
        }
        
        # Suspicious TLDs that are often used for malicious purposes
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review',
            '.work', '.party', '.racing', '.win', '.bid', '.loan', '.men',
            '.cricket', '.science', '.stream', '.date', '.faith', '.accountant'
        }
        
        # URL shorteners (can hide malicious destinations)
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 'short.link', 'ow.ly', 't.co',
            'goo.gl', 'is.gd', 'buff.ly', 'tiny.cc', 'lnkd.in',
            'rebrand.ly', 'cutt.ly', 'bitly.com', 'shorte.st'
        }
        
        # Free hosting providers (often abused)
        self.free_hosting_providers = {
            'blogspot.com', 'wordpress.com', 'weebly.com', 'wix.com',
            'squarespace.com', 'github.io', 'netlify.app', 'herokuapp.com',
            '000webhost.com', 'freehostia.com', 'byethost.com'
        }
    
    def check_domain_blacklist(self, url_or_domain: str) -> Dict[str, Any]:
        """
        Check domain against various blacklists and suspicious indicators
        """
        result = {
            'status': 'unknown',
            'domain': '',
            'is_blacklisted': False,
            'blacklist_sources': [],
            'suspicious_indicators': [],
            'risk_score': 0,
            'details': {}
        }
        
        try:
            # Extract domain
            domain = self._extract_domain(url_or_domain)
            result['domain'] = domain
            
            # Check against known malicious domains
            malicious_check = self._check_known_malicious(domain)
            if malicious_check['is_malicious']:
                result['is_blacklisted'] = True
                result['blacklist_sources'].append('Known Malicious Domains')
                result['risk_score'] += 80
            
            # Check TLD suspiciousness
            tld_check = self._check_suspicious_tld(domain)
            if tld_check['is_suspicious']:
                result['suspicious_indicators'].extend(tld_check['indicators'])
                result['risk_score'] += tld_check['risk_score']
            
            # Check URL shorteners
            shortener_check = self._check_url_shortener(domain)
            if shortener_check['is_shortener']:
                result['suspicious_indicators'].extend(shortener_check['indicators'])
                result['risk_score'] += shortener_check['risk_score']
            
            # Check free hosting
            hosting_check = self._check_free_hosting(domain)
            if hosting_check['is_free_hosting']:
                result['suspicious_indicators'].extend(hosting_check['indicators'])
                result['risk_score'] += hosting_check['risk_score']
            
            # Check domain reputation using multiple sources
            reputation_check = self._check_domain_reputation(domain)
            result['details']['reputation_check'] = reputation_check
            if reputation_check.get('is_suspicious', False):
                result['suspicious_indicators'].extend(reputation_check.get('reasons', []))
                result['risk_score'] += reputation_check.get('risk_score', 0)
            
            # Determine final status
            if result['is_blacklisted']:
                result['status'] = 'failed'
            elif result['risk_score'] > 30:
                result['status'] = 'warning'
            else:
                result['status'] = 'passed'
                
        except Exception as e:
            logger.error(f"Blacklist check failed for {url_or_domain}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            
        return result
    
    def check_ip_blacklist(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address against blacklists
        """
        result = {
            'status': 'unknown',
            'ip_address': ip_address,
            'is_blacklisted': False,
            'blacklist_sources': [],
            'reputation_score': 0,
            'details': {}
        }
        
        try:
            # Check against known malicious IP ranges
            ip_check = self._check_malicious_ip_ranges(ip_address)
            result.update(ip_check)
            
            # Check IP reputation (this would typically use external APIs)
            reputation_check = self._check_ip_reputation(ip_address)
            result['details']['reputation_check'] = reputation_check
            
            if result['is_blacklisted']:
                result['status'] = 'failed'
            elif result['reputation_score'] > 50:
                result['status'] = 'warning'
            else:
                result['status'] = 'passed'
                
        except Exception as e:
            logger.error(f"IP blacklist check failed for {ip_address}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            
        return result
    
    def _extract_domain(self, url_or_domain: str) -> str:
        """Extract domain from URL or return domain as-is"""
        if '://' in url_or_domain:
            parsed = urlparse(url_or_domain)
            domain = parsed.netloc
        else:
            domain = url_or_domain
        
        # Remove port if present
        domain = domain.split(':')[0].lower().strip()
        
        # Remove www if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return domain
    
    def _check_known_malicious(self, domain: str) -> Dict[str, Any]:
        """Check against known malicious domains"""
        result = {
            'is_malicious': False,
            'match_type': None
        }
        
        # Direct match
        if domain in self.known_malicious_domains:
            result['is_malicious'] = True
            result['match_type'] = 'exact'
            return result
        
        # Check subdomains
        for malicious_domain in self.known_malicious_domains:
            if domain.endswith('.' + malicious_domain):
                result['is_malicious'] = True
                result['match_type'] = 'subdomain'
                return result
        
        return result
    
    def _check_suspicious_tld(self, domain: str) -> Dict[str, Any]:
        """Check for suspicious top-level domains"""
        result = {
            'is_suspicious': False,
            'indicators': [],
            'risk_score': 0
        }
        
        extracted = tldextract.extract(domain)
        tld = '.' + extracted.suffix
        
        if tld in self.suspicious_tlds:
            result['is_suspicious'] = True
            result['indicators'].append(f'Uses suspicious TLD: {tld}')
            result['risk_score'] = 20
        
        return result
    
    def _check_url_shortener(self, domain: str) -> Dict[str, Any]:
        """Check if domain is a URL shortener"""
        result = {
            'is_shortener': False,
            'indicators': [],
            'risk_score': 0
        }
        
        if domain in self.url_shorteners:
            result['is_shortener'] = True
            result['indicators'].append('URL shortener detected - final destination unknown')
            result['risk_score'] = 25
        
        return result
    
    def _check_free_hosting(self, domain: str) -> Dict[str, Any]:
        """Check if domain uses free hosting"""
        result = {
            'is_free_hosting': False,
            'indicators': [],
            'risk_score': 0
        }
        
        for provider in self.free_hosting_providers:
            if domain.endswith(provider) or domain == provider:
                result['is_free_hosting'] = True
                result['indicators'].append(f'Uses free hosting provider: {provider}')
                result['risk_score'] = 15
                break
        
        return result
    
    def _check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Check domain reputation using various heuristics
        In a production environment, this would integrate with reputation APIs
        """
        result = {
            'is_suspicious': False,
            'reasons': [],
            'risk_score': 0,
            'analysis': {}
        }
        
        try:
            # Domain length analysis
            if len(domain) > 50:
                result['reasons'].append('Unusually long domain name')
                result['risk_score'] += 10
            
            # Character analysis
            if '-' in domain and domain.count('-') > 3:
                result['reasons'].append('Multiple hyphens in domain')
                result['risk_score'] += 10
            
            # Number of dots (subdomains)
            if domain.count('.') > 3:
                result['reasons'].append('Multiple subdomains detected')
                result['risk_score'] += 8
            
            # Suspicious character patterns
            if any(char.isdigit() for char in domain.split('.')[0]):
                # Check if it's not a legitimate pattern
                if not any(pattern in domain for pattern in ['api', 'cdn', 'mail', 'ftp']):
                    result['reasons'].append('Numbers in primary domain')
                    result['risk_score'] += 5
            
            # Check for common typosquatting patterns
            typosquat_check = self._check_typosquatting(domain)
            if typosquat_check['is_suspicious']:
                result['reasons'].extend(typosquat_check['reasons'])
                result['risk_score'] += typosquat_check['risk_score']
            
            if result['risk_score'] > 0:
                result['is_suspicious'] = True
                
        except Exception as e:
            logger.error(f"Domain reputation check failed for {domain}: {e}")
            
        return result
    
    def _check_typosquatting(self, domain: str) -> Dict[str, Any]:
        """Check for potential typosquatting of popular domains"""
        result = {
            'is_suspicious': False,
            'reasons': [],
            'risk_score': 0
        }
        
        # Popular domains to check against
        popular_domains = [
            'google', 'facebook', 'amazon', 'microsoft', 'apple',
            'twitter', 'instagram', 'linkedin', 'github', 'paypal',
            'netflix', 'youtube', 'yahoo', 'ebay', 'adobe'
        ]
        
        extracted = tldextract.extract(domain)
        domain_name = extracted.domain.lower()
        
        for popular in popular_domains:
            if popular != domain_name and self._is_similar_domain(domain_name, popular):
                result['is_suspicious'] = True
                result['reasons'].append(f'Potential typosquatting of {popular}')
                result['risk_score'] = 30
                break
        
        return result
    
    def _is_similar_domain(self, domain1: str, domain2: str) -> bool:
        """Check if two domains are suspiciously similar"""
        # Simple Levenshtein distance check
        if abs(len(domain1) - len(domain2)) > 2:
            return False
        
        # Calculate character differences
        differences = 0
        min_len = min(len(domain1), len(domain2))
        
        for i in range(min_len):
            if domain1[i] != domain2[i]:
                differences += 1
                if differences > 2:
                    return False
        
        # Add length difference
        differences += abs(len(domain1) - len(domain2))
        
        # Consider similar if 1-2 character differences
        return 1 <= differences <= 2
    
    def _check_malicious_ip_ranges(self, ip_address: str) -> Dict[str, Any]:
        """Check IP against known malicious ranges"""
        result = {
            'is_blacklisted': False,
            'blacklist_sources': [],
            'reputation_score': 0
        }
        
        # Check for private/internal IPs (shouldn't be hosting public websites)
        if self._is_private_ip(ip_address):
            result['is_blacklisted'] = True
            result['blacklist_sources'].append('Private IP range')
            result['reputation_score'] = 70
        
        # In a real implementation, you would check against:
        # - Spamhaus SBL
        # - SURBL
        # - DNS blacklists
        # - Commercial threat intelligence feeds
        
        return result
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP address is in private range"""
        private_ranges = [
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
            '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.',
            '127.'
        ]
        
        return any(ip_address.startswith(prefix) for prefix in private_ranges)
    
    def _check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP reputation
        In production, this would use reputation APIs like VirusTotal, AbuseIPDB, etc.
        """
        result = {
            'reputation_score': 0,
            'sources_checked': [],
            'analysis': 'Limited analysis - would use external APIs in production'
        }
        
        # Basic checks
        if self._is_private_ip(ip_address):
            result['reputation_score'] = 60
            result['sources_checked'].append('Private IP detection')
        
        return result
    
    def bulk_check_domains(self, domains: List[str]) -> Dict[str, Any]:
        """Check multiple domains efficiently"""
        result = {
            'total_domains': len(domains),
            'clean_domains': 0,
            'suspicious_domains': 0,
            'blacklisted_domains': 0,
            'results': {}
        }
        
        for domain in domains:
            domain_result = self.check_domain_blacklist(domain)
            result['results'][domain] = domain_result
            
            if domain_result.get('is_blacklisted', False):
                result['blacklisted_domains'] += 1
            elif domain_result.get('risk_score', 0) > 30:
                result['suspicious_domains'] += 1
            else:
                result['clean_domains'] += 1
        
        return result