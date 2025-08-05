import requests
import logging
from typing import Dict, Any, List
from urllib.parse import urlparse
import time
from django.conf import settings

logger = logging.getLogger(__name__)

class GoogleSafeBrowsingChecker:
    """Google Safe Browsing API integration for malware and phishing detection"""
    
    def __init__(self):
        self.api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
        self.api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.threat_types = [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE", 
            "POTENTIALLY_HARMFUL_APPLICATION"
        ]
        self.platform_types = ["ANY_PLATFORM"]
        self.threat_entry_types = ["URL"]
        
    def check_url_safety(self, url: str) -> Dict[str, Any]:
        """
        Check URL against Google Safe Browsing database
        Returns detailed threat information
        """
        result = {
            'status': 'unknown',
            'is_safe': True,
            'threats_found': [],
            'threat_types': [],
            'risk_score': 0,
            'details': {}
        }
        
        if not self.api_key:
            result['status'] = 'error'
            result['error'] = 'Google Safe Browsing API key not configured'
            logger.warning("Google Safe Browsing API key not found")
            return result
        
        try:
            # Prepare the request payload
            payload = {
                "client": {
                    "clientId": "safebrowse-url-checker",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": self.threat_types,
                    "platformTypes": self.platform_types,
                    "threatEntryTypes": self.threat_entry_types,
                    "threatEntries": [{"url": url}]
                }
            }
            
            # Make API request
            response = requests.post(
                f"{self.api_url}?key={self.api_key}",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Process response
                if 'matches' in data and data['matches']:
                    result['is_safe'] = False
                    result['threats_found'] = data['matches']
                    result['threat_types'] = [match['threatType'] for match in data['matches']]
                    result['risk_score'] = self._calculate_risk_score(data['matches'])
                    result['status'] = 'warning' if result['risk_score'] < 70 else 'failed'
                else:
                    result['status'] = 'passed'
                    result['is_safe'] = True
                    
                result['details']['api_response'] = data
                
            elif response.status_code == 400:
                result['status'] = 'error'
                result['error'] = 'Invalid request format'
                logger.error(f"Safe Browsing API error 400: {response.text}")
                
            elif response.status_code == 401:
                result['status'] = 'error'
                result['error'] = 'Invalid API key'
                logger.error("Safe Browsing API authentication failed")
                
            elif response.status_code == 429:
                result['status'] = 'error'
                result['error'] = 'API rate limit exceeded'
                logger.error("Safe Browsing API rate limit exceeded")
                
            else:
                result['status'] = 'error'
                result['error'] = f'API request failed with status {response.status_code}'
                logger.error(f"Safe Browsing API error {response.status_code}: {response.text}")
                
        except requests.exceptions.Timeout:
            result['status'] = 'error'
            result['error'] = 'API request timeout'
            logger.error(f"Safe Browsing API timeout for URL: {url}")
            
        except requests.exceptions.RequestException as e:
            result['status'] = 'error'
            result['error'] = f'Network error: {str(e)}'
            logger.error(f"Safe Browsing API network error: {e}")
            
        except Exception as e:
            result['status'] = 'error'
            result['error'] = f'Unexpected error: {str(e)}'
            logger.error(f"Safe Browsing API unexpected error: {e}")
            
        return result
    
    def _calculate_risk_score(self, matches: List[Dict]) -> int:
        """Calculate risk score based on threat types found"""
        risk_score = 0
        
        threat_scores = {
            'MALWARE': 90,
            'SOCIAL_ENGINEERING': 85,
            'UNWANTED_SOFTWARE': 70,
            'POTENTIALLY_HARMFUL_APPLICATION': 65
        }
        
        for match in matches:
            threat_type = match.get('threatType', '')
            score = threat_scores.get(threat_type, 50)
            risk_score = max(risk_score, score)
            
        return risk_score
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Check domain reputation using Safe Browsing
        This is a simplified version focusing on the domain
        """
        # Clean domain
        if '://' in domain:
            domain = urlparse(domain).netloc
        
        # Check both HTTP and HTTPS versions
        urls_to_check = [
            f"http://{domain}",
            f"https://{domain}",
            f"http://www.{domain}",
            f"https://www.{domain}"
        ]
        
        combined_result = {
            'status': 'passed',
            'is_safe': True,
            'threats_found': [],
            'risk_score': 0,
            'checked_urls': []
        }
        
        for url in urls_to_check:
            check_result = self.check_url_safety(url)
            combined_result['checked_urls'].append({
                'url': url,
                'result': check_result
            })
            
            if not check_result.get('is_safe', True):
                combined_result['is_safe'] = False
                combined_result['threats_found'].extend(check_result.get('threats_found', []))
                combined_result['risk_score'] = max(
                    combined_result['risk_score'], 
                    check_result.get('risk_score', 0)
                )
        
        if not combined_result['is_safe']:
            combined_result['status'] = 'warning' if combined_result['risk_score'] < 70 else 'failed'
            
        return combined_result
    
    def bulk_check_urls(self, urls: List[str]) -> Dict[str, Any]:
        """
        Check multiple URLs in a single API request
        More efficient for checking multiple URLs
        """
        if not urls:
            return {'status': 'error', 'error': 'No URLs provided'}
        
        if len(urls) > 500:  # API limit
            return {'status': 'error', 'error': 'Too many URLs (max 500)'}
        
        result = {
            'status': 'unknown',
            'total_urls': len(urls),
            'safe_urls': 0,
            'unsafe_urls': 0,
            'results': {},
            'overall_risk_score': 0
        }
        
        try:
            # Prepare threat entries
            threat_entries = [{"url": url} for url in urls]
            
            payload = {
                "client": {
                    "clientId": "safebrowse-url-checker",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": self.threat_types,
                    "platformTypes": self.platform_types,
                    "threatEntryTypes": self.threat_entry_types,
                    "threatEntries": threat_entries
                }
            }
            
            response = requests.post(
                f"{self.api_url}?key={self.api_key}",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Initialize all URLs as safe
                for url in urls:
                    result['results'][url] = {
                        'is_safe': True,
                        'threats': [],
                        'risk_score': 0
                    }
                
                # Process matches
                if 'matches' in data and data['matches']:
                    for match in data['matches']:
                        threat_url = match['threat']['url']
                        if threat_url in result['results']:
                            result['results'][threat_url]['is_safe'] = False
                            result['results'][threat_url]['threats'].append(match)
                            risk_score = self._calculate_risk_score([match])
                            result['results'][threat_url]['risk_score'] = max(
                                result['results'][threat_url]['risk_score'],
                                risk_score
                            )
                
                # Calculate summary statistics
                for url_result in result['results'].values():
                    if url_result['is_safe']:
                        result['safe_urls'] += 1
                    else:
                        result['unsafe_urls'] += 1
                        result['overall_risk_score'] = max(
                            result['overall_risk_score'],
                            url_result['risk_score']
                        )
                
                result['status'] = 'passed'
                
            else:
                result['status'] = 'error'
                result['error'] = f'API request failed with status {response.status_code}'
                
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            logger.error(f"Bulk URL check failed: {e}")
            
        return result