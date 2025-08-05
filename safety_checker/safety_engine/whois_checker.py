import whois
import logging
from typing import Dict, Any
from datetime import datetime, timezone
from urllib.parse import urlparse
import tldextract

logger = logging.getLogger(__name__)

class WHOISChecker:
    """WHOIS domain information checker for domain age and suspicious patterns"""
    
    def __init__(self):
        self.suspicious_registrars = [
            'namecheap',  # Often used for suspicious domains (when combined with other factors)
            'godaddy',    # Popular with cybercriminals
        ]
        self.suspicious_keywords = [
            'privacy', 'proxy', 'protected', 'whoisguard', 'private',
            'temp', 'temporary', 'disposable'
        ]
        
    def check_domain_info(self, url_or_domain: str) -> Dict[str, Any]:
        """
        Get comprehensive WHOIS information and analyze for suspicious patterns
        """
        result = {
            'status': 'unknown',
            'domain': '',
            'domain_age_days': 0,
            'is_suspicious': False,
            'risk_score': 0,
            'registrar': '',
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'registrant_info': {},
            'suspicious_indicators': [],
            'details': {}
        }
        
        try:
            # Extract domain from URL
            if '://' in url_or_domain:
                parsed = urlparse(url_or_domain)
                domain = parsed.netloc
            else:
                domain = url_or_domain
            
            # Clean domain
            domain = domain.lower().strip()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            result['domain'] = domain
            
            # Extract domain parts
            extracted = tldextract.extract(domain)
            if not extracted.domain or not extracted.suffix:
                result['status'] = 'error'
                result['error'] = 'Invalid domain format'
                return result
            
            # Get WHOIS information
            whois_info = whois.whois(domain)
            
            if whois_info:
                result.update(self._parse_whois_info(whois_info))
                result['details']['raw_whois'] = str(whois_info)
                
                # Analyze for suspicious patterns
                analysis = self._analyze_domain_patterns(result, extracted)
                result.update(analysis)
                
                result['status'] = 'passed'
            else:
                result['status'] = 'error'
                result['error'] = 'Could not retrieve WHOIS information'
                
        except Exception as e:
            logger.error(f"WHOIS check failed for {url_or_domain}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            
        return result
    
    def _parse_whois_info(self, whois_info) -> Dict[str, Any]:
        """Parse WHOIS information into structured format"""
        parsed = {
            'registrar': '',
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'registrant_info': {},
            'domain_age_days': 0
        }
        
        try:
            # Registrar
            if hasattr(whois_info, 'registrar') and whois_info.registrar:
                registrar = whois_info.registrar
                if isinstance(registrar, list):
                    registrar = registrar[0] if registrar else ''
                parsed['registrar'] = str(registrar).strip()
            
            # Dates
            for date_field in ['creation_date', 'expiration_date', 'updated_date']:
                date_value = getattr(whois_info, date_field, None)
                if date_value:
                    if isinstance(date_value, list):
                        date_value = date_value[0] if date_value else None
                    
                    if date_value:
                        if isinstance(date_value, datetime):
                            # Convert datetime to ISO string for JSON serialization
                            if date_value.tzinfo is None:
                                date_value = date_value.replace(tzinfo=timezone.utc)
                            parsed[date_field] = date_value.isoformat()
                        elif isinstance(date_value, str):
                            # Try to parse string dates and convert to ISO
                            try:
                                dt = datetime.fromisoformat(date_value.replace('Z', '+00:00'))
                                parsed[date_field] = dt.isoformat()
                            except ValueError:
                                pass
            
            # Calculate domain age
            if parsed['creation_date']:
                now = datetime.now(timezone.utc)
                try:
                    # Parse the ISO string back to datetime for age calculation
                    creation_date = datetime.fromisoformat(parsed['creation_date'])
                    if creation_date.tzinfo is None:
                        creation_date = creation_date.replace(tzinfo=timezone.utc)
                    
                    age_delta = now - creation_date
                    parsed['domain_age_days'] = age_delta.days
                except (ValueError, TypeError):
                    parsed['domain_age_days'] = 0
            
            # Name servers
            if hasattr(whois_info, 'name_servers') and whois_info.name_servers:
                name_servers = whois_info.name_servers
                if isinstance(name_servers, list):
                    parsed['name_servers'] = [str(ns).lower().strip() for ns in name_servers if ns]
                else:
                    parsed['name_servers'] = [str(name_servers).lower().strip()]
            
            # Registrant information
            registrant_fields = ['name', 'organization', 'address', 'city', 'state', 'country']
            for field in registrant_fields:
                value = getattr(whois_info, field, None)
                if value:
                    if isinstance(value, list):
                        value = value[0] if value else None
                    if value:
                        parsed['registrant_info'][field] = str(value).strip()
                        
        except Exception as e:
            logger.error(f"Failed to parse WHOIS info: {e}")
            
        return parsed
    
    def _analyze_domain_patterns(self, domain_info: Dict[str, Any], extracted_domain) -> Dict[str, Any]:
        """Analyze domain for suspicious patterns"""
        analysis = {
            'is_suspicious': False,
            'risk_score': 0,
            'suspicious_indicators': []
        }
        
        try:
            domain = domain_info['domain']
            registrar = domain_info.get('registrar', '').lower()
            domain_age = domain_info.get('domain_age_days', 0)
            registrant_info = domain_info.get('registrant_info', {})
            
            # Check domain age (very new domains can be suspicious)
            if domain_age < 30:
                analysis['suspicious_indicators'].append(f'Very new domain ({domain_age} days old)')
                analysis['risk_score'] += 25
            elif domain_age < 90:
                analysis['suspicious_indicators'].append(f'Recently created domain ({domain_age} days old)')
                analysis['risk_score'] += 15
            
            # Check for privacy protection (not inherently bad, but worth noting)
            registrant_name = registrant_info.get('name', '').lower()
            registrant_org = registrant_info.get('organization', '').lower()
            
            privacy_indicators = ['privacy', 'protected', 'proxy', 'whoisguard', 'private']
            if any(indicator in registrant_name for indicator in privacy_indicators):
                analysis['suspicious_indicators'].append('Domain uses privacy protection')
                analysis['risk_score'] += 5
            
            if any(indicator in registrant_org for indicator in privacy_indicators):
                analysis['suspicious_indicators'].append('Organization uses privacy service')
                analysis['risk_score'] += 5
            
            # Check for suspicious domain patterns
            domain_lower = domain.lower()
            
            # Multiple hyphens (can indicate suspicious domains)
            if domain_lower.count('-') > 2:
                analysis['suspicious_indicators'].append('Domain contains multiple hyphens')
                analysis['risk_score'] += 10
            
            # Very long domain names
            if len(extracted_domain.domain) > 20:
                analysis['suspicious_indicators'].append('Unusually long domain name')
                analysis['risk_score'] += 10
            
            # Numbers mixed with letters (common in suspicious domains)
            if any(c.isdigit() for c in extracted_domain.domain) and any(c.isalpha() for c in extracted_domain.domain):
                # Only flag if it's not a well-known pattern
                if not any(pattern in domain_lower for pattern in ['web', 'mail', 'ftp', 'api']):
                    analysis['suspicious_indicators'].append('Domain mixes numbers and letters')
                    analysis['risk_score'] += 8
            
            # Check for common typosquatting patterns
            suspicious_patterns = [
                'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
                'twitter', 'instagram', 'linkedin', 'github', 'dropbox'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in domain_lower and domain_lower != pattern:
                    # Check for character substitution
                    if self._is_potential_typosquat(domain_lower, pattern):
                        analysis['suspicious_indicators'].append(f'Potential typosquatting of {pattern}')
                        analysis['risk_score'] += 30
            
            # Check TLD for suspicious extensions
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review']
            domain_tld = '.' + extracted_domain.suffix
            if domain_tld in suspicious_tlds:
                analysis['suspicious_indicators'].append(f'Suspicious TLD: {domain_tld}')
                analysis['risk_score'] += 20
            
            # Check expiration date (domains with very short registration periods can be suspicious)
            if domain_info.get('expiration_date'):
                try:
                    exp_date = domain_info['expiration_date']
                    if exp_date.tzinfo is None:
                        exp_date = exp_date.replace(tzinfo=timezone.utc)
                    
                    now = datetime.now(timezone.utc)
                    days_until_expiry = (exp_date - now).days
                    
                    if days_until_expiry < 30:
                        analysis['suspicious_indicators'].append(f'Domain expires soon ({days_until_expiry} days)')
                        analysis['risk_score'] += 15
                except Exception:
                    pass
            
            # Final assessment
            if analysis['risk_score'] > 30:
                analysis['is_suspicious'] = True
                
        except Exception as e:
            logger.error(f"Domain pattern analysis failed: {e}")
            
        return analysis
    
    def _is_potential_typosquat(self, domain: str, target: str) -> bool:
        """Check if domain is a potential typosquat of target"""
        if len(domain) != len(target):
            # Allow for small differences
            if abs(len(domain) - len(target)) > 2:
                return False
        
        # Check character substitution
        differences = 0
        min_len = min(len(domain), len(target))
        
        for i in range(min_len):
            if domain[i] != target[i]:
                differences += 1
                if differences > 2:
                    return False
        
        # Account for length differences
        differences += abs(len(domain) - len(target))
        
        # Consider it a potential typosquat if 1-3 character differences
        return 1 <= differences <= 3