import ssl
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone
import logging
from typing import Dict, Any, Tuple
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

class SSLChecker:
    """SSL/TLS certificate and connection checker"""
    
    def __init__(self):
        self.timeout = 10
        
    def check_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive SSL certificate check
        Returns detailed certificate information and security assessment
        """
        result = {
            'status': 'unknown',
            'has_ssl': False,
            'certificate_valid': False,
            'certificate_expired': False,
            'is_self_signed': False,
            'certificate_details': {},
            'security_issues': [],
            'risk_score': 0,
            'details': {}
        }
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc or parsed_url.path
            port = parsed_url.port or 443
            
            if parsed_url.scheme != 'https':
                # Check if HTTPS is available
                result['has_ssl'] = self._check_https_availability(domain, port)
                if not result['has_ssl']:
                    result['status'] = 'failed'
                    result['security_issues'].append('No SSL/TLS encryption')
                    result['risk_score'] = 80
                    return result
            else:
                result['has_ssl'] = True
            
            # Get certificate information
            cert_info = self._get_certificate_info(domain, port)
            result['certificate_details'] = cert_info
            
            # Validate certificate
            validation_result = self._validate_certificate(cert_info, domain)
            result.update(validation_result)
            
            # Check for security issues
            security_assessment = self._assess_certificate_security(cert_info)
            result['security_issues'].extend(security_assessment['issues'])
            result['risk_score'] = security_assessment['risk_score']
            
            # Overall status
            if result['certificate_valid'] and not result['certificate_expired']:
                result['status'] = 'passed'
            elif result['security_issues']:
                result['status'] = 'warning'
            else:
                result['status'] = 'failed'
                
        except Exception as e:
            logger.error(f"SSL check failed for {url}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            result['risk_score'] = 50
            
        return result
    
    def _check_https_availability(self, domain: str, port: int = 443) -> bool:
        """Check if HTTPS is available on the domain"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return True
        except Exception:
            return False
    
    def _get_certificate_info(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """Extract detailed certificate information"""
        cert_info = {}
        
        try:
            # Get certificate using OpenSSL
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    
                    # Parse with cryptography library for detailed info
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    cert_info = {
                        'subject': {attr.oid._name: attr.value for attr in cert.subject},
                        'issuer': {attr.oid._name: attr.value for attr in cert.issuer},
                        'version': cert.version.name,
                        'serial_number': str(cert.serial_number),
                        'not_valid_before': cert.not_valid_before,
                        'not_valid_after': cert.not_valid_after,
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'public_key_size': cert.public_key().key_size,
                        'subject_alternative_names': self._get_san_list(cert),
                        'extensions': self._parse_certificate_extensions(cert),
                        'fingerprint_sha256': cert.fingerprint(hashes.SHA256()).hex(),
                        'is_ca': self._is_ca_certificate(cert),
                    }
                    
        except Exception as e:
            logger.error(f"Failed to get certificate info for {domain}: {e}")
            cert_info['error'] = str(e)
            
        return cert_info
    
    def _get_san_list(self, cert) -> list:
        """Extract Subject Alternative Names from certificate"""
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return [san.value for san in san_ext.value]
        except x509.ExtensionNotFound:
            return []
    
    def _parse_certificate_extensions(self, cert) -> Dict[str, Any]:
        """Parse certificate extensions"""
        extensions = {}
        try:
            for ext in cert.extensions:
                ext_name = ext.oid._name
                extensions[ext_name] = {
                    'critical': ext.critical,
                    'value': str(ext.value)
                }
        except Exception as e:
            logger.error(f"Failed to parse extensions: {e}")
        
        return extensions
    
    def _is_ca_certificate(self, cert) -> bool:
        """Check if certificate is a CA certificate"""
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            ).value
            return basic_constraints.ca
        except x509.ExtensionNotFound:
            return False
    
    def _validate_certificate(self, cert_info: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Validate certificate against domain and check expiration"""
        validation = {
            'certificate_valid': False,
            'certificate_expired': False,
            'is_self_signed': False,
            'domain_mismatch': False,
        }
        
        if 'error' in cert_info:
            return validation
        
        try:
            now = datetime.now(timezone.utc)
            
            # Check expiration
            not_after = cert_info.get('not_valid_after')
            if not_after and isinstance(not_after, datetime):
                validation['certificate_expired'] = not_after < now
            
            # Check if certificate is valid for the domain
            subject_cn = cert_info.get('subject', {}).get('2.5.4.3')  # Common Name
            san_list = cert_info.get('subject_alternative_names', [])
            
            domain_valid = False
            if subject_cn and self._domain_matches(domain, subject_cn):
                domain_valid = True
            
            for san in san_list:
                if self._domain_matches(domain, san):
                    domain_valid = True
                    break
            
            validation['domain_mismatch'] = not domain_valid
            
            # Check if self-signed
            subject = cert_info.get('subject', {})
            issuer = cert_info.get('issuer', {})
            validation['is_self_signed'] = subject == issuer
            
            # Overall validity
            validation['certificate_valid'] = (
                not validation['certificate_expired'] and 
                not validation['domain_mismatch'] and 
                not validation['is_self_signed']
            )
            
        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")
            
        return validation
    
    def _domain_matches(self, domain: str, cert_domain: str) -> bool:
        """Check if domain matches certificate domain (including wildcards)"""
        if domain == cert_domain:
            return True
        
        # Handle wildcard certificates
        if cert_domain.startswith('*.'):
            cert_base = cert_domain[2:]
            if domain.endswith('.' + cert_base) or domain == cert_base:
                return True
        
        return False
    
    def _assess_certificate_security(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """Assess certificate security and identify issues"""
        assessment = {
            'issues': [],
            'risk_score': 0
        }
        
        if 'error' in cert_info:
            assessment['issues'].append('Could not retrieve certificate')
            assessment['risk_score'] = 70
            return assessment
        
        # Check key size
        key_size = cert_info.get('public_key_size', 0)
        if key_size < 2048:
            assessment['issues'].append(f'Weak key size: {key_size} bits')
            assessment['risk_score'] += 30
        
        # Check signature algorithm
        sig_algo = cert_info.get('signature_algorithm', '')
        weak_algorithms = ['md5', 'sha1']
        if any(weak in sig_algo.lower() for weak in weak_algorithms):
            assessment['issues'].append(f'Weak signature algorithm: {sig_algo}')
            assessment['risk_score'] += 25
        
        # Check expiration
        try:
            not_after = cert_info.get('not_valid_after')
            if not_after:
                days_until_expiry = (not_after - datetime.now(timezone.utc)).days
                if days_until_expiry < 30:
                    assessment['issues'].append(f'Certificate expires in {days_until_expiry} days')
                    assessment['risk_score'] += 20
        except Exception:
            pass
        
        # Check for self-signed
        subject = cert_info.get('subject', {})
        issuer = cert_info.get('issuer', {})
        if subject == issuer:
            assessment['issues'].append('Self-signed certificate')
            assessment['risk_score'] += 40
        
        return assessment
    
    def check_mixed_content(self, url: str) -> Dict[str, Any]:
        """Check for mixed content issues on HTTPS sites"""
        result = {
            'status': 'unknown',
            'has_mixed_content': False,
            'http_resources': [],
            'risk_score': 0,
            'details': {}
        }
        
        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme != 'https':
                result['status'] = 'skipped'
                result['details']['reason'] = 'Not an HTTPS URL'
                return result
            
            # Fetch the page content
            response = requests.get(url, timeout=self.timeout, verify=True)
            content = response.text.lower()
            
            # Look for HTTP resources in HTTPS page
            http_patterns = [
                'src="http://',
                'href="http://',
                'action="http://',
                "src='http://",
                "href='http://",
                "action='http://",
            ]
            
            mixed_content_found = []
            for pattern in http_patterns:
                if pattern in content:
                    mixed_content_found.append(pattern.replace('"', '').replace("'", ''))
            
            if mixed_content_found:
                result['has_mixed_content'] = True
                result['http_resources'] = mixed_content_found
                result['risk_score'] = 40
                result['status'] = 'warning'
            else:
                result['status'] = 'passed'
                
        except Exception as e:
            logger.error(f"Mixed content check failed for {url}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            
        return result