import dns.resolver
import dns.exception
import logging
from typing import Dict, Any, List
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)

class DNSChecker:
    """DNS record validation and security check"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 30
        
    def check_dns_records(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive DNS record check including SPF, DKIM, DMARC
        """
        if '://' in domain:
            domain = urlparse(domain).netloc
        
        # Clean domain
        domain = domain.lower().strip()
        if domain.startswith('www.'):
            domain = domain[4:]
        
        result = {
            'status': 'unknown',
            'domain': domain,
            'has_dns_records': False,
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'txt_records': [],
            'ns_records': [],
            'cname_records': [],
            'spf_record': None,
            'dmarc_record': None,
            'dkim_records': [],
            'security_issues': [],
            'risk_score': 0,
            'details': {}
        }
        
        try:
            # Check A records (IPv4)
            result['a_records'] = self._get_dns_records(domain, 'A')
            
            # Check AAAA records (IPv6)
            result['aaaa_records'] = self._get_dns_records(domain, 'AAAA')
            
            # Check MX records (Mail)
            result['mx_records'] = self._get_mx_records(domain)
            
            # Check NS records (Name servers)
            result['ns_records'] = self._get_dns_records(domain, 'NS')
            
            # Check CNAME records
            result['cname_records'] = self._get_dns_records(domain, 'CNAME')
            
            # Check TXT records
            result['txt_records'] = self._get_dns_records(domain, 'TXT')
            
            # Parse security-related records
            self._parse_security_records(result)
            
            # Analyze DNS security
            security_analysis = self._analyze_dns_security(result)
            result.update(security_analysis)
            
            # Check if domain has basic DNS records
            result['has_dns_records'] = bool(
                result['a_records'] or result['aaaa_records'] or 
                result['mx_records'] or result['cname_records']
            )
            
            if result['has_dns_records']:
                result['status'] = 'passed'
            else:
                result['status'] = 'warning'
                result['security_issues'].append('No DNS records found')
                result['risk_score'] += 20
                
        except Exception as e:
            logger.error(f"DNS check failed for {domain}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            
        return result
    
    def _get_dns_records(self, domain: str, record_type: str) -> List[str]:
        """Get DNS records of specified type"""
        records = []
        try:
            answers = self.resolver.resolve(domain, record_type)
            records = [str(answer) for answer in answers]
        except dns.resolver.NXDOMAIN:
            # Domain doesn't exist
            pass
        except dns.resolver.NoAnswer:
            # No records of this type
            pass
        except dns.exception.Timeout:
            logger.warning(f"DNS timeout for {domain} {record_type}")
        except Exception as e:
            logger.error(f"DNS query failed for {domain} {record_type}: {e}")
            
        return records
    
    def _get_mx_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get MX records with priority"""
        mx_records = []
        try:
            answers = self.resolver.resolve(domain, 'MX')
            for answer in answers:
                mx_records.append({
                    'priority': answer.preference,
                    'exchange': str(answer.exchange)
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception as e:
            logger.error(f"MX query failed for {domain}: {e}")
            
        return sorted(mx_records, key=lambda x: x['priority'])
    
    def _parse_security_records(self, result: Dict[str, Any]) -> None:
        """Parse SPF, DMARC, and DKIM records from TXT records"""
        domain = result['domain']
        txt_records = result['txt_records']
        
        # Parse SPF record
        for record in txt_records:
            if record.startswith('"v=spf1') or record.startswith('v=spf1'):
                result['spf_record'] = record.strip('"')
                break
        
        # Parse DMARC record (usually at _dmarc.domain)
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_records = self._get_dns_records(dmarc_domain, 'TXT')
            for record in dmarc_records:
                if 'v=DMARC1' in record:
                    result['dmarc_record'] = record.strip('"')
                    break
        except Exception as e:
            logger.debug(f"DMARC query failed for {domain}: {e}")
        
        # Check common DKIM selectors
        dkim_selectors = ['default', 'google', 'selector1', 'selector2', 's1', 's2']
        for selector in dkim_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                dkim_records = self._get_dns_records(dkim_domain, 'TXT')
                for record in dkim_records:
                    if 'v=DKIM1' in record or 'k=rsa' in record:
                        result['dkim_records'].append({
                            'selector': selector,
                            'record': record.strip('"')
                        })
            except Exception:
                continue
    
    def _analyze_dns_security(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze DNS configuration for security issues"""
        analysis = {
            'security_issues': [],
            'risk_score': 0
        }
        
        # Check SPF record
        spf_analysis = self._analyze_spf_record(result.get('spf_record'))
        analysis['security_issues'].extend(spf_analysis['issues'])
        analysis['risk_score'] += spf_analysis['risk_score']
        
        # Check DMARC record
        dmarc_analysis = self._analyze_dmarc_record(result.get('dmarc_record'))
        analysis['security_issues'].extend(dmarc_analysis['issues'])
        analysis['risk_score'] += dmarc_analysis['risk_score']
        
        # Check DKIM records
        if not result.get('dkim_records'):
            analysis['security_issues'].append('No DKIM records found')
            analysis['risk_score'] += 10
        
        # Check for suspicious DNS patterns
        dns_pattern_analysis = self._check_suspicious_dns_patterns(result)
        analysis['security_issues'].extend(dns_pattern_analysis['issues'])
        analysis['risk_score'] += dns_pattern_analysis['risk_score']
        
        return analysis
    
    def _analyze_spf_record(self, spf_record: str) -> Dict[str, Any]:
        """Analyze SPF record for security issues"""
        analysis = {'issues': [], 'risk_score': 0}
        
        if not spf_record:
            analysis['issues'].append('No SPF record found')
            analysis['risk_score'] += 15
            return analysis
        
        # Check for overly permissive SPF
        if '+all' in spf_record:
            analysis['issues'].append('SPF record allows all senders (+all)')
            analysis['risk_score'] += 25
        elif '?all' in spf_record:
            analysis['issues'].append('SPF record has neutral policy (?all)')
            analysis['risk_score'] += 10
        elif '~all' not in spf_record and '-all' not in spf_record:
            analysis['issues'].append('SPF record missing fail policy')
            analysis['risk_score'] += 15
        
        # Check for too many DNS lookups (SPF limit is 10)
        include_count = spf_record.count('include:')
        redirect_count = spf_record.count('redirect:')
        if include_count + redirect_count > 8:
            analysis['issues'].append(f'SPF record may exceed DNS lookup limit ({include_count + redirect_count} lookups)')
            analysis['risk_score'] += 10
        
        return analysis
    
    def _analyze_dmarc_record(self, dmarc_record: str) -> Dict[str, Any]:
        """Analyze DMARC record for security issues"""
        analysis = {'issues': [], 'risk_score': 0}
        
        if not dmarc_record:
            analysis['issues'].append('No DMARC record found')
            analysis['risk_score'] += 20
            return analysis
        
        # Parse DMARC policy
        policy_match = re.search(r'p=(\w+)', dmarc_record)
        if policy_match:
            policy = policy_match.group(1).lower()
            if policy == 'none':
                analysis['issues'].append('DMARC policy is set to none (monitoring only)')
                analysis['risk_score'] += 10
            elif policy not in ['quarantine', 'reject']:
                analysis['issues'].append(f'Unknown DMARC policy: {policy}')
                analysis['risk_score'] += 15
        else:
            analysis['issues'].append('DMARC record missing policy directive')
            analysis['risk_score'] += 15
        
        # Check for reporting addresses
        if 'rua=' not in dmarc_record and 'ruf=' not in dmarc_record:
            analysis['issues'].append('DMARC record has no reporting addresses')
            analysis['risk_score'] += 5
        
        return analysis
    
    def _check_suspicious_dns_patterns(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Check for suspicious DNS patterns"""
        analysis = {'issues': [], 'risk_score': 0}
        
        # Check for unusual number of A records
        a_records = result.get('a_records', [])
        if len(a_records) > 10:
            analysis['issues'].append(f'Unusual number of A records ({len(a_records)})')
            analysis['risk_score'] += 10
        
        # Check for suspicious IP ranges
        suspicious_ranges = [
            '127.',      # Localhost
            '10.',       # Private network
            '172.16.',   # Private network
            '192.168.',  # Private network
        ]
        
        for record in a_records:
            for suspicious_range in suspicious_ranges:
                if record.startswith(suspicious_range):
                    analysis['issues'].append(f'A record points to suspicious IP: {record}')
                    analysis['risk_score'] += 20
        
        # Check name servers
        ns_records = result.get('ns_records', [])
        if len(ns_records) < 2:
            analysis['issues'].append('Less than 2 name servers configured')
            analysis['risk_score'] += 10
        
        # Check for name servers in suspicious TLDs
        suspicious_ns_tlds = ['.tk', '.ml', '.ga', '.cf']
        for ns in ns_records:
            for tld in suspicious_ns_tlds:
                if ns.endswith(tld):
                    analysis['issues'].append(f'Name server uses suspicious TLD: {ns}')
                    analysis['risk_score'] += 15
        
        return analysis
    
    def check_dns_propagation(self, domain: str) -> Dict[str, Any]:
        """Check DNS propagation across multiple resolvers"""
        if '://' in domain:
            domain = urlparse(domain).netloc
        
        # Clean domain
        domain = domain.lower().strip()
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Public DNS servers to test
        dns_servers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare
            '208.67.222.222', # OpenDNS
            '9.9.9.9',      # Quad9
        ]
        
        result = {
            'status': 'unknown',
            'domain': domain,
            'propagation_complete': True,
            'resolver_results': {},
            'inconsistencies': [],
            'risk_score': 0
        }
        
        try:
            first_result = None
            
            for dns_server in dns_servers:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 5
                
                try:
                    answers = resolver.resolve(domain, 'A')
                    ips = sorted([str(answer) for answer in answers])
                    result['resolver_results'][dns_server] = ips
                    
                    if first_result is None:
                        first_result = ips
                    elif first_result != ips:
                        result['propagation_complete'] = False
                        result['inconsistencies'].append(f'DNS server {dns_server} returns different results')
                        
                except Exception as e:
                    result['resolver_results'][dns_server] = f'Error: {str(e)}'
                    result['propagation_complete'] = False
            
            if result['propagation_complete']:
                result['status'] = 'passed'
            else:
                result['status'] = 'warning'
                result['risk_score'] = 15
                
        except Exception as e:
            logger.error(f"DNS propagation check failed for {domain}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            
        return result