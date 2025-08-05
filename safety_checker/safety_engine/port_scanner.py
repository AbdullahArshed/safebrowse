import socket
import threading
import logging
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

class PortScanner:
    """Network port scanner for security assessment"""
    
    def __init__(self):
        self.timeout = 3
        self.max_threads = 100
        
        # Common ports and their typical services
        self.common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL',
            1433: 'MSSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            5984: 'CouchDB',
            9200: 'Elasticsearch',
        }
        
        # Potentially dangerous ports
        self.dangerous_ports = {
            23: 'Telnet (unencrypted)',
            135: 'RPC Endpoint Mapper',
            139: 'NetBIOS Session Service',
            445: 'SMB',
            1433: 'MSSQL (if exposed)',
            3389: 'RDP (if exposed)',
            5432: 'PostgreSQL (if exposed)',
            6379: 'Redis (if exposed)',
            27017: 'MongoDB (if exposed)',
        }
    
    def scan_common_ports(self, url_or_host: str) -> Dict[str, Any]:
        """
        Scan common ports on the target host
        """
        result = {
            'status': 'unknown',
            'host': '',
            'open_ports': [],
            'dangerous_ports': [],
            'total_scanned': 0,
            'scan_duration': 0,
            'risk_score': 0,
            'security_issues': [],
            'details': {}
        }
        
        try:
            # Extract host from URL
            host = self._extract_host(url_or_host)
            result['host'] = host
            
            start_time = time.time()
            
            # Scan common ports
            ports_to_scan = list(self.common_ports.keys())
            result['total_scanned'] = len(ports_to_scan)
            
            open_ports = self._scan_ports(host, ports_to_scan)
            
            # Process results
            for port, service in open_ports:
                port_info = {
                    'port': port,
                    'service': service,
                    'is_dangerous': port in self.dangerous_ports
                }
                
                result['open_ports'].append(port_info)
                
                if port in self.dangerous_ports:
                    result['dangerous_ports'].append(port_info)
                    result['security_issues'].append(f'Dangerous port {port} ({service}) is open')
            
            # Calculate risk score
            result['risk_score'] = self._calculate_risk_score(result['open_ports'])
            
            result['scan_duration'] = time.time() - start_time
            result['status'] = 'passed'
            
            if result['dangerous_ports']:
                result['status'] = 'warning'
                
        except Exception as e:
            logger.error(f"Port scan failed for {url_or_host}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            
        return result
    
    def scan_port_range(self, url_or_host: str, start_port: int = 1, end_port: int = 1000) -> Dict[str, Any]:
        """
        Scan a range of ports (use with caution - can be slow)
        """
        result = {
            'status': 'unknown',
            'host': '',
            'open_ports': [],
            'total_scanned': 0,
            'scan_duration': 0,
            'risk_score': 0,
            'port_range': f'{start_port}-{end_port}',
            'details': {}
        }
        
        try:
            host = self._extract_host(url_or_host)
            result['host'] = host
            
            start_time = time.time()
            
            # Generate port list
            ports_to_scan = list(range(start_port, end_port + 1))
            result['total_scanned'] = len(ports_to_scan)
            
            # Scan ports (with more limited threading for range scans)
            open_ports = self._scan_ports(host, ports_to_scan, max_workers=50)
            
            # Process results
            for port, service in open_ports:
                port_info = {
                    'port': port,
                    'service': service or 'Unknown',
                    'is_dangerous': port in self.dangerous_ports
                }
                result['open_ports'].append(port_info)
            
            result['risk_score'] = self._calculate_risk_score(result['open_ports'])
            result['scan_duration'] = time.time() - start_time
            result['status'] = 'passed'
            
        except Exception as e:
            logger.error(f"Port range scan failed for {url_or_host}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            
        return result
    
    def _extract_host(self, url_or_host: str) -> str:
        """Extract hostname/IP from URL or return as-is if already a host"""
        if '://' in url_or_host:
            parsed = urlparse(url_or_host)
            return parsed.netloc.split(':')[0]  # Remove port if present
        else:
            return url_or_host.split(':')[0]  # Remove port if present
    
    def _scan_ports(self, host: str, ports: List[int], max_workers: int = None) -> List[Tuple[int, str]]:
        """Scan multiple ports using threading"""
        max_workers = max_workers or min(self.max_threads, len(ports))
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self._scan_single_port, host, port): port 
                for port in ports
            }
            
            # Collect results
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, service = future.result()
                    if is_open:
                        open_ports.append((port, service))
                except Exception as e:
                    logger.debug(f"Port scan error for {host}:{port}: {e}")
        
        return sorted(open_ports)
    
    def _scan_single_port(self, host: str, port: int) -> Tuple[bool, str]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service = self.common_ports.get(port, 'Unknown')
                return True, service
            else:
                return False, ''
                
        except socket.gaierror:
            # DNS resolution failed
            return False, ''
        except Exception as e:
            logger.debug(f"Port scan error for {host}:{port}: {e}")
            return False, ''
    
    def _calculate_risk_score(self, open_ports: List[Dict[str, Any]]) -> int:
        """Calculate risk score based on open ports"""
        risk_score = 0
        
        for port_info in open_ports:
            port = port_info['port']
            
            # Base score for any open port
            risk_score += 2
            
            # Higher score for dangerous ports
            if port in self.dangerous_ports:
                risk_score += 20
            
            # Specific port risk assessments
            if port == 23:  # Telnet
                risk_score += 30
            elif port == 21:  # FTP
                risk_score += 15
            elif port in [135, 139, 445]:  # Windows services
                risk_score += 25
            elif port in [3306, 5432, 1433, 6379, 27017]:  # Databases
                risk_score += 20
            elif port == 3389:  # RDP
                risk_score += 25
        
        return min(risk_score, 100)  # Cap at 100
    
    def check_specific_vulnerabilities(self, url_or_host: str) -> Dict[str, Any]:
        """Check for specific known vulnerabilities based on open ports"""
        result = {
            'status': 'unknown',
            'host': '',
            'vulnerabilities': [],
            'recommendations': [],
            'risk_score': 0
        }
        
        try:
            host = self._extract_host(url_or_host)
            result['host'] = host
            
            # Check for common vulnerable services
            vulnerable_ports = [21, 23, 135, 139, 445, 1433, 3389]
            open_ports = self._scan_ports(host, vulnerable_ports)
            
            for port, service in open_ports:
                vulnerability_info = self._get_vulnerability_info(port, service)
                if vulnerability_info:
                    result['vulnerabilities'].extend(vulnerability_info['vulnerabilities'])
                    result['recommendations'].extend(vulnerability_info['recommendations'])
                    result['risk_score'] = max(result['risk_score'], vulnerability_info['risk_score'])
            
            if not result['vulnerabilities']:
                result['status'] = 'passed'
            else:
                result['status'] = 'warning' if result['risk_score'] < 70 else 'failed'
                
        except Exception as e:
            logger.error(f"Vulnerability check failed for {url_or_host}: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            
        return result
    
    def _get_vulnerability_info(self, port: int, service: str) -> Dict[str, Any]:
        """Get vulnerability information for specific port/service"""
        vulnerabilities = {
            21: {
                'vulnerabilities': [
                    'FTP service may transmit credentials in plaintext',
                    'Anonymous FTP access may be enabled',
                    'FTP bounce attacks possible'
                ],
                'recommendations': [
                    'Use SFTP or FTPS instead of plain FTP',
                    'Disable anonymous access',
                    'Implement strong authentication'
                ],
                'risk_score': 60
            },
            23: {
                'vulnerabilities': [
                    'Telnet transmits all data including passwords in plaintext',
                    'No encryption protection',
                    'Susceptible to eavesdropping and man-in-the-middle attacks'
                ],
                'recommendations': [
                    'Replace Telnet with SSH',
                    'Disable Telnet service immediately',
                    'Use encrypted alternatives for remote access'
                ],
                'risk_score': 90
            },
            135: {
                'vulnerabilities': [
                    'RPC Endpoint Mapper can reveal system information',
                    'May be exploitable for remote code execution',
                    'Often targeted in worm attacks'
                ],
                'recommendations': [
                    'Block port 135 at firewall',
                    'Disable unnecessary RPC services',
                    'Keep Windows systems updated'
                ],
                'risk_score': 75
            },
            139: {
                'vulnerabilities': [
                    'NetBIOS Session Service may allow null session attacks',
                    'Information disclosure possible',
                    'Can be used for network reconnaissance'
                ],
                'recommendations': [
                    'Disable NetBIOS over TCP/IP',
                    'Block ports 139 and 445 externally',
                    'Use SMB signing'
                ],
                'risk_score': 70
            },
            445: {
                'vulnerabilities': [
                    'SMB service may be vulnerable to various attacks',
                    'EternalBlue and other SMB exploits',
                    'Ransomware propagation vector'
                ],
                'recommendations': [
                    'Keep SMB service updated',
                    'Block port 445 externally',
                    'Enable SMB signing and encryption'
                ],
                'risk_score': 85
            },
            3389: {
                'vulnerabilities': [
                    'RDP may be vulnerable to brute force attacks',
                    'BlueKeep and other RDP vulnerabilities',
                    'Remote code execution possible'
                ],
                'recommendations': [
                    'Use VPN for remote access',
                    'Enable Network Level Authentication',
                    'Limit RDP access by IP',
                    'Use strong passwords and account lockout'
                ],
                'risk_score': 80
            }
        }
        
        return vulnerabilities.get(port, None)