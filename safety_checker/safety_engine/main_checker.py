import asyncio
import logging
from typing import Dict, Any, List
from django.contrib.auth.models import User
from django.utils import timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from .ssl_checker import SSLChecker
from .safe_browsing import GoogleSafeBrowsingChecker
from .whois_checker import WHOISChecker
from .dns_checker import DNSChecker
from .port_scanner import PortScanner
from .blacklist_checker import BlacklistChecker

from ..models import URLSafetyReport, SecurityCheckResult, DomainInfo

logger = logging.getLogger(__name__)

class MainSafetyChecker:
    """
    Main safety checker that orchestrates all security checks
    """
    
    def __init__(self):
        self.ssl_checker = SSLChecker()
        self.safe_browsing_checker = GoogleSafeBrowsingChecker()
        self.whois_checker = WHOISChecker()
        self.dns_checker = DNSChecker()
        self.port_scanner = PortScanner()
        self.blacklist_checker = BlacklistChecker()
        
        # Check configuration
        self.check_modules = {
            'ssl_check': {
                'checker': self.ssl_checker,
                'method': 'check_ssl_certificate',
                'weight': 20,
                'enabled': True
            },
            'safe_browsing': {
                'checker': self.safe_browsing_checker,
                'method': 'check_url_safety',
                'weight': 25,
                'enabled': True
            },
            'certificate_check': {
                'checker': self.ssl_checker,
                'method': 'check_ssl_certificate',
                'weight': 15,
                'enabled': True
            },
            'whois_check': {
                'checker': self.whois_checker,
                'method': 'check_domain_info',
                'weight': 15,
                'enabled': True
            },
            'dns_check': {
                'checker': self.dns_checker,
                'method': 'check_dns_records',
                'weight': 10,
                'enabled': True
            },
            'port_scan': {
                'checker': self.port_scanner,
                'method': 'scan_common_ports',
                'weight': 15,
                'enabled': True
            },
            'blacklist_check': {
                'checker': self.blacklist_checker,
                'method': 'check_domain_blacklist',
                'weight': 20,
                'enabled': True
            },
            'mixed_content': {
                'checker': self.ssl_checker,
                'method': 'check_mixed_content',
                'weight': 5,
                'enabled': True
            }
        }
    
    def check_url_safety(self, url: str, user: User, check_types: List[str] = None) -> URLSafetyReport:
        """
        Perform comprehensive safety check on URL
        """
        start_time = time.time()
        
        # Create safety report
        report = URLSafetyReport.objects.create(
            url=url,
            user=user,
            analyzed_at=timezone.now()
        )
        
        try:
            # Determine which checks to run
            if check_types is None:
                checks_to_run = [name for name, config in self.check_modules.items() if config['enabled']]
            else:
                checks_to_run = [name for name in check_types if name in self.check_modules]
            
            # Run checks in parallel
            check_results = self._run_checks_parallel(url, checks_to_run)
            
            # Process results and create SecurityCheckResult objects
            total_risk_score = 0
            total_weight = 0
            checks_completed = 0
            checks_failed = 0
            
            for check_name, result in check_results.items():
                try:
                    check_config = self.check_modules[check_name]
                    weight = check_config['weight']
                    
                    # Determine status
                    status = result.get('status', 'error')
                    if status == 'error':
                        checks_failed += 1
                    else:
                        checks_completed += 1
                    
                    # Calculate risk score
                    risk_score = result.get('risk_score', 0)
                    total_risk_score += risk_score * weight
                    total_weight += weight
                    
                    # Create SecurityCheckResult
                    SecurityCheckResult.objects.create(
                        report=report,
                        check_type=check_name,
                        status='passed' if status == 'passed' else 'failed' if status == 'failed' else 'warning' if status == 'warning' else 'error',
                        details=result,
                        error_message=result.get('error', ''),
                        execution_time=result.get('execution_time', 0),
                        risk_score=risk_score,
                        weight=weight
                    )
                    
                except Exception as e:
                    logger.error(f"Failed to process result for {check_name}: {e}")
                    checks_failed += 1
            
            # Calculate overall safety score and level
            if total_weight > 0:
                overall_score = total_risk_score / total_weight
            else:
                overall_score = 0
            
            safety_level, safety_flags = self._determine_safety_level(check_results, overall_score)
            
            # Update report
            analysis_duration = time.time() - start_time
            
            report.safety_score = max(0, 100 - overall_score)  # Invert so higher is better
            report.safety_level = safety_level
            report.checks_completed = checks_completed
            report.checks_failed = checks_failed
            report.analysis_duration = analysis_duration
            report.summary = self._generate_summary(check_results, safety_level)
            
            # Set safety flags
            report.has_ssl_issues = safety_flags.get('ssl_issues', False)
            report.has_malware = safety_flags.get('malware', False)
            report.has_phishing = safety_flags.get('phishing', False)
            report.has_suspicious_domain = safety_flags.get('suspicious_domain', False)
            report.has_open_ports = safety_flags.get('open_ports', False)
            report.has_dns_issues = safety_flags.get('dns_issues', False)
            report.is_blacklisted = safety_flags.get('blacklisted', False)
            report.has_mixed_content = safety_flags.get('mixed_content', False)
            
            report.save()
            
        except Exception as e:
            logger.error(f"Safety check failed for {url}: {e}")
            report.summary = f"Analysis failed: {str(e)}"
            report.safety_level = 'unknown'
            report.save()
        
        return report
    
    def _run_checks_parallel(self, url: str, check_names: List[str]) -> Dict[str, Any]:
        """Run security checks in parallel"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            # Submit all check tasks
            future_to_check = {}
            
            for check_name in check_names:
                if check_name in self.check_modules:
                    config = self.check_modules[check_name]
                    checker = config['checker']
                    method_name = config['method']
                    
                    method = getattr(checker, method_name)
                    future = executor.submit(self._run_single_check, method, url, check_name)
                    future_to_check[future] = check_name
            
            # Collect results
            for future in as_completed(future_to_check):
                check_name = future_to_check[future]
                try:
                    result = future.result()
                    results[check_name] = result
                except Exception as e:
                    logger.error(f"Check {check_name} failed: {e}")
                    results[check_name] = {
                        'status': 'error',
                        'error': str(e),
                        'risk_score': 50
                    }
        
        return results
    
    def _run_single_check(self, method, url: str, check_name: str) -> Dict[str, Any]:
        """Run a single security check with timing"""
        start_time = time.time()
        try:
            result = method(url)
            result['execution_time'] = time.time() - start_time
            return result
        except Exception as e:
            logger.error(f"Check {check_name} failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'risk_score': 50,
                'execution_time': time.time() - start_time
            }
    
    def _determine_safety_level(self, check_results: Dict[str, Any], overall_score: float) -> tuple:
        """Determine overall safety level and flags"""
        safety_flags = {
            'ssl_issues': False,
            'malware': False,
            'phishing': False,
            'suspicious_domain': False,
            'open_ports': False,
            'dns_issues': False,
            'blacklisted': False,
            'mixed_content': False
        }
        
        # Check specific conditions
        for check_name, result in check_results.items():
            if check_name == 'ssl_check' and result.get('risk_score', 0) > 30:
                safety_flags['ssl_issues'] = True
            
            elif check_name == 'safe_browsing':
                if not result.get('is_safe', True):
                    threat_types = result.get('threat_types', [])
                    if 'MALWARE' in threat_types:
                        safety_flags['malware'] = True
                    if 'SOCIAL_ENGINEERING' in threat_types:
                        safety_flags['phishing'] = True
            
            elif check_name == 'whois_check' and result.get('is_suspicious', False):
                safety_flags['suspicious_domain'] = True
            
            elif check_name == 'port_scan':
                dangerous_ports = result.get('dangerous_ports', [])
                if dangerous_ports:
                    safety_flags['open_ports'] = True
            
            elif check_name == 'dns_check' and result.get('risk_score', 0) > 20:
                safety_flags['dns_issues'] = True
            
            elif check_name == 'blacklist_check' and result.get('is_blacklisted', False):
                safety_flags['blacklisted'] = True
            
            elif check_name == 'mixed_content' and result.get('has_mixed_content', False):
                safety_flags['mixed_content'] = True
        
        # Determine safety level
        if safety_flags['malware'] or safety_flags['phishing'] or safety_flags['blacklisted']:
            safety_level = 'dangerous'
        elif overall_score > 60 or any([
            safety_flags['ssl_issues'],
            safety_flags['suspicious_domain'],
            safety_flags['open_ports']
        ]):
            safety_level = 'warning'
        elif overall_score > 30:
            safety_level = 'warning'
        else:
            safety_level = 'safe'
        
        return safety_level, safety_flags
    
    def _generate_summary(self, check_results: Dict[str, Any], safety_level: str) -> str:
        """Generate human-readable summary"""
        issues = []
        positives = []
        
        for check_name, result in check_results.items():
            status = result.get('status', 'error')
            risk_score = result.get('risk_score', 0)
            
            if status == 'error':
                issues.append(f"{check_name.replace('_', ' ').title()} check failed")
            elif status == 'failed' or risk_score > 50:
                issues.append(f"{check_name.replace('_', ' ').title()} detected security issues")
            elif status == 'warning' or risk_score > 20:
                issues.append(f"{check_name.replace('_', ' ').title()} found minor concerns")
            elif status == 'passed':
                positives.append(f"{check_name.replace('_', ' ').title()} passed")
        
        if safety_level == 'dangerous':
            summary = "⚠️ DANGEROUS: This URL poses significant security risks. "
        elif safety_level == 'warning':
            summary = "⚠️ WARNING: This URL has some security concerns. "
        elif safety_level == 'safe':
            summary = "✅ SAFE: This URL appears to be safe. "
        else:
            summary = "❓ UNKNOWN: Unable to determine safety level. "
        
        if issues:
            summary += "Issues found: " + ", ".join(issues[:3])
            if len(issues) > 3:
                summary += f" and {len(issues) - 3} more"
        
        if positives and len(positives) > len(issues):
            summary += ". Positive checks: " + ", ".join(positives[:2])
        
        return summary
    
    def quick_check(self, url: str, user: User) -> URLSafetyReport:
        """Perform quick safety check with essential checks only"""
        essential_checks = ['safe_browsing', 'ssl_check', 'blacklist_check']
        return self.check_url_safety(url, user, essential_checks)
    
    def comprehensive_check(self, url: str, user: User) -> URLSafetyReport:
        """Perform comprehensive safety check with all available checks"""
        return self.check_url_safety(url, user)
    
    def get_cached_result(self, url: str, max_age_hours: int = 24) -> URLSafetyReport:
        """Get cached result if available and not too old"""
        try:
            from django.utils import timezone
            from datetime import timedelta
            
            cutoff_time = timezone.now() - timedelta(hours=max_age_hours)
            
            return URLSafetyReport.objects.filter(
                url=url,
                analyzed_at__gte=cutoff_time
            ).order_by('-analyzed_at').first()
            
        except Exception as e:
            logger.error(f"Failed to get cached result: {e}")
            return None