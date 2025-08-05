from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid

class URLSafetyReport(models.Model):
    """Main model to store URL safety analysis results"""
    SAFETY_LEVELS = [
        ('safe', 'Safe'),
        ('warning', 'Warning'),
        ('dangerous', 'Dangerous'),
        ('unknown', 'Unknown'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    url = models.URLField(max_length=2048)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='safety_reports')
    
    # Overall safety assessment
    safety_level = models.CharField(max_length=10, choices=SAFETY_LEVELS, default='unknown')
    safety_score = models.FloatField(default=0.0)  # 0-100 score
    summary = models.TextField(blank=True)
    
    # Analysis metadata
    analyzed_at = models.DateTimeField(default=timezone.now)
    analysis_duration = models.FloatField(default=0.0)  # in seconds
    checks_completed = models.PositiveIntegerField(default=0)
    checks_failed = models.PositiveIntegerField(default=0)
    
    # Flags for different types of issues found
    has_ssl_issues = models.BooleanField(default=False)
    has_malware = models.BooleanField(default=False)
    has_phishing = models.BooleanField(default=False)
    has_suspicious_domain = models.BooleanField(default=False)
    has_open_ports = models.BooleanField(default=False)
    has_dns_issues = models.BooleanField(default=False)
    is_blacklisted = models.BooleanField(default=False)
    has_mixed_content = models.BooleanField(default=False)

    class Meta:
        ordering = ['-analyzed_at']
        verbose_name = 'URL Safety Report'
        verbose_name_plural = 'URL Safety Reports'
        indexes = [
            models.Index(fields=['url']),
            models.Index(fields=['user', '-analyzed_at']),
            models.Index(fields=['safety_level']),
        ]

    def __str__(self):
        return f"{self.url} - {self.safety_level}"

class SecurityCheckResult(models.Model):
    """Individual security check results"""
    CHECK_TYPES = [
        ('ssl_check', 'SSL/TLS Check'),
        ('safe_browsing', 'Google Safe Browsing'),
        ('certificate_check', 'Certificate Validation'),
        ('whois_check', 'WHOIS Lookup'),
        ('port_scan', 'Port Scanning'),
        ('dns_check', 'DNS Validation'),
        ('blacklist_check', 'Blacklist Check'),
        ('mixed_content', 'Mixed Content Detection'),
        ('vulnerability_scan', 'Vulnerability Scan'),
    ]
    
    STATUS_CHOICES = [
        ('passed', 'Passed'),
        ('failed', 'Failed'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('skipped', 'Skipped'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(URLSafetyReport, on_delete=models.CASCADE, related_name='check_results')
    check_type = models.CharField(max_length=20, choices=CHECK_TYPES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    
    # Check details
    details = models.JSONField(default=dict)  # Store detailed check results
    error_message = models.TextField(blank=True)
    execution_time = models.FloatField(default=0.0)  # in seconds
    
    # Scoring
    risk_score = models.FloatField(default=0.0)  # 0-100, higher = more risky
    weight = models.FloatField(default=1.0)  # Weight for overall score calculation
    
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['check_type']
        verbose_name = 'Security Check Result'
        verbose_name_plural = 'Security Check Results'
        unique_together = ['report', 'check_type']

    def __str__(self):
        return f"{self.report.url} - {self.get_check_type_display()}: {self.status}"

class DomainInfo(models.Model):
    """Store domain information for caching"""
    domain = models.CharField(max_length=253, unique=True)  # Max domain length
    
    # WHOIS information
    registrar = models.CharField(max_length=200, blank=True)
    creation_date = models.DateTimeField(null=True, blank=True)
    expiration_date = models.DateTimeField(null=True, blank=True)
    name_servers = models.JSONField(default=list)
    
    # DNS information
    a_records = models.JSONField(default=list)
    mx_records = models.JSONField(default=list)
    txt_records = models.JSONField(default=list)
    spf_record = models.TextField(blank=True)
    dmarc_record = models.TextField(blank=True)
    dkim_records = models.JSONField(default=list)
    
    # Reputation data
    reputation_score = models.FloatField(default=0.0)
    is_suspicious = models.BooleanField(default=False)
    blacklist_status = models.JSONField(default=dict)
    
    # Cache metadata
    last_updated = models.DateTimeField(auto_now=True)
    cache_expires = models.DateTimeField()
    
    class Meta:
        verbose_name = 'Domain Information'
        verbose_name_plural = 'Domain Information'
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['last_updated']),
        ]

    def __str__(self):
        return self.domain

class SSLCertificate(models.Model):
    """Store SSL certificate information"""
    domain = models.CharField(max_length=253)
    
    # Certificate details
    issuer = models.CharField(max_length=500)
    subject = models.CharField(max_length=500)
    serial_number = models.CharField(max_length=100)
    signature_algorithm = models.CharField(max_length=100)
    
    # Validity
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    is_valid = models.BooleanField(default=True)
    is_expired = models.BooleanField(default=False)
    is_self_signed = models.BooleanField(default=False)
    
    # Security assessment
    key_size = models.IntegerField(default=0)
    is_weak_key = models.BooleanField(default=False)
    has_san = models.BooleanField(default=False)
    san_domains = models.JSONField(default=list)
    
    # Certificate chain
    chain_length = models.IntegerField(default=0)
    is_chain_valid = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        verbose_name = 'SSL Certificate'
        verbose_name_plural = 'SSL Certificates'
        unique_together = ['domain', 'serial_number']

    def __str__(self):
        return f"{self.domain} - {self.issuer}"

class PortScanResult(models.Model):
    """Store port scanning results"""
    report = models.ForeignKey(URLSafetyReport, on_delete=models.CASCADE, related_name='port_scans')
    host = models.GenericIPAddressField()
    port = models.PositiveIntegerField()
    
    # Port status
    is_open = models.BooleanField(default=False)
    service = models.CharField(max_length=100, blank=True)
    version = models.CharField(max_length=200, blank=True)
    banner = models.TextField(blank=True)
    
    # Risk assessment
    is_suspicious = models.BooleanField(default=False)
    risk_level = models.CharField(
        max_length=10,
        choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')],
        default='low'
    )
    
    scanned_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        verbose_name = 'Port Scan Result'
        verbose_name_plural = 'Port Scan Results'
        unique_together = ['report', 'host', 'port']

    def __str__(self):
        return f"{self.host}:{self.port} - {'Open' if self.is_open else 'Closed'}"