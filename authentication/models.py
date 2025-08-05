from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class UserProfile(models.Model):
    """Extended user profile with additional information"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Profile information
    phone_number = models.CharField(max_length=20, blank=True)
    organization = models.CharField(max_length=200, blank=True)
    bio = models.TextField(max_length=500, blank=True)
    
    # Preferences
    email_notifications = models.BooleanField(default=True)
    default_scan_depth = models.CharField(
        max_length=15,
        choices=[('basic', 'Basic'), ('standard', 'Standard'), ('comprehensive', 'Comprehensive')],
        default='standard'
    )
    
    # Usage statistics
    total_scans = models.PositiveIntegerField(default=0)
    scans_this_month = models.PositiveIntegerField(default=0)
    last_scan_date = models.DateTimeField(null=True, blank=True)
    
    # Account status
    is_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'

    def __str__(self):
        return f"{self.user.username}'s Profile"

    def increment_scan_count(self):
        """Increment scan counters"""
        self.total_scans += 1
        self.scans_this_month += 1
        self.last_scan_date = timezone.now()
        self.save()

class APIUsage(models.Model):
    """Track API usage for rate limiting and billing"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_usage')
    
    # Usage tracking
    endpoint = models.CharField(max_length=100)
    method = models.CharField(max_length=10)
    timestamp = models.DateTimeField(default=timezone.now)
    
    # Request details
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    request_size = models.PositiveIntegerField(default=0)  # in bytes
    response_size = models.PositiveIntegerField(default=0)  # in bytes
    response_time = models.FloatField(default=0.0)  # in seconds
    
    # Status
    status_code = models.PositiveIntegerField()
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        verbose_name = 'API Usage'
        verbose_name_plural = 'API Usage Records'
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['endpoint', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.endpoint} - {self.timestamp}"

class LoginAttempt(models.Model):
    """Track login attempts for security monitoring"""
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # Attempt details
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(default=timezone.now)
    failure_reason = models.CharField(max_length=100, blank=True)
    
    # Security flags
    is_suspicious = models.BooleanField(default=False)
    country = models.CharField(max_length=2, blank=True)  # Country code
    
    class Meta:
        verbose_name = 'Login Attempt'
        verbose_name_plural = 'Login Attempts'
        indexes = [
            models.Index(fields=['username', '-timestamp']),
            models.Index(fields=['ip_address', '-timestamp']),
        ]

    def __str__(self):
        status = "Success" if self.success else "Failed"
        return f"{self.username} - {status} - {self.timestamp}"