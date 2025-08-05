from django.contrib import admin
from .models import (
    URLSafetyReport, SecurityCheckResult, DomainInfo, 
    SSLCertificate, PortScanResult
)

@admin.register(URLSafetyReport)
class URLSafetyReportAdmin(admin.ModelAdmin):
    list_display = [
        'url', 'user', 'safety_level', 'safety_score', 
        'checks_completed', 'checks_failed', 'analyzed_at'
    ]
    list_filter = [
        'safety_level', 'has_malware', 'has_phishing', 'has_ssl_issues', 
        'is_blacklisted', 'analyzed_at'
    ]
    search_fields = ['url', 'user__username', 'summary']
    readonly_fields = ['id', 'analyzed_at']
    date_hierarchy = 'analyzed_at'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('url', 'user', 'analyzed_at')
        }),
        ('Safety Assessment', {
            'fields': ('safety_level', 'safety_score', 'summary')
        }),
        ('Analysis Metadata', {
            'fields': ('analysis_duration', 'checks_completed', 'checks_failed'),
            'classes': ('collapse',)
        }),
        ('Security Flags', {
            'fields': (
                'has_ssl_issues', 'has_malware', 'has_phishing', 
                'has_suspicious_domain', 'has_open_ports', 'has_dns_issues',
                'is_blacklisted', 'has_mixed_content'
            ),
            'classes': ('collapse',)
        })
    )
    
    def has_add_permission(self, request):
        return False  # Reports should only be created through the safety checker

class SecurityCheckResultInline(admin.TabularInline):
    model = SecurityCheckResult
    extra = 0
    readonly_fields = ['check_type', 'status', 'risk_score', 'execution_time', 'created_at']
    
    def has_add_permission(self, request, obj=None):
        return False

@admin.register(SecurityCheckResult)
class SecurityCheckResultAdmin(admin.ModelAdmin):
    list_display = [
        'report', 'check_type', 'status', 'risk_score', 
        'execution_time', 'created_at'
    ]
    list_filter = ['check_type', 'status', 'created_at']
    search_fields = ['report__url', 'report__user__username', 'check_type']
    readonly_fields = ['id', 'created_at']
    
    def has_add_permission(self, request):
        return False

@admin.register(DomainInfo)
class DomainInfoAdmin(admin.ModelAdmin):
    list_display = [
        'domain', 'registrar', 'creation_date', 'expiration_date',
        'is_suspicious', 'reputation_score', 'last_updated'
    ]
    list_filter = ['is_suspicious', 'last_updated', 'cache_expires']
    search_fields = ['domain', 'registrar']
    readonly_fields = ['last_updated']
    date_hierarchy = 'last_updated'
    
    fieldsets = (
        ('Domain Information', {
            'fields': ('domain', 'registrar')
        }),
        ('WHOIS Data', {
            'fields': ('creation_date', 'expiration_date', 'name_servers'),
            'classes': ('collapse',)
        }),
        ('DNS Information', {
            'fields': ('a_records', 'mx_records', 'txt_records', 'spf_record', 'dmarc_record', 'dkim_records'),
            'classes': ('collapse',)
        }),
        ('Reputation', {
            'fields': ('reputation_score', 'is_suspicious', 'blacklist_status')
        }),
        ('Cache Management', {
            'fields': ('last_updated', 'cache_expires'),
            'classes': ('collapse',)
        })
    )

@admin.register(SSLCertificate)
class SSLCertificateAdmin(admin.ModelAdmin):
    list_display = [
        'domain', 'issuer', 'not_after', 'is_valid', 
        'is_expired', 'is_self_signed', 'created_at'
    ]
    list_filter = ['is_valid', 'is_expired', 'is_self_signed', 'created_at']
    search_fields = ['domain', 'issuer', 'subject']
    readonly_fields = ['created_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Certificate Basic Info', {
            'fields': ('domain', 'issuer', 'subject', 'serial_number')
        }),
        ('Validity', {
            'fields': ('not_before', 'not_after', 'is_valid', 'is_expired', 'is_self_signed')
        }),
        ('Technical Details', {
            'fields': ('signature_algorithm', 'key_size', 'is_weak_key'),
            'classes': ('collapse',)
        }),
        ('Extensions', {
            'fields': ('has_san', 'san_domains', 'chain_length', 'is_chain_valid'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        })
    )

class PortScanResultInline(admin.TabularInline):
    model = PortScanResult
    extra = 0
    readonly_fields = ['host', 'port', 'is_open', 'service', 'scanned_at']
    
    def has_add_permission(self, request, obj=None):
        return False

@admin.register(PortScanResult)
class PortScanResultAdmin(admin.ModelAdmin):
    list_display = [
        'report', 'host', 'port', 'is_open', 'service', 
        'is_suspicious', 'risk_level', 'scanned_at'
    ]
    list_filter = ['is_open', 'is_suspicious', 'risk_level', 'scanned_at']
    search_fields = ['report__url', 'host', 'service']
    readonly_fields = ['scanned_at']
    
    def has_add_permission(self, request):
        return False

# Customize admin site
admin.site.site_header = "SafeBrowse Administration"
admin.site.site_title = "SafeBrowse Admin"
admin.site.index_title = "Welcome to SafeBrowse Administration"