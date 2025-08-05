from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import UserProfile, APIUsage, LoginAttempt

# Unregister the default User admin
admin.site.unregister(User)

class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'

class UserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,)
    
    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super().get_inline_instances(request, obj)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'organization', 'total_scans', 'scans_this_month', 'is_verified', 'created_at']
    list_filter = ['is_verified', 'default_scan_depth', 'email_notifications', 'created_at']
    search_fields = ['user__username', 'user__email', 'organization']
    readonly_fields = ['created_at', 'updated_at', 'total_scans', 'scans_this_month', 'last_scan_date']
    
    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('Profile Details', {
            'fields': ('phone_number', 'organization', 'bio')
        }),
        ('Preferences', {
            'fields': ('email_notifications', 'default_scan_depth')
        }),
        ('Usage Statistics', {
            'fields': ('total_scans', 'scans_this_month', 'last_scan_date'),
            'classes': ('collapse',)
        }),
        ('Account Status', {
            'fields': ('is_verified', 'verification_token'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )

@admin.register(APIUsage)
class APIUsageAdmin(admin.ModelAdmin):
    list_display = ['user', 'endpoint', 'method', 'status_code', 'success', 'timestamp']
    list_filter = ['success', 'method', 'endpoint', 'timestamp']
    search_fields = ['user__username', 'endpoint', 'ip_address']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        return False  # Prevent manual creation
    
    def has_change_permission(self, request, obj=None):
        return False  # Prevent editing

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['username', 'ip_address', 'success', 'is_suspicious', 'timestamp']
    list_filter = ['success', 'is_suspicious', 'timestamp', 'country']
    search_fields = ['username', 'ip_address']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        return False  # Prevent manual creation
    
    def has_change_permission(self, request, obj=None):
        return False  # Prevent editing

# Re-register UserAdmin
admin.site.register(User, UserAdmin)