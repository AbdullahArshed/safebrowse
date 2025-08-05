from django.contrib import admin
from .models import ChatSession, ChatMessage, BotIntent, ConversationContext

@admin.register(ChatSession)
class ChatSessionAdmin(admin.ModelAdmin):
    list_display = ['title', 'user', 'is_active', 'created_at', 'updated_at', 'message_count']
    list_filter = ['is_active', 'created_at', 'updated_at']
    search_fields = ['title', 'user__username', 'user__email']
    readonly_fields = ['id', 'created_at', 'updated_at']
    date_hierarchy = 'created_at'
    
    def message_count(self, obj):
        return obj.messages.count()
    message_count.short_description = 'Messages'

@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ['session', 'message_type', 'content_preview', 'url_checked', 'timestamp']
    list_filter = ['message_type', 'timestamp']
    search_fields = ['session__title', 'session__user__username', 'content', 'url_checked']
    readonly_fields = ['id', 'timestamp']
    date_hierarchy = 'timestamp'
    
    def content_preview(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    content_preview.short_description = 'Content'
    
    def has_add_permission(self, request):
        return False  # Prevent manual creation through admin

@admin.register(BotIntent)
class BotIntentAdmin(admin.ModelAdmin):
    list_display = ['name', 'description', 'is_active', 'patterns_count', 'responses_count', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'description', 'is_active')
        }),
        ('Patterns & Responses', {
            'fields': ('patterns', 'responses'),
            'description': 'Enter patterns and responses as JSON arrays'
        }),
        ('Metadata', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        })
    )
    
    def patterns_count(self, obj):
        return len(obj.patterns) if obj.patterns else 0
    patterns_count.short_description = 'Patterns'
    
    def responses_count(self, obj):
        return len(obj.responses) if obj.responses else 0
    responses_count.short_description = 'Responses'

@admin.register(ConversationContext)
class ConversationContextAdmin(admin.ModelAdmin):
    list_display = ['session', 'current_intent', 'last_updated']
    list_filter = ['current_intent', 'last_updated']
    search_fields = ['session__title', 'session__user__username', 'current_intent']
    readonly_fields = ['last_updated']
    
    def has_add_permission(self, request):
        return False  # Prevent manual creation