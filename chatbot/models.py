from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid

class ChatSession(models.Model):
    """Model to represent a chat session between user and bot"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='chat_sessions')
    title = models.CharField(max_length=200, default='New Chat')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-updated_at']
        verbose_name = 'Chat Session'
        verbose_name_plural = 'Chat Sessions'

    def __str__(self):
        return f"{self.user.username} - {self.title}"

class ChatMessage(models.Model):
    """Model to store individual chat messages"""
    MESSAGE_TYPES = [
        ('user', 'User Message'),
        ('bot', 'Bot Message'),
        ('system', 'System Message'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(ChatSession, on_delete=models.CASCADE, related_name='messages')
    message_type = models.CharField(max_length=10, choices=MESSAGE_TYPES, default='user')
    content = models.TextField()
    metadata = models.JSONField(default=dict, blank=True)  # Store additional data like URL checks
    timestamp = models.DateTimeField(default=timezone.now)
    
    # For URL safety check results
    url_checked = models.URLField(blank=True, null=True)
    safety_report = models.ForeignKey(
        'safety_checker.URLSafetyReport', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='chat_messages'
    )

    class Meta:
        ordering = ['timestamp']
        verbose_name = 'Chat Message'
        verbose_name_plural = 'Chat Messages'

    def __str__(self):
        return f"{self.message_type}: {self.content[:50]}..."

class BotIntent(models.Model):
    """Model to store bot intents and responses"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    patterns = models.JSONField(default=list)  # List of patterns that trigger this intent
    responses = models.JSONField(default=list)  # List of possible responses
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return self.name

class ConversationContext(models.Model):
    """Model to maintain conversation context"""
    session = models.OneToOneField(ChatSession, on_delete=models.CASCADE, related_name='context')
    current_intent = models.CharField(max_length=100, blank=True)
    context_data = models.JSONField(default=dict)  # Store conversation state
    last_updated = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Context for {self.session.title}"