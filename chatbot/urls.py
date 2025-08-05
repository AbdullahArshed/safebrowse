from django.urls import path
from . import views

urlpatterns = [
    # API endpoints
    path('api/message/', views.chat_message, name='api_chat_message'),
    path('api/history/<uuid:session_id>/', views.chat_history, name='api_chat_history'),
    path('api/sessions/', views.user_sessions, name='api_user_sessions'),
    path('api/sessions/new/', views.new_session, name='api_new_session'),
    path('api/sessions/<uuid:session_id>/delete/', views.delete_session, name='api_delete_session'),
    
    # Template views
    path('', views.chat_page, name='chat'),
    path('session/<uuid:session_id>/', views.chat_session_page, name='chat_session'),
    
    # AJAX endpoints for minimal UI
    path('ajax/send-message/', views.ajax_send_message, name='ajax_send_message'),
    path('ajax/history/<uuid:session_id>/', views.ajax_get_history, name='ajax_get_history'),
]