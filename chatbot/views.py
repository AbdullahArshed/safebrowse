from rest_framework import status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import json
import logging

from .services import ChatbotService
from .models import ChatSession, ChatMessage
from safety_checker.models import URLSafetyReport

logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def chat_message(request):
    """Process chat message API endpoint"""
    try:
        data = request.data
        message_content = data.get('message', '').strip()
        session_id = data.get('session_id')
        
        if not message_content:
            return Response(
                {'error': 'Message content is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Process message using chatbot service
        chatbot_service = ChatbotService()
        result = chatbot_service.process_message(
            user=request.user,
            session_id=session_id,
            message_content=message_content
        )
        
        if result['success']:
            return Response(result, status=status.HTTP_200_OK)
        else:
            return Response(
                {'error': result.get('error', 'Unknown error')},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    except Exception as e:
        logger.error(f"Chat message processing failed: {e}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def chat_history(request, session_id):
    """Get chat history for a session"""
    try:
        chatbot_service = ChatbotService()
        history = chatbot_service.get_chat_history(
            user=request.user,
            session_id=session_id,
            limit=50
        )
        
        return Response({
            'session_id': session_id,
            'messages': history
        })
        
    except Exception as e:
        logger.error(f"Failed to get chat history: {e}")
        return Response(
            {'error': 'Failed to retrieve chat history'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_sessions(request):
    """Get user's chat sessions"""
    try:
        chatbot_service = ChatbotService()
        sessions = chatbot_service.get_user_sessions(
            user=request.user,
            limit=20
        )
        
        return Response({
            'sessions': sessions
        })
        
    except Exception as e:
        logger.error(f"Failed to get user sessions: {e}")
        return Response(
            {'error': 'Failed to retrieve sessions'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def new_session(request):
    """Create new chat session"""
    try:
        title = request.data.get('title', 'New Chat')
        
        session = ChatSession.objects.create(
            user=request.user,
            title=title
        )
        
        return Response({
            'session_id': str(session.id),
            'title': session.title,
            'created_at': session.created_at.isoformat()
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"Failed to create new session: {e}")
        return Response(
            {'error': 'Failed to create session'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_session(request, session_id):
    """Delete chat session"""
    try:
        session = ChatSession.objects.get(id=session_id, user=request.user)
        session.is_active = False
        session.save()
        
        return Response({'message': 'Session deleted successfully'})
        
    except ChatSession.DoesNotExist:
        return Response(
            {'error': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Failed to delete session: {e}")
        return Response(
            {'error': 'Failed to delete session'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# Template views for minimal UI
@login_required
def chat_page(request):
    """Main chat interface page"""
    return render(request, 'chatbot/chat.html')

@login_required
def chat_session_page(request, session_id):
    """Chat page for specific session"""
    try:
        session = ChatSession.objects.get(id=session_id, user=request.user)
        return render(request, 'chatbot/chat.html', {
            'session_id': session_id,
            'session_title': session.title
        })
    except ChatSession.DoesNotExist:
        return render(request, 'chatbot/chat.html', {
            'error': 'Session not found'
        })

# AJAX endpoints for the minimal UI
@csrf_exempt
@login_required
def ajax_send_message(request):
    """AJAX endpoint for sending messages (for minimal UI)"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            message_content = data.get('message', '').strip()
            session_id = data.get('session_id')
            
            if not message_content:
                return JsonResponse({
                    'error': 'Message content is required'
                }, status=400)
            
            # Process message
            chatbot_service = ChatbotService()
            result = chatbot_service.process_message(
                user=request.user,
                session_id=session_id,
                message_content=message_content
            )
            
            return JsonResponse(result)
            
        except Exception as e:
            logger.error(f"AJAX message processing failed: {e}")
            return JsonResponse({
                'error': 'Failed to process message'
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@login_required
def ajax_get_history(request, session_id):
    """AJAX endpoint for getting chat history"""
    try:
        chatbot_service = ChatbotService()
        history = chatbot_service.get_chat_history(
            user=request.user,
            session_id=session_id,
            limit=50
        )
        
        return JsonResponse({
            'session_id': session_id,
            'messages': history
        })
        
    except Exception as e:
        logger.error(f"Failed to get chat history: {e}")
        return JsonResponse({
            'error': 'Failed to retrieve chat history'
        }, status=500)