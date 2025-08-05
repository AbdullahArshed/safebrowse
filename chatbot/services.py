import openai
import logging
from typing import Dict, Any, List, Optional
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
import re
import json

from .models import ChatSession, ChatMessage, BotIntent, ConversationContext
from safety_checker.safety_engine.main_checker import MainSafetyChecker

logger = logging.getLogger(__name__)

class ChatbotService:
    """
    Main chatbot service using OpenAI API for natural language processing
    """
    
    def __init__(self):
        openai.api_key = settings.OPENAI_API_KEY
        self.safety_checker = MainSafetyChecker()
        self.max_tokens = 150
        self.temperature = 0.7
        
        # Initialize intents
        self._initialize_intents()
    
    def _initialize_intents(self):
        """Initialize bot intents if they don't exist"""
        try:
            intents_data = [
                {
                    'name': 'greeting',
                    'description': 'User greets the bot',
                    'patterns': ['hello', 'hi', 'hey', 'good morning', 'good afternoon'],
                    'responses': [
                        "Hello! I'm SafeBrowse Bot. I can help you check URLs for safety. Just share a URL and I'll analyze it for you!",
                        "Hi there! I'm here to help you check website safety. Send me a URL to get started!",
                        "Hey! I can help you determine if a website is safe to visit. What URL would you like me to check?"
                    ]
                },
                {
                    'name': 'url_check_request',
                    'description': 'User wants to check a URL',
                    'patterns': ['check', 'analyze', 'scan', 'is safe', 'url', 'website', 'link'],
                    'responses': [
                        "I'll check that URL for you right away!",
                        "Let me analyze that website for potential security issues.",
                        "Running a comprehensive safety check on that URL..."
                    ]
                },
                {
                    'name': 'help',
                    'description': 'User asks for help',
                    'patterns': ['help', 'what can you do', 'commands', 'how to use'],
                    'responses': [
                        "I can help you check URLs for safety! Here's what I can do:\n• Analyze websites for malware and phishing\n• Check SSL certificates\n• Verify domain reputation\n• Scan for open ports\n• Check DNS configuration\n\nJust send me a URL and I'll do the rest!",
                        "I'm a URL safety checker! Send me any website URL and I'll analyze it for:\n✓ Malware detection\n✓ Phishing attempts\n✓ SSL/TLS security\n✓ Domain reputation\n✓ Network security\n\nTry sending me a URL to check!"
                    ]
                },
                {
                    'name': 'thanks',
                    'description': 'User thanks the bot',
                    'patterns': ['thank', 'thanks', 'appreciate', 'great job'],
                    'responses': [
                        "You're welcome! Feel free to check more URLs anytime.",
                        "Happy to help! Stay safe online!",
                        "Glad I could help! Send me another URL if you need it checked."
                    ]
                }
            ]
            
            for intent_data in intents_data:
                intent, created = BotIntent.objects.get_or_create(
                    name=intent_data['name'],
                    defaults={
                        'description': intent_data['description'],
                        'patterns': intent_data['patterns'],
                        'responses': intent_data['responses']
                    }
                )
                if created:
                    logger.info(f"Created intent: {intent.name}")
                    
        except Exception as e:
            logger.error(f"Failed to initialize intents: {e}")
    
    def process_message(self, user: User, session_id: str, message_content: str) -> Dict[str, Any]:
        """
        Process user message and generate appropriate response
        """
        try:
            # Get or create chat session
            session = self._get_or_create_session(user, session_id)
            
            # Save user message
            user_message = ChatMessage.objects.create(
                session=session,
                message_type='user',
                content=message_content,
                timestamp=timezone.now()
            )
            
            # Detect intent and generate response
            intent_result = self._detect_intent(message_content)
            
            # Check if message contains URL
            urls = self._extract_urls(message_content)
            
            if urls:
                # Process URL safety check
                response = self._process_url_check(session, urls[0])
            else:
                # Generate conversational response
                response = self._generate_response(session, message_content, intent_result)
            
            # Save bot response
            bot_message = ChatMessage.objects.create(
                session=session,
                message_type='bot',
                content=response['content'],
                metadata=response.get('metadata', {}),
                timestamp=timezone.now()
            )
            
            # Update session
            session.updated_at = timezone.now()
            session.save()
            
            return {
                'success': True,
                'session_id': str(session.id),
                'user_message': {
                    'id': str(user_message.id),
                    'content': user_message.content,
                    'timestamp': user_message.timestamp.isoformat()
                },
                'bot_response': {
                    'id': str(bot_message.id),
                    'content': bot_message.content,
                    'metadata': bot_message.metadata,
                    'timestamp': bot_message.timestamp.isoformat()
                },
                'detected_urls': urls,
                'intent': intent_result['intent']
            }
            
        except Exception as e:
            logger.error(f"Failed to process message: {e}")
            return {
                'success': False,
                'error': str(e),
                'bot_response': {
                    'content': "I'm sorry, I encountered an error processing your message. Please try again.",
                    'metadata': {'error': True}
                }
            }
    
    def _get_or_create_session(self, user: User, session_id: str = None) -> ChatSession:
        """Get existing session or create new one"""
        if session_id:
            try:
                return ChatSession.objects.get(id=session_id, user=user)
            except ChatSession.DoesNotExist:
                pass
        
        # Create new session
        return ChatSession.objects.create(
            user=user,
            title='New Chat',
            created_at=timezone.now()
        )
    
    def _detect_intent(self, message: str) -> Dict[str, Any]:
        """Detect user intent from message"""
        message_lower = message.lower()
        
        # Check against predefined patterns
        intents = BotIntent.objects.filter(is_active=True)
        
        for intent in intents:
            for pattern in intent.patterns:
                if pattern.lower() in message_lower:
                    return {
                        'intent': intent.name,
                        'confidence': 0.8,
                        'intent_obj': intent
                    }
        
        # Use OpenAI for intent detection if no pattern match
        try:
            intent_result = self._detect_intent_with_openai(message)
            return intent_result
        except Exception as e:
            logger.error(f"OpenAI intent detection failed: {e}")
            return {
                'intent': 'unknown',
                'confidence': 0.0,
                'intent_obj': None
            }
    
    def _detect_intent_with_openai(self, message: str) -> Dict[str, Any]:
        """Use OpenAI to detect intent"""
        try:
            response = openai.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {
                        "role": "system",
                        "content": """You are an intent classifier for a URL safety checker chatbot. 
                        Classify the user's intent into one of these categories:
                        - greeting: User is greeting or starting conversation
                        - url_check_request: User wants to check a URL for safety
                        - help: User is asking for help or information
                        - thanks: User is thanking the bot
                        - question: User is asking a general question
                        - unknown: Intent is unclear
                        
                        Respond with just the intent name."""
                    },
                    {
                        "role": "user",
                        "content": message
                    }
                ],
                max_tokens=10,
                temperature=0.3
            )
            
            intent = response.choices[0].message.content.strip().lower()
            
            return {
                'intent': intent,
                'confidence': 0.7,
                'intent_obj': None
            }
            
        except Exception as e:
            logger.error(f"OpenAI intent detection error: {e}")
            raise
    
    def _extract_urls(self, message: str) -> List[str]:
        """Extract URLs from message"""
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        
        urls = url_pattern.findall(message)
        
        # Also look for domain-only patterns
        domain_pattern = re.compile(
            r'(?:^|\s)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\s|$)'
        )
        
        domains = domain_pattern.findall(message)
        for domain in domains:
            if not domain.startswith('http'):
                urls.append(f'https://{domain.strip()}')
        
        return list(set(urls))  # Remove duplicates
    
    def _process_url_check(self, session: ChatSession, url: str) -> Dict[str, Any]:
        """Process URL safety check request"""
        try:
            # Check if we have a recent result for this URL
            cached_result = self.safety_checker.get_cached_result(url, max_age_hours=6)
            
            if cached_result:
                report = cached_result
                response_text = f"I found a recent analysis for {url}:\n\n{self._format_safety_report(report)}"
            else:
                # Perform new safety check
                response_text = f"🔍 Analyzing {url} for security threats...\n\nThis may take a moment while I check multiple security aspects."
                
                # Run safety check
                report = self.safety_checker.quick_check(url, session.user)
                
                # Format response
                response_text = f"✅ Analysis complete for {url}:\n\n{self._format_safety_report(report)}"
            
            return {
                'content': response_text,
                'metadata': {
                    'url_checked': url,
                    'safety_report_id': str(report.id),
                    'safety_level': report.safety_level,
                    'safety_score': report.safety_score
                }
            }
            
        except Exception as e:
            logger.error(f"URL check failed: {e}")
            return {
                'content': f"I encountered an error while checking {url}. Please make sure the URL is valid and try again.",
                'metadata': {
                    'error': True,
                    'url_checked': url
                }
            }
    
    def _format_safety_report(self, report) -> str:
        """Format safety report for chat display"""
        # Safety level emoji and text
        level_display = {
            'safe': '🟢 SAFE',
            'warning': '🟡 WARNING',
            'dangerous': '🔴 DANGEROUS',
            'unknown': '⚪ UNKNOWN'
        }
        
        safety_text = level_display.get(report.safety_level, '⚪ UNKNOWN')
        score_text = f"Safety Score: {report.safety_score:.0f}/100"
        
        response = f"{safety_text}\n{score_text}\n"
        
        if report.summary:
            response += f"\n📋 Summary: {report.summary}\n"
        
        # Add specific findings
        findings = []
        if report.has_malware:
            findings.append("🦠 Malware detected")
        if report.has_phishing:
            findings.append("🎣 Phishing attempt detected")
        if report.has_ssl_issues:
            findings.append("🔒 SSL/TLS issues found")
        if report.has_suspicious_domain:
            findings.append("🔍 Suspicious domain characteristics")
        if report.has_open_ports:
            findings.append("🚪 Potentially dangerous open ports")
        if report.is_blacklisted:
            findings.append("⚫ Domain is blacklisted")
        if report.has_mixed_content:
            findings.append("⚠️ Mixed content detected")
        
        if findings:
            response += "\n🚨 Issues Found:\n" + "\n".join(f"• {finding}" for finding in findings)
        
        # Add recommendations
        if report.safety_level == 'dangerous':
            response += "\n\n❌ Recommendation: DO NOT visit this website. It poses significant security risks."
        elif report.safety_level == 'warning':
            response += "\n\n⚠️ Recommendation: Use caution. This website has some security concerns."
        elif report.safety_level == 'safe':
            response += "\n\n✅ Recommendation: This website appears to be safe to visit."
        
        response += f"\n\n📊 Analysis completed in {report.analysis_duration:.1f} seconds"
        response += f"\n🔍 Checks completed: {report.checks_completed}"
        
        if report.checks_failed > 0:
            response += f" | Failed: {report.checks_failed}"
        
        return response
    
    def _generate_response(self, session: ChatSession, message: str, intent_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate conversational response"""
        intent = intent_result.get('intent', 'unknown')
        intent_obj = intent_result.get('intent_obj')
        
        # Use predefined responses if available
        if intent_obj and intent_obj.responses:
            import random
            response_text = random.choice(intent_obj.responses)
        else:
            # Use OpenAI for dynamic response
            try:
                response_text = self._generate_openai_response(session, message, intent)
            except Exception as e:
                logger.error(f"OpenAI response generation failed: {e}")
                response_text = "I understand you're trying to communicate with me. I'm here to help you check URLs for safety. Just share a URL and I'll analyze it for you!"
        
        return {
            'content': response_text,
            'metadata': {
                'intent': intent,
                'generated_by': 'pattern' if intent_obj else 'openai'
            }
        }
    
    def _generate_openai_response(self, session: ChatSession, message: str, intent: str) -> str:
        """Generate response using OpenAI"""
        try:
            # Get recent conversation context
            recent_messages = ChatMessage.objects.filter(
                session=session
            ).order_by('-timestamp')[:6]
            
            conversation_history = []
            for msg in reversed(recent_messages):
                role = "user" if msg.message_type == "user" else "assistant"
                conversation_history.append({
                    "role": role,
                    "content": msg.content
                })
            
            system_prompt = """You are SafeBrowse Bot, a helpful assistant that specializes in URL safety checking. 
            Your main function is to help users check websites for security threats including malware, phishing, SSL issues, and more.
            
            Keep responses concise and friendly. If users ask about URL checking, encourage them to share a URL.
            If they share a URL, acknowledge that you'll check it (the URL checking is handled separately).
            
            Stay focused on your role as a security-focused chatbot."""
            
            messages = [{"role": "system", "content": system_prompt}]
            messages.extend(conversation_history[-4:])  # Last 4 messages for context
            messages.append({"role": "user", "content": message})
            
            response = openai.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"OpenAI response generation error: {e}")
            raise
    
    def get_chat_history(self, user: User, session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get chat history for a session"""
        try:
            session = ChatSession.objects.get(id=session_id, user=user)
            messages = ChatMessage.objects.filter(
                session=session
            ).order_by('timestamp')[:limit]
            
            return [
                {
                    'id': str(msg.id),
                    'type': msg.message_type,
                    'content': msg.content,
                    'timestamp': msg.timestamp.isoformat(),
                    'metadata': msg.metadata
                }
                for msg in messages
            ]
            
        except ChatSession.DoesNotExist:
            return []
        except Exception as e:
            logger.error(f"Failed to get chat history: {e}")
            return []
    
    def get_user_sessions(self, user: User, limit: int = 10) -> List[Dict[str, Any]]:
        """Get user's chat sessions"""
        try:
            sessions = ChatSession.objects.filter(
                user=user,
                is_active=True
            ).order_by('-updated_at')[:limit]
            
            return [
                {
                    'id': str(session.id),
                    'title': session.title,
                    'created_at': session.created_at.isoformat(),
                    'updated_at': session.updated_at.isoformat(),
                    'message_count': session.messages.count()
                }
                for session in sessions
            ]
            
        except Exception as e:
            logger.error(f"Failed to get user sessions: {e}")
            return []