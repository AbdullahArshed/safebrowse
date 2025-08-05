from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import logging

from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, UserSerializer
from .models import UserProfile, LoginAttempt

logger = logging.getLogger(__name__)

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'message': 'Registration successful'
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """API login endpoint"""
    serializer = UserLoginSerializer(data=request.data)
    
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        # Log successful login attempt
        LoginAttempt.objects.create(
            username=user.username,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user': UserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'message': 'Login successful'
        })
    
    # Log failed login attempt
    username = request.data.get('username', '')
    if username:
        LoginAttempt.objects.create(
            username=username,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=False,
            failure_reason='Invalid credentials'
        )
    
    return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """API logout endpoint"""
    try:
        refresh_token = request.data.get('refresh')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()
        
        return Response({'message': 'Logout successful'})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        profile, created = UserProfile.objects.get_or_create(user=self.request.user)
        return profile

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_stats_view(request):
    """Get user statistics"""
    try:
        profile = UserProfile.objects.get(user=request.user)
        return Response({
            'total_scans': profile.total_scans,
            'scans_this_month': profile.scans_this_month,
            'last_scan_date': profile.last_scan_date,
            'member_since': request.user.date_joined,
            'is_verified': profile.is_verified
        })
    except UserProfile.DoesNotExist:
        return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)

# Django template views for minimal UI
def login_page(request):
    """Login page template view"""
    if request.user.is_authenticated:
        return redirect('chat')
    
    if request.method == 'POST':
        from django.contrib.auth import authenticate, login
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            messages.success(request, 'Login successful!')
            return redirect('chat')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'authentication/login.html')

def register_page(request):
    """Registration page template view"""
    if request.user.is_authenticated:
        return redirect('chat')
    
    if request.method == 'POST':
        from django.contrib.auth import login
        
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')
        
        # Basic validation
        if password != password_confirm:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'authentication/register.html')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return render(request, 'authentication/register.html')
        
        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            
            # Create profile
            UserProfile.objects.create(user=user)
            
            login(request, user)
            messages.success(request, 'Registration successful!')
            return redirect('chat')
            
        except Exception as e:
            messages.error(request, f'Registration failed: {str(e)}')
    
    return render(request, 'authentication/register.html')

def logout_page(request):
    """Logout view"""
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('login')