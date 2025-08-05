from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

urlpatterns = [
    # API endpoints
    path('api/register/', views.RegisterView.as_view(), name='api_register'),
    path('api/login/', views.login_view, name='api_login'),
    path('api/logout/', views.logout_view, name='api_logout'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/profile/', views.UserProfileView.as_view(), name='api_user_profile'),
    path('api/stats/', views.user_stats_view, name='api_user_stats'),
    
    # Template views
    path('login/', views.login_page, name='login'),
    path('register/', views.register_page, name='register'),
    path('logout/', views.logout_page, name='logout'),
]