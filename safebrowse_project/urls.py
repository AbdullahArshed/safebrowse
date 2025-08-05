"""
URL configuration for safebrowse_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.conf import settings
from django.conf.urls.static import static

def home_redirect(request):
    """Redirect home page to chat if authenticated, otherwise to login"""
    if request.user.is_authenticated:
        return redirect('chat')
    return redirect('login')

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Home redirect
    path('', home_redirect, name='home'),
    
    # App URLs
    path('auth/', include('authentication.urls')),
    path('chat/', include('chatbot.urls')),
    path('safety/', include('safety_checker.urls')),
    
    # Direct access to main features
    path('login/', include('authentication.urls')),
    path('register/', include('authentication.urls')),
    path('reports/', include('safety_checker.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)