from django.urls import path
from . import views

urlpatterns = [
    # API endpoints
    path('api/check/', views.check_url, name='api_check_url'),
    path('api/reports/<uuid:report_id>/', views.report_details, name='api_report_details'),
    path('api/reports/', views.user_reports, name='api_user_reports'),
    
    # Template views
    path('reports/', views.reports_page, name='reports'),
    path('reports/<uuid:report_id>/', views.report_detail_page, name='report_detail'),
    
    # AJAX endpoints for minimal UI
    path('ajax/check/', views.ajax_check_url, name='ajax_check_url'),
]