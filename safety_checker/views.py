from rest_framework import status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
import json
import logging

from .safety_engine.main_checker import MainSafetyChecker
from .models import URLSafetyReport, SecurityCheckResult
from authentication.models import UserProfile

logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def check_url(request):
    """URL safety check API endpoint"""
    try:
        data = request.data
        url = data.get('url', '').strip()
        check_type = data.get('check_type', 'quick')  # quick, comprehensive
        
        if not url:
            return Response(
                {'error': 'URL is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Initialize safety checker
        safety_checker = MainSafetyChecker()
        
        # Check if we have a recent cached result
        cached_result = safety_checker.get_cached_result(url, max_age_hours=6)
        
        if cached_result and data.get('use_cache', True):
            # Return cached result
            report = cached_result
            was_cached = True
        else:
            # Perform new check
            if check_type == 'comprehensive':
                report = safety_checker.comprehensive_check(url, request.user)
            else:
                report = safety_checker.quick_check(url, request.user)
            
            was_cached = False
            
            # Update user profile scan count
            try:
                profile = UserProfile.objects.get(user=request.user)
                profile.increment_scan_count()
            except UserProfile.DoesNotExist:
                pass
        
        # Serialize report data
        report_data = {
            'id': str(report.id),
            'url': report.url,
            'safety_level': report.safety_level,
            'safety_score': report.safety_score,
            'summary': report.summary,
            'analyzed_at': report.analyzed_at.isoformat(),
            'analysis_duration': report.analysis_duration,
            'checks_completed': report.checks_completed,
            'checks_failed': report.checks_failed,
            'flags': {
                'has_ssl_issues': report.has_ssl_issues,
                'has_malware': report.has_malware,
                'has_phishing': report.has_phishing,
                'has_suspicious_domain': report.has_suspicious_domain,
                'has_open_ports': report.has_open_ports,
                'has_dns_issues': report.has_dns_issues,
                'is_blacklisted': report.is_blacklisted,
                'has_mixed_content': report.has_mixed_content,
            },
            'was_cached': was_cached
        }
        
        return Response(report_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"URL safety check failed: {e}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def report_details(request, report_id):
    """Get detailed security check results for a report"""
    try:
        report = URLSafetyReport.objects.get(id=report_id, user=request.user)
        
        # Get all check results
        check_results = SecurityCheckResult.objects.filter(report=report)
        
        check_data = []
        for check in check_results:
            check_data.append({
                'id': str(check.id),
                'check_type': check.check_type,
                'status': check.status,
                'risk_score': check.risk_score,
                'execution_time': check.execution_time,
                'details': check.details,
                'error_message': check.error_message,
                'weight': check.weight
            })
        
        report_data = {
            'id': str(report.id),
            'url': report.url,
            'safety_level': report.safety_level,
            'safety_score': report.safety_score,
            'summary': report.summary,
            'analyzed_at': report.analyzed_at.isoformat(),
            'analysis_duration': report.analysis_duration,
            'checks_completed': report.checks_completed,
            'checks_failed': report.checks_failed,
            'flags': {
                'has_ssl_issues': report.has_ssl_issues,
                'has_malware': report.has_malware,
                'has_phishing': report.has_phishing,
                'has_suspicious_domain': report.has_suspicious_domain,
                'has_open_ports': report.has_open_ports,
                'has_dns_issues': report.has_dns_issues,
                'is_blacklisted': report.is_blacklisted,
                'has_mixed_content': report.has_mixed_content,
            },
            'check_results': check_data
        }
        
        return Response(report_data)
        
    except URLSafetyReport.DoesNotExist:
        return Response(
            {'error': 'Report not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Failed to get report details: {e}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_reports(request):
    """Get user's safety reports"""
    try:
        reports = URLSafetyReport.objects.filter(
            user=request.user
        ).order_by('-analyzed_at')
        
        # Pagination
        page = request.GET.get('page', 1)
        per_page = min(int(request.GET.get('per_page', 20)), 100)
        
        paginator = Paginator(reports, per_page)
        page_obj = paginator.get_page(page)
        
        reports_data = []
        for report in page_obj:
            reports_data.append({
                'id': str(report.id),
                'url': report.url,
                'safety_level': report.safety_level,
                'safety_score': report.safety_score,
                'summary': report.summary[:100] + '...' if len(report.summary) > 100 else report.summary,
                'analyzed_at': report.analyzed_at.isoformat(),
                'analysis_duration': report.analysis_duration,
                'checks_completed': report.checks_completed,
                'checks_failed': report.checks_failed
            })
        
        return Response({
            'reports': reports_data,
            'pagination': {
                'page': page_obj.number,
                'per_page': per_page,
                'total_pages': paginator.num_pages,
                'total_count': paginator.count,
                'has_next': page_obj.has_next(),
                'has_previous': page_obj.has_previous()
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to get user reports: {e}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# Template views for minimal UI
@login_required
def reports_page(request):
    """Reports listing page"""
    reports = URLSafetyReport.objects.filter(
        user=request.user
    ).order_by('-analyzed_at')[:20]
    
    return render(request, 'safety_checker/reports.html', {
        'reports': reports
    })

@login_required
def report_detail_page(request, report_id):
    """Report detail page"""
    try:
        report = URLSafetyReport.objects.get(id=report_id, user=request.user)
        check_results = SecurityCheckResult.objects.filter(report=report)
        
        return render(request, 'safety_checker/report_detail.html', {
            'report': report,
            'check_results': check_results
        })
    except URLSafetyReport.DoesNotExist:
        return render(request, 'safety_checker/report_detail.html', {
            'error': 'Report not found'
        })

# AJAX endpoints for minimal UI
@csrf_exempt
@login_required
def ajax_check_url(request):
    """AJAX endpoint for URL checking (for minimal UI)"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url = data.get('url', '').strip()
            check_type = data.get('check_type', 'quick')
            
            if not url:
                return JsonResponse({
                    'error': 'URL is required'
                }, status=400)
            
            # Initialize safety checker
            safety_checker = MainSafetyChecker()
            
            # Perform check
            if check_type == 'comprehensive':
                report = safety_checker.comprehensive_check(url, request.user)
            else:
                report = safety_checker.quick_check(url, request.user)
            
            # Update user profile
            try:
                profile = UserProfile.objects.get(user=request.user)
                profile.increment_scan_count()
            except UserProfile.DoesNotExist:
                pass
            
            # Return simplified response for AJAX
            return JsonResponse({
                'success': True,
                'report_id': str(report.id),
                'url': report.url,
                'safety_level': report.safety_level,
                'safety_score': report.safety_score,
                'summary': report.summary,
                'analysis_duration': report.analysis_duration
            })
            
        except Exception as e:
            logger.error(f"AJAX URL check failed: {e}")
            return JsonResponse({
                'error': 'Failed to check URL'
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)