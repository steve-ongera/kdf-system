"""
KDF Authentication Views with Role-Based Dashboard Routing
File: sentinel/views.py
"""

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
from django.db.models import Count, Q, Sum
from datetime import timedelta, datetime
import random
import pyotp
from decimal import Decimal
from django.db.models import Count


from .models import (
    KDFUser, TwoFactorAuth, LoginAttempt, Mission, MissionAssignment,
    ThreatIntelligence, Equipment, SupplyChain, Incident, AuditLog
)
from .utils import send_otp_sms, send_otp_email, get_client_ip, get_user_agent


# ==================== AUTHENTICATION VIEWS ====================

def login_view(request):
    """Handle user login with optional 2FA based on DEBUG setting"""
    
    # Redirect if already authenticated
    if request.user.is_authenticated:
        return redirect('dashboard_router')
    
    if request.method == 'POST':
        service_number = request.POST.get('service_number', '').strip().upper()
        password = request.POST.get('password', '')
        
        # Get client information
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Authenticate user
        user = authenticate(request, service_number=service_number, password=password)
        
        if user is not None:
            # Check if account is locked
            if user.is_account_locked():
                LoginAttempt.objects.create(
                    user=user,
                    service_number=service_number,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    successful=False,
                    failure_reason='Account locked'
                )
                messages.error(request, f'Account locked until {user.account_locked_until.strftime("%H:%M")}. Please try again later.')
                return render(request, 'sentinel/login.html')
            
            # Check if user is active
            if not user.is_active:
                LoginAttempt.objects.create(
                    user=user,
                    service_number=service_number,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    successful=False,
                    failure_reason='Account inactive'
                )
                messages.error(request, 'Your account is inactive. Contact your commanding officer.')
                return render(request, 'sentinel/login.html')
            
            # Reset failed attempts on successful authentication
            user.failed_login_attempts = 0
            user.last_login_ip = ip_address
            user.save()
            
            # 2FA Logic based on DEBUG setting
            if not settings.DEBUG and user.is_two_factor_enabled:
                # Production: Require 2FA
                request.session['pre_2fa_user_id'] = str(user.id)
                request.session['pre_2fa_ip'] = ip_address
                
                # Generate and send OTP
                otp_code = str(random.randint(100000, 999999))
                expires_at = timezone.now() + timedelta(minutes=10)
                
                # Create OTP record
                TwoFactorAuth.objects.create(
                    user=user,
                    code=otp_code,
                    method='SMS',  # Default to SMS
                    expires_at=expires_at,
                    ip_address=ip_address
                )
                
                # Send OTP via SMS
                send_otp_sms(user.phone_number, otp_code)
                
                messages.success(request, f'OTP sent to {user.phone_number[-4:].rjust(10, "*")}')
                return redirect('verify_otp')
            else:
                # Development: Skip 2FA and login directly
                login(request, user)
                
                # Log successful login
                LoginAttempt.objects.create(
                    user=user,
                    service_number=service_number,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    successful=True
                )
                
                # Audit log
                AuditLog.objects.create(
                    user=user,
                    action='LOGIN',
                    model_name='KDFUser',
                    object_id=str(user.id),
                    changes={'login_time': timezone.now().isoformat()},
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                messages.success(request, f'Welcome back, {user.rank} {user.last_name}!')
                return redirect('dashboard_router')
        else:
            # Failed login attempt
            try:
                user_obj = KDFUser.objects.get(service_number=service_number)
                user_obj.failed_login_attempts += 1
                
                # Lock account after 5 failed attempts
                if user_obj.failed_login_attempts >= 5:
                    user_obj.account_locked_until = timezone.now() + timedelta(minutes=30)
                    user_obj.save()
                    
                    LoginAttempt.objects.create(
                        user=user_obj,
                        service_number=service_number,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        successful=False,
                        failure_reason='Account locked after 5 failed attempts'
                    )
                    
                    messages.error(request, 'Account locked for 30 minutes due to multiple failed login attempts.')
                else:
                    user_obj.save()
                    remaining = 5 - user_obj.failed_login_attempts
                    
                    LoginAttempt.objects.create(
                        user=user_obj,
                        service_number=service_number,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        successful=False,
                        failure_reason='Invalid password'
                    )
                    
                    messages.error(request, f'Invalid credentials. {remaining} attempts remaining.')
            except KDFUser.DoesNotExist:
                # User doesn't exist
                LoginAttempt.objects.create(
                    service_number=service_number,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    successful=False,
                    failure_reason='Invalid service number'
                )
                messages.error(request, 'Invalid service number or password.')
    
    return render(request, 'sentinel/login.html')


def verify_otp_view(request):
    """Verify OTP for 2FA"""
    
    # Check if user has pre-authenticated
    if 'pre_2fa_user_id' not in request.session:
        messages.error(request, 'Session expired. Please login again.')
        return redirect('login')
    
    user_id = request.session.get('pre_2fa_user_id')
    
    try:
        user = KDFUser.objects.get(id=user_id)
    except KDFUser.DoesNotExist:
        messages.error(request, 'Invalid session. Please login again.')
        return redirect('login')
    
    if request.method == 'POST':
        otp_code = request.POST.get('otp_code', '').strip()
        ip_address = get_client_ip(request)
        
        # Verify OTP
        try:
            otp_record = TwoFactorAuth.objects.filter(
                user=user,
                code=otp_code,
                is_used=False
            ).latest('created_at')
            
            if otp_record.is_valid():
                # Mark OTP as used
                otp_record.is_used = True
                otp_record.save()
                
                # Login user
                login(request, user)
                
                # Clear session data
                del request.session['pre_2fa_user_id']
                if 'pre_2fa_ip' in request.session:
                    del request.session['pre_2fa_ip']
                
                # Log successful login
                LoginAttempt.objects.create(
                    user=user,
                    service_number=user.service_number,
                    ip_address=ip_address,
                    user_agent=get_user_agent(request),
                    successful=True
                )
                
                # Audit log
                AuditLog.objects.create(
                    user=user,
                    action='LOGIN',
                    model_name='KDFUser',
                    object_id=str(user.id),
                    changes={'login_time': timezone.now().isoformat(), '2fa': True},
                    ip_address=ip_address,
                    user_agent=get_user_agent(request)
                )
                
                messages.success(request, f'Welcome back, {user.rank} {user.last_name}!')
                return redirect('dashboard_router')
            else:
                messages.error(request, 'OTP has expired. Please request a new one.')
        except TwoFactorAuth.DoesNotExist:
            messages.error(request, 'Invalid OTP code.')
    
    return render(request, 'sentinel/verify_otp.html', {'user': user})


def resend_otp_view(request):
    """Resend OTP to user"""
    
    if 'pre_2fa_user_id' not in request.session:
        messages.error(request, 'Session expired. Please login again.')
        return redirect('login')
    
    user_id = request.session.get('pre_2fa_user_id')
    
    try:
        user = KDFUser.objects.get(id=user_id)
        ip_address = get_client_ip(request)
        
        # Generate new OTP
        otp_code = str(random.randint(100000, 999999))
        expires_at = timezone.now() + timedelta(minutes=10)
        
        # Create OTP record
        TwoFactorAuth.objects.create(
            user=user,
            code=otp_code,
            method='SMS',
            expires_at=expires_at,
            ip_address=ip_address
        )
        
        # Send OTP
        send_otp_sms(user.phone_number, otp_code)
        
        messages.success(request, 'New OTP sent successfully.')
    except KDFUser.DoesNotExist:
        messages.error(request, 'Invalid session.')
        return redirect('login')
    
    return redirect('verify_otp')


@login_required
def logout_view(request):
    """Handle user logout"""
    
    # Audit log
    AuditLog.objects.create(
        user=request.user,
        action='LOGOUT',
        model_name='KDFUser',
        object_id=str(request.user.id),
        changes={'logout_time': timezone.now().isoformat()},
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request)
    )
    
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')


# ==================== DASHBOARD ROUTER ====================

@login_required
def dashboard_router(request):
    """Route users to appropriate dashboard based on rank/role"""
    
    user = request.user
    
    # High Command (Generals, Brigadiers)
    if user.rank in ['GENERAL', 'BRIGADIER']:
        return redirect('command_dashboard')
    
    # Senior Officers (Colonels, Majors)
    elif user.rank in ['COLONEL', 'MAJOR']:
        return redirect('operations_dashboard')
    
    # Junior Officers (Captains, Lieutenants)
    elif user.rank in ['CAPTAIN', 'LIEUTENANT']:
        return redirect('tactical_dashboard')
    
    # NCOs and Enlisted (Sergeants, Corporals, Privates)
    else:
        return redirect('personnel_dashboard')


# ==================== COMMAND DASHBOARD (Generals, Brigadiers and general IT Admin) ====================

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Count, Sum, Avg, Q, F, Value
from django.db.models.functions import TruncDate, TruncMonth, Coalesce
from django.db.models import Case, When, IntegerField
from datetime import timedelta
from decimal import Decimal
import json

from .models import (
    KDFUser, Mission, ThreatIntelligence, Equipment, 
    SupplyChain, Incident, AuditLog, MLModel, LoginAttempt
)


@login_required
def command_dashboard(request):
    """Strategic overview dashboard for high command with advanced analytics"""
    
    # Check permission
    if request.user.rank not in ['GENERAL', 'BRIGADIER']:
        messages.error(request, 'Access denied. Insufficient clearance level.')
        return redirect('dashboard_router')
    
    # Date ranges
    today = timezone.now().date()
    last_30_days = today - timedelta(days=30)
    last_7_days = today - timedelta(days=7)
    last_90_days = today - timedelta(days=90)
    last_12_months = today - timedelta(days=365)
    
    # ==================== KEY METRICS ====================
    total_personnel = KDFUser.objects.filter(status='ACTIVE').count()
    active_missions = Mission.objects.filter(status='ACTIVE').count()
    critical_threats = ThreatIntelligence.objects.filter(
        severity='CRITICAL',
        status__in=['UNDER_INVESTIGATION', 'VERIFIED', 'MONITORING']
    ).count()
    
    missions_by_status = list(
        Mission.objects
        .values('status')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    missions_timeline = list(
        Mission.objects.filter(created_at__gte=last_90_days)
        .annotate(date=TruncDate('created_at'))
        .values('date')
        .annotate(count=Count('id'))
        .order_by('date')
    )
    
    # Mission by Classification (for Bar Chart)
    missions_by_classification = list(
        Mission.objects.values('classification')
        .annotate(count=Count('id'))
        .order_by('classification')
    )
    
    # Average Mission Duration
    completed_missions = Mission.objects.filter(
        status='COMPLETED',
        end_date__isnull=False
    )
    
    # ==================== THREAT INTELLIGENCE ====================
    # Threat Trends (Last 30 Days - Line Graph)
    threat_trends = list(
        ThreatIntelligence.objects.filter(detected_at__gte=last_30_days)
        .annotate(date=TruncDate('detected_at'))
        .values('date')
        .annotate(count=Count('id'))
        .order_by('date')
    )
    
    # Threat Severity Distribution (Donut Chart)
    threats_by_severity = list(
        ThreatIntelligence.objects.values('severity')
        .annotate(count=Count('id'))
        .order_by('severity')
    )
    
    # Threat Source Analysis (Bar Chart)
    threats_by_source = list(
        ThreatIntelligence.objects.values('source')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    # AI Confidence Analysis
    avg_threat_confidence_result = ThreatIntelligence.objects.aggregate(
        avg_confidence=Avg('ai_confidence_score')
    )
    avg_threat_confidence = avg_threat_confidence_result['avg_confidence'] or Decimal('0')
    
    # Recent High Severity Threats
    high_severity_threats = ThreatIntelligence.objects.filter(
        severity__in=['HIGH', 'CRITICAL'],
        status__in=['UNDER_INVESTIGATION', 'VERIFIED', 'MONITORING']
    ).order_by('-detected_at')[:10]
    
    # ==================== PERSONNEL ANALYTICS ====================
    # Branch Distribution (for Donut Chart)
    branch_distribution = list(
        KDFUser.objects.filter(status='ACTIVE')
        .values('branch')
        .annotate(count=Count('id'))
    )
    
    # Rank Distribution (for Bar Chart)
    rank_distribution = list(
        KDFUser.objects.filter(status='ACTIVE')
        .values('rank')
        .annotate(count=Count('id'))
        .order_by('rank')
    )
    
    # Clearance Level Distribution (for Radar Chart)
    clearance_distribution = list(
        KDFUser.objects.filter(status='ACTIVE')
        .values('clearance_level')
        .annotate(count=Count('id'))
        .order_by('clearance_level')
    )
    
    # Personnel Status
    personnel_by_status = list(
        KDFUser.objects.values('status')
        .annotate(count=Count('id'))
    )
    
    # ==================== EQUIPMENT & LOGISTICS ====================
    # Equipment Status (Donut Chart)
    equipment_by_status = list(
        Equipment.objects.values('status')
        .annotate(count=Count('id'))
    )
    
    # Equipment Category Distribution (Bar Chart)
    equipment_by_category = list(
        Equipment.objects.values('category')
        .annotate(
            count=Count('id'),
            total_value=Sum('total_value')
        )
        .order_by('-total_value')
    )
    
    # Equipment requiring maintenance soon
    equipment_maintenance_due = Equipment.objects.filter(
        next_maintenance__lte=today + timedelta(days=7),
        status='OPERATIONAL'
    ).count()
    
    # Total Equipment Value
    total_equipment_value_result = Equipment.objects.aggregate(
        total=Sum('total_value')
    )
    total_equipment_value = total_equipment_value_result['total'] or Decimal('0')
    
    # ==================== SUPPLY CHAIN ====================
    # Supply Chain Status (for Bar Chart)
    supply_by_status = list(
        SupplyChain.objects.values('status')
        .annotate(count=Count('id'))
        .order_by('status')
    )
    
    # Monthly Supply Requests (Line Graph)
    monthly_supply_requests = list(
        SupplyChain.objects.filter(requested_date__gte=last_12_months)
        .annotate(month=TruncMonth('requested_date'))
        .values('month')
        .annotate(count=Count('id'))
        .order_by('month')
    )
    
    # ==================== INCIDENT MANAGEMENT ====================
    # Incident Trends (Last 30 Days)
    incident_trends = list(
        Incident.objects.filter(reported_at__gte=last_30_days)
        .annotate(date=TruncDate('reported_at'))
        .values('date')
        .annotate(count=Count('id'))
        .order_by('date')
    )
    
    # Incidents by Type (Bar Chart)
    incidents_by_type = list(
        Incident.objects.values('incident_type')
        .annotate(count=Count('id'))
        .order_by('-count')[:8]
    )
    
    # Incidents by Priority (Donut Chart)
    incidents_by_priority = list(
        Incident.objects.values('priority')
        .annotate(count=Count('id'))
    )
    
    # Recent Critical Incidents
    recent_incidents = Incident.objects.filter(
        priority__in=['HIGH', 'CRITICAL']
    ).order_by('-reported_at')[:8]
    
    # Resolution Rate
    total_incidents = Incident.objects.count()
    resolved_incidents = Incident.objects.filter(resolved=True).count()
    resolution_rate = (resolved_incidents / total_incidents * 100) if total_incidents > 0 else 0
    
    # ==================== BUDGET & FINANCIAL ====================
    # Total Budget Allocated
    total_budget_allocated_result = Mission.objects.filter(
        status__in=['APPROVED', 'ACTIVE']
    ).aggregate(total=Sum('allocated_budget'))
    total_budget_allocated = total_budget_allocated_result['total'] or Decimal('0')
    
    # Budget by Mission Classification
    budget_by_classification = list(
        Mission.objects.filter(allocated_budget__isnull=False)
        .values('classification')
        .annotate(total_budget=Sum('allocated_budget'))
        .order_by('classification')
    )
    
    # ==================== SECURITY & AUDIT ====================
    # Failed Login Attempts (Last 7 Days)
    failed_logins = LoginAttempt.objects.filter(
        successful=False,
        timestamp__gte=last_7_days
    ).count()
    
    # Suspicious Activity
    suspicious_activities = AuditLog.objects.filter(
        flagged_suspicious=True,
        timestamp__gte=last_7_days
    ).count()
    
    # Login trends - FIXED: Using Sum with Case/When
    login_trends_data = list(
        LoginAttempt.objects.filter(timestamp__gte=last_30_days)
        .annotate(date=TruncDate('timestamp'))
        .values('date')
        .annotate(
            successful=Sum(
                Case(
                    When(successful=True, then=Value(1)),
                    default=Value(0),
                    output_field=IntegerField()
                )
            ),
            failed=Sum(
                Case(
                    When(successful=False, then=Value(1)),
                    default=Value(0),
                    output_field=IntegerField()
                )
            )
        )
        .order_by('date')
    )
    
    # Process login trends to ensure proper JSON serialization
    processed_login_trends = []
    for trend in login_trends_data:
        processed_login_trends.append({
            'date': trend['date'].isoformat() if trend['date'] else None,
            'successful': trend['successful'] or 0,
            'failed': trend['failed'] or 0
        })
    
    # ==================== ML MODEL PERFORMANCE ====================
    # Active ML Models
    active_ml_models = MLModel.objects.filter(is_active=True).count()
    
    # Model Performance (Radar Chart Data)
    ml_model_performance = list(
        MLModel.objects.filter(is_active=True)
        .values('model_type', 'accuracy', 'precision', 'recall', 'f1_score')
    )
    
    # Convert Decimal fields to float for JSON serialization
    processed_ml_performance = []
    for model in ml_model_performance:
        processed_model = {
            'model_type': model['model_type'],
            'accuracy': float(model['accuracy']) if model['accuracy'] else 0.0,
            'precision': float(model['precision']) if model['precision'] else 0.0,
            'recall': float(model['recall']) if model['recall'] else 0.0,
            'f1_score': float(model['f1_score']) if model['f1_score'] else 0.0
        }
        processed_ml_performance.append(processed_model)
    
    # ==================== OPERATIONAL READINESS SCORE (Radar Chart) ====================
    # Calculate equipment operational percentage
    equipment_status_counts = {item['status']: item['count'] for item in equipment_by_status}
    total_equipment_count = sum(equipment_status_counts.values())
    equipment_operational_pct = (equipment_status_counts.get('OPERATIONAL', 0) / total_equipment_count * 100) if total_equipment_count > 0 else 0
    
    # Calculate logistics delivery percentage
    supply_status_counts = {item['status']: item['count'] for item in supply_by_status}
    total_supplies = sum(supply_status_counts.values())
    logistics_delivery_pct = (supply_status_counts.get('DELIVERED', 0) / total_supplies * 100) if total_supplies > 0 else 0
    
    operational_readiness = {
        'personnel': min((total_personnel / 10000) * 100, 100),  # Assuming 10,000 is full strength
        'equipment': min(equipment_operational_pct, 100),
        'missions': min((active_missions / 50) * 100, 100),  # Assuming 50 is max concurrent
        'intelligence': max(0, min(100 - (critical_threats * 5), 100)),  # Inverse of threats
        'logistics': min(logistics_delivery_pct, 100),
    }
    
    # ==================== ADDITIONAL METRICS ====================
    # Mission success rate (if we had this field)
    completed_successful_missions = Mission.objects.filter(
        status='COMPLETED'
    ).count()
    
    total_completed_missions = Mission.objects.filter(
        status='COMPLETED'
    ).count()
    
    mission_success_rate = (completed_successful_missions / total_completed_missions * 100) if total_completed_missions > 0 else 0
    
    # Average response time for incidents (if we had this field)
    resolved_incidents_with_time = Incident.objects.filter(
        resolved=True,
        resolved_at__isnull=False,
        reported_at__isnull=False
    )
    
    # Equipment utilization rate
    equipment_assigned = Equipment.objects.filter(assigned_to__isnull=False).count()
    total_equipment = Equipment.objects.count()
    equipment_utilization = (equipment_assigned / total_equipment * 100) if total_equipment > 0 else 0
    
    # ==================== PROCESS DATA FOR JSON SERIALIZATION ====================
    def process_for_json(data):
        """Helper to convert dates and decimals for JSON serialization"""
        if isinstance(data, list):
            return [process_for_json(item) for item in data]
        elif isinstance(data, dict):
            processed_dict = {}
            for key, value in data.items():
                try:
                    processed_dict[key] = process_for_json(value)
                except (ValueError, TypeError):
                    processed_dict[key] = str(value) if value is not None else None
            return processed_dict
        elif isinstance(data, Decimal):
            return float(data)
        elif hasattr(data, 'isoformat'):
            return data.isoformat()
        elif isinstance(data, (int, float, str, bool)) or data is None:
            return data
        else:
            return str(data)
    
    # ==================== CONVERT TO JSON FOR JAVASCRIPT ====================
    # Prepare all chart data
    chart_data = {
        'missions_by_status': process_for_json(missions_by_status),
        'missions_timeline': process_for_json(missions_timeline),
        'missions_by_classification': process_for_json(missions_by_classification),
        'threat_trends': process_for_json(threat_trends),
        'threats_by_severity': process_for_json(threats_by_severity),
        'threats_by_source': process_for_json(threats_by_source),
        'branch_distribution': process_for_json(branch_distribution),
        'rank_distribution': process_for_json(rank_distribution),
        'clearance_distribution': process_for_json(clearance_distribution),
        'equipment_by_status': process_for_json(equipment_by_status),
        'equipment_by_category': process_for_json(equipment_by_category),
        'supply_by_status': process_for_json(supply_by_status),
        'monthly_supply_requests': process_for_json(monthly_supply_requests),
        'incident_trends': process_for_json(incident_trends),
        'incidents_by_type': process_for_json(incidents_by_type),
        'incidents_by_priority': process_for_json(incidents_by_priority),
        'budget_by_classification': process_for_json(budget_by_classification),
        'login_trends': processed_login_trends,
        'operational_readiness': operational_readiness,
        'ml_model_performance': processed_ml_performance,
    }
    
    # Convert all chart data to JSON strings
    chart_data_json = {key: json.dumps(value) for key, value in chart_data.items()}
    
    context = {
        # Key Metrics
        'total_personnel': total_personnel,
        'active_missions': active_missions,
        'critical_threats': critical_threats,
        'total_budget_allocated': total_budget_allocated,
        'equipment_maintenance_due': equipment_maintenance_due,
        'failed_logins': failed_logins,
        'suspicious_activities': suspicious_activities,
        'active_ml_models': active_ml_models,
        'resolution_rate': round(resolution_rate, 1),
        'avg_threat_confidence': round(float(avg_threat_confidence) * 100, 1),
        'mission_success_rate': round(mission_success_rate, 1),
        'equipment_utilization': round(equipment_utilization, 1),
        
        # Chart Data (JSON strings)
        **chart_data_json,
        
        # List Data
        'high_severity_threats': high_severity_threats,
        'recent_incidents': recent_incidents,
        'personnel_by_status': personnel_by_status,
        'total_equipment_value': total_equipment_value,
        'total_incidents': total_incidents,
        'resolved_incidents': resolved_incidents,
        'equipment_assigned': equipment_assigned,
        'total_equipment': total_equipment,
        'equipment_operational_pct': round(equipment_operational_pct, 1),
        'logistics_delivery_pct': round(logistics_delivery_pct, 1),
        'completed_missions_count': total_completed_missions,
        'completed_successful_missions': completed_successful_missions,
        
        # User information for dashboard
        'user_rank': request.user.rank,
        'user_name': f"{request.user.rank} {request.user.first_name} {request.user.last_name}",
        'user_branch': request.user.branch,
        'user_clearance': request.user.clearance_level,
    }
    
    return render(request, 'sentinel/dashboards/command_dashboard.html', context)

# ==================== OPERATIONS DASHBOARD (Colonels, Majors) ====================

@login_required
def operations_dashboard(request):
    """Operations management dashboard for senior officers"""
    
    # Check permission
    if request.user.rank not in ['COLONEL', 'MAJOR', 'GENERAL', 'BRIGADIER']:
        messages.error(request, 'Access denied. Insufficient clearance level.')
        return redirect('dashboard_router')
    
    # Missions Overview
    my_commanded_missions = Mission.objects.filter(commander=request.user)
    active_missions = Mission.objects.filter(status='ACTIVE').order_by('-start_date')[:10]
    pending_approval = Mission.objects.filter(status='PLANNING').order_by('-created_at')[:10]
    
    # Threat Intelligence
    recent_threats = ThreatIntelligence.objects.filter(
        severity__in=['MEDIUM', 'HIGH', 'CRITICAL']
    ).order_by('-detected_at')[:10]
    
    unverified_threats = ThreatIntelligence.objects.filter(
        verified=False
    ).count()
    
    # Supply Chain Management
    pending_supplies = SupplyChain.objects.filter(
        status__in=['REQUESTED', 'APPROVED']
    ).order_by('-priority', '-requested_date')[:10]
    
    # Incident Reports
    recent_incidents = Incident.objects.filter(
        resolved=False
    ).order_by('-priority', '-reported_at')[:10]
    
    # Personnel under command
    personnel_count = MissionAssignment.objects.filter(
        mission__commander=request.user,
        mission__status='ACTIVE'
    ).count()
    
    # Equipment Requests
    critical_equipment = Equipment.objects.filter(
        status='DAMAGED',
        ml_maintenance_priority__gte=7
    ).order_by('-ml_maintenance_priority')[:10]
    
    context = {
        'my_commanded_missions': my_commanded_missions.count(),
        'active_missions': active_missions,
        'pending_approval': pending_approval,
        'recent_threats': recent_threats,
        'unverified_threats': unverified_threats,
        'pending_supplies': pending_supplies,
        'recent_incidents': recent_incidents,
        'personnel_count': personnel_count,
        'critical_equipment': critical_equipment,
    }
    
    return render(request, 'sentinel/dashboards/operations_dashboard.html', context)


# ==================== TACTICAL DASHBOARD (Captains, Lieutenants) ====================

@login_required
def tactical_dashboard(request):
    """Tactical operations dashboard for junior officers"""
    
    # Check permission
    if request.user.rank not in ['CAPTAIN', 'LIEUTENANT', 'MAJOR', 'COLONEL', 'GENERAL', 'BRIGADIER']:
        messages.error(request, 'Access denied. Insufficient clearance level.')
        return redirect('dashboard_router')
    
    # My Missions
    my_missions = Mission.objects.filter(
        missionassignment__personnel=request.user
    ).order_by('-start_date')[:10]
    
    active_assignments = MissionAssignment.objects.filter(
        personnel=request.user,
        mission__status='ACTIVE'
    ).select_related('mission')
    
    # My Unit
    unit_personnel = KDFUser.objects.filter(
        unit=request.user.unit,
        status='ACTIVE'
    ).count()
    
    # Incidents in my area
    recent_incidents = Incident.objects.filter(
        location__icontains=request.user.unit.split()[0]  # Match unit location
    ).order_by('-reported_at')[:8]
    
    # Threat Intelligence relevant to unit
    relevant_threats = ThreatIntelligence.objects.filter(
        severity__in=['MEDIUM', 'HIGH', 'CRITICAL'],
        status__in=['VERIFIED', 'MONITORING']
    ).order_by('-detected_at')[:8]
    
    # Equipment assigned to me
    my_equipment = Equipment.objects.filter(
        assigned_to=request.user
    )
    
    # Supply requests I've made
    my_supply_requests = SupplyChain.objects.filter(
        requested_by=request.user
    ).order_by('-requested_date')[:8]
    
    # Briefing status
    unbriefed_missions = MissionAssignment.objects.filter(
        personnel=request.user,
        briefed=False,
        mission__status__in=['APPROVED', 'ACTIVE']
    ).count()
    
    context = {
        'my_missions': my_missions,
        'active_assignments': active_assignments,
        'unit_personnel': unit_personnel,
        'recent_incidents': recent_incidents,
        'relevant_threats': relevant_threats,
        'my_equipment': my_equipment,
        'my_supply_requests': my_supply_requests,
        'unbriefed_missions': unbriefed_missions,
    }
    
    return render(request, 'sentinel/dashboards/tactical_dashboard.html', context)


# ==================== PERSONNEL DASHBOARD (NCOs, Enlisted) ====================

@login_required
def personnel_dashboard(request):
    """Basic dashboard for NCOs and enlisted personnel"""
    
    # My Profile Summary
    my_missions_count = MissionAssignment.objects.filter(
        personnel=request.user
    ).count()
    
    current_missions = MissionAssignment.objects.filter(
        personnel=request.user,
        mission__status='ACTIVE'
    ).select_related('mission')
    
    # My Equipment
    my_equipment = Equipment.objects.filter(
        assigned_to=request.user
    )
    
    # Training & Briefings
    unbriefed_count = MissionAssignment.objects.filter(
        personnel=request.user,
        briefed=False,
        mission__status__in=['APPROVED', 'ACTIVE']
    ).count()
    
    # Unit Information
    unit_size = KDFUser.objects.filter(
        unit=request.user.unit,
        status='ACTIVE'
    ).count()
    
    # Recent Activity
    my_recent_activity = AuditLog.objects.filter(
        user=request.user
    ).order_by('-timestamp')[:10]
    
    # Announcements/Notices (using recent incidents as proxy)
    notices = Incident.objects.filter(
        priority__in=['MEDIUM', 'HIGH', 'CRITICAL']
    ).order_by('-reported_at')[:5]
    
    context = {
        'my_missions_count': my_missions_count,
        'current_missions': current_missions,
        'my_equipment': my_equipment,
        'unbriefed_count': unbriefed_count,
        'unit_size': unit_size,
        'my_recent_activity': my_recent_activity,
        'notices': notices,
    }
    
    return render(request, 'sentinel/dashboards/personnel_dashboard.html', context)