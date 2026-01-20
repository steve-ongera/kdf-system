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


# ==================== COMMAND DASHBOARD (Generals, Brigadiers) ====================

@login_required
def command_dashboard(request):
    """Strategic overview dashboard for high command"""
    
    # Check permission
    if request.user.rank not in ['GENERAL', 'BRIGADIER']:
        messages.error(request, 'Access denied. Insufficient clearance level.')
        return redirect('dashboard_router')
    
    # Date ranges
    today = timezone.now().date()
    last_30_days = today - timedelta(days=30)
    last_7_days = today - timedelta(days=7)
    
    # Key Metrics
    total_personnel = KDFUser.objects.filter(status='ACTIVE').count()
    active_missions = Mission.objects.filter(status='ACTIVE').count()
    critical_threats = ThreatIntelligence.objects.filter(
        severity='CRITICAL',
        status__in=['UNDER_INVESTIGATION', 'VERIFIED', 'MONITORING']
    ).count()
    
    # Mission Statistics
    missions_by_status = Mission.objects.values('status').annotate(count=Count('id'))
    
    # Threat Analysis
    threats_last_30_days = ThreatIntelligence.objects.filter(
        detected_at__gte=last_30_days
    ).count()
    
    high_severity_threats = ThreatIntelligence.objects.filter(
        severity__in=['HIGH', 'CRITICAL'],
        status__in=['UNDER_INVESTIGATION', 'VERIFIED', 'MONITORING']
    ).order_by('-detected_at')[:10]
    
    # Budget Overview
    total_budget_allocated = Mission.objects.filter(
        status__in=['APPROVED', 'ACTIVE']
    ).aggregate(total=Sum('allocated_budget'))['total'] or Decimal('0')
    
    # Recent Incidents
    recent_incidents = Incident.objects.filter(
        priority__in=['HIGH', 'CRITICAL']
    ).order_by('-reported_at')[:8]
    
    # Equipment Status
    equipment_operational = Equipment.objects.filter(status='OPERATIONAL').count()
    equipment_maintenance = Equipment.objects.filter(status='MAINTENANCE').count()
    equipment_damaged = Equipment.objects.filter(status='DAMAGED').count()
    
    # Branch Distribution
    branch_distribution = KDFUser.objects.filter(status='ACTIVE').values('branch').annotate(count=Count('id'))
    
    context = {
        'total_personnel': total_personnel,
        'active_missions': active_missions,
        'critical_threats': critical_threats,
        'missions_by_status': missions_by_status,
        'threats_last_30_days': threats_last_30_days,
        'high_severity_threats': high_severity_threats,
        'total_budget_allocated': total_budget_allocated,
        'recent_incidents': recent_incidents,
        'equipment_operational': equipment_operational,
        'equipment_maintenance': equipment_maintenance,
        'equipment_damaged': equipment_damaged,
        'branch_distribution': branch_distribution,
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