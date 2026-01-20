from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.db.models import Count, Q
from django.utils import timezone
from .models import (
    KDFUser, TwoFactorAuth, LoginAttempt, Mission, MissionAssignment,
    ThreatIntelligence, Equipment, SupplyChain, Incident, AuditLog, MLModel
)


class MissionAssignmentInline(admin.TabularInline):
    model = MissionAssignment
    extra = 1
    fields = ('personnel', 'role', 'briefed', 'assigned_date')
    readonly_fields = ('assigned_date',)
    autocomplete_fields = ['personnel']


class TwoFactorAuthInline(admin.TabularInline):
    model = TwoFactorAuth
    extra = 0
    fields = ('method', 'code', 'created_at', 'expires_at', 'is_used', 'ip_address')
    readonly_fields = ('created_at', 'expires_at', 'ip_address')
    can_delete = False
    max_num = 5

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(KDFUser)
class KDFUserAdmin(UserAdmin):
    list_display = (
        'service_number', 'get_full_name', 'rank', 'branch', 
        'status', 'clearance_badge', 'security_status', 'is_active'
    )
    list_filter = (
        'rank', 'branch', 'status', 'clearance_level', 
        'is_two_factor_enabled', 'is_active', 'date_joined'
    )
    search_fields = (
        'service_number', 'email', 'first_name', 'last_name', 
        'national_id', 'phone_number', 'unit'
    )
    ordering = ('-date_joined',)
    date_hierarchy = 'date_joined'
    
    fieldsets = (
        ('Authentication', {
            'fields': ('service_number', 'email', 'password')
        }),
        ('Personal Information', {
            'fields': (
                'first_name', 'last_name', 'national_id', 
                'date_of_birth', 'phone_number'
            )
        }),
        ('Military Information', {
            'fields': (
                'rank', 'branch', 'unit', 'specialization',
                'enlistment_date', 'status', 'clearance_level'
            )
        }),
        ('Security & 2FA', {
            'fields': (
                'is_two_factor_enabled', 'phone_verified', 'email_verified',
                'failed_login_attempts', 'account_locked_until', 'last_login_ip'
            ),
            'classes': ('collapse',)
        }),
        ('Biometric Data', {
            'fields': ('fingerprint_hash', 'face_recognition_hash'),
            'classes': ('collapse',)
        }),
        ('Permissions', {
            'fields': (
                'is_active', 'is_staff', 'is_superuser',
                'groups', 'user_permissions'
            ),
            'classes': ('collapse',)
        }),
        ('Important Dates', {
            'fields': ('last_login', 'date_joined', 'last_updated'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = (
        'date_joined', 'last_updated', 'last_login', 
        'failed_login_attempts', 'last_login_ip'
    )
    
    inlines = [TwoFactorAuthInline]
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"
    get_full_name.short_description = 'Name'
    
    def clearance_badge(self, obj):
        colors = {1: '#gray', 2: '#blue', 3: '#green', 4: '#orange', 5: '#red'}
        color = colors.get(obj.clearance_level, '#gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-weight: bold;">Level {}</span>',
            color, obj.clearance_level
        )
    clearance_badge.short_description = 'Clearance'
    
    def security_status(self, obj):
        if obj.is_account_locked():
            return format_html('<span style="color: red;">🔒 LOCKED</span>')
        if obj.is_two_factor_enabled and obj.phone_verified and obj.email_verified:
            return format_html('<span style="color: green;">✓ SECURED</span>')
        return format_html('<span style="color: orange;">⚠ PARTIAL</span>')
    security_status.short_description = 'Security'
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related().annotate(
            mission_count=Count('missions'),
            incident_count=Count('reported_incidents')
        )


@admin.register(TwoFactorAuth)
class TwoFactorAuthAdmin(admin.ModelAdmin):
    list_display = ('user', 'method', 'code', 'created_at', 'expires_at', 'is_used', 'is_valid_status')
    list_filter = ('method', 'is_used', 'created_at')
    search_fields = ('user__service_number', 'user__email', 'code')
    readonly_fields = ('created_at', 'is_valid_status')
    date_hierarchy = 'created_at'
    
    def is_valid_status(self, obj):
        if obj.is_valid():
            return format_html('<span style="color: green;">✓ Valid</span>')
        return format_html('<span style="color: red;">✗ Invalid/Expired</span>')
    is_valid_status.short_description = 'Status'


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = (
        'service_number', 'ip_address', 'successful', 
        'timestamp', 'location', 'failure_reason'
    )
    list_filter = ('successful', 'timestamp')
    search_fields = ('service_number', 'ip_address', 'user_agent')
    readonly_fields = ('timestamp',)
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(Mission)
class MissionAdmin(admin.ModelAdmin):
    list_display = (
        'mission_code', 'title', 'classification_badge', 'status_badge',
        'commander', 'threat_level_indicator', 'start_date', 'personnel_count'
    )
    list_filter = ('classification', 'status', 'start_date', 'ai_threat_level')
    search_fields = ('mission_code', 'title', 'description', 'location')
    date_hierarchy = 'start_date'
    autocomplete_fields = ['commander']
    
    fieldsets = (
        ('Mission Identification', {
            'fields': ('mission_code', 'title', 'description')
        }),
        ('Classification & Status', {
            'fields': ('classification', 'status', 'location', 'coordinates')
        }),
        ('Timeline', {
            'fields': ('start_date', 'end_date')
        }),
        ('Personnel & Resources', {
            'fields': (
                'commander', 'required_personnel_count', 
                'allocated_budget'
            )
        }),
        ('AI Threat Assessment', {
            'fields': (
                'ai_threat_level', 'ai_risk_factors', 'ai_recommendations'
            ),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at')
    inlines = [MissionAssignmentInline]
    
    def classification_badge(self, obj):
        colors = {
            'UNCLASSIFIED': '#gray',
            'CONFIDENTIAL': '#blue',
            'SECRET': '#orange',
            'TOP_SECRET': '#red'
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            colors.get(obj.classification, '#gray'),
            obj.get_classification_display()
        )
    classification_badge.short_description = 'Classification'
    
    def status_badge(self, obj):
        colors = {
            'PLANNING': '#gray',
            'APPROVED': '#blue',
            'ACTIVE': '#green',
            'COMPLETED': '#purple',
            'ABORTED': '#red'
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.status, '#gray'),
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    
    def threat_level_indicator(self, obj):
        level = float(obj.ai_threat_level)
        if level >= 0.8:
            color = 'red'
            icon = '🔴'
        elif level >= 0.5:
            color = 'orange'
            icon = '🟠'
        else:
            color = 'green'
            icon = '🟢'
        percentage = int(level * 100)
        return format_html(
            '{} <span style="color: {};">{}%</span>',
            icon, color, percentage
        )
    threat_level_indicator.short_description = 'AI Threat'
    
    def personnel_count(self, obj):
        return obj.assigned_personnel.count()
    personnel_count.short_description = 'Personnel'


@admin.register(MissionAssignment)
class MissionAssignmentAdmin(admin.ModelAdmin):
    list_display = ('mission', 'personnel', 'role', 'assigned_date', 'briefed')
    list_filter = ('role', 'briefed', 'assigned_date')
    search_fields = ('mission__mission_code', 'personnel__service_number')
    autocomplete_fields = ['mission', 'personnel']
    readonly_fields = ('assigned_date',)


@admin.register(ThreatIntelligence)
class ThreatIntelligenceAdmin(admin.ModelAdmin):
    list_display = (
        'title', 'threat_type', 'severity_badge', 'source',
        'confidence_indicator', 'verified', 'status', 'detected_at'
    )
    list_filter = ('severity', 'source', 'verified', 'status', 'detected_at')
    search_fields = ('title', 'description', 'threat_type', 'location')
    date_hierarchy = 'detected_at'
    autocomplete_fields = ['verified_by', 'related_mission']
    
    fieldsets = (
        ('Threat Information', {
            'fields': ('title', 'description', 'threat_type', 'location', 'coordinates')
        }),
        ('Classification', {
            'fields': ('severity', 'source', 'status')
        }),
        ('AI/ML Analysis', {
            'fields': (
                'ai_confidence_score', 'ai_predicted_timeline',
                'ai_related_threats', 'ml_pattern_match'
            )
        }),
        ('Verification', {
            'fields': ('verified', 'verified_by', 'related_mission')
        }),
        ('Timeline', {
            'fields': ('detected_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('detected_at', 'updated_at')
    
    def severity_badge(self, obj):
        colors = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107',
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545'
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            colors.get(obj.severity, '#gray'),
            obj.severity
        )
    severity_badge.short_description = 'Severity'
    
    def confidence_indicator(self, obj):
        score = float(obj.ai_confidence_score)
        if score >= 0.8:
            icon = '✓✓✓'
            color = 'green'
        elif score >= 0.6:
            icon = '✓✓'
            color = 'orange'
        else:
            icon = '✓'
            color = 'gray'
        percentage = int(score * 100)
        return format_html(
            '<span style="color: {};">{} {}%</span>',
            color, icon, percentage
        )
    confidence_indicator.short_description = 'AI Confidence'


@admin.register(Equipment)
class EquipmentAdmin(admin.ModelAdmin):
    list_display = (
        'equipment_code', 'name', 'category', 'quantity',
        'status_badge', 'current_location', 'maintenance_status',
        'total_value'
    )
    list_filter = ('category', 'status', 'acquired_date')
    search_fields = ('equipment_code', 'name', 'description', 'current_location')
    autocomplete_fields = ['assigned_to']
    date_hierarchy = 'acquired_date'
    
    fieldsets = (
        ('Equipment Details', {
            'fields': ('equipment_code', 'name', 'category', 'description')
        }),
        ('Inventory & Valuation', {
            'fields': ('quantity', 'unit_cost', 'total_value')
        }),
        ('Status & Location', {
            'fields': (
                'status', 'current_location', 'assigned_unit', 'assigned_to'
            )
        }),
        ('Maintenance', {
            'fields': ('last_maintenance', 'next_maintenance')
        }),
        ('ML Predictions', {
            'fields': ('ml_predicted_failure_date', 'ml_maintenance_priority'),
            'classes': ('collapse',)
        }),
        ('Tracking', {
            'fields': ('acquired_date', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at')
    
    def status_badge(self, obj):
        colors = {
            'OPERATIONAL': 'green',
            'MAINTENANCE': 'orange',
            'DAMAGED': 'red',
            'DECOMMISSIONED': 'gray'
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.status, 'black'),
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    
    def maintenance_status(self, obj):
        if obj.next_maintenance:
            days_until = (obj.next_maintenance - timezone.now().date()).days
            if days_until < 0:
                return format_html('<span style="color: red;">⚠ OVERDUE</span>')
            elif days_until < 7:
                return format_html('<span style="color: orange;">⚠ DUE SOON</span>')
            else:
                return format_html('<span style="color: green;">✓ OK</span>')
        return '-'
    maintenance_status.short_description = 'Maintenance'


@admin.register(SupplyChain)
class SupplyChainAdmin(admin.ModelAdmin):
    list_display = (
        'request_number', 'requesting_unit', 'status_badge',
        'priority_indicator', 'requested_date', 'delivery_confidence'
    )
    list_filter = ('status', 'priority', 'requested_date')
    search_fields = ('request_number', 'requesting_unit', 'origin', 'destination')
    autocomplete_fields = ['requested_by', 'approved_by']
    date_hierarchy = 'requested_date'
    
    fieldsets = (
        ('Request Information', {
            'fields': ('request_number', 'requesting_unit', 'requested_by', 'approved_by')
        }),
        ('Items & Priority', {
            'fields': ('items', 'priority', 'status')
        }),
        ('Timeline', {
            'fields': (
                'requested_date', 'approved_date', 
                'expected_delivery', 'delivery_date'
            )
        }),
        ('Logistics', {
            'fields': ('origin', 'destination', 'current_location')
        }),
        ('ML Optimization', {
            'fields': (
                'ml_optimal_route', 'ml_estimated_cost', 'ml_delivery_confidence'
            ),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('requested_date',)
    
    def status_badge(self, obj):
        colors = {
            'REQUESTED': '#6c757d',
            'APPROVED': '#007bff',
            'IN_TRANSIT': '#ffc107',
            'DELIVERED': '#28a745',
            'CANCELLED': '#dc3545'
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            colors.get(obj.status, '#gray'),
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    
    def priority_indicator(self, obj):
        icons = {1: '🔴🔴🔴', 2: '🔴🔴', 3: '🟡', 4: '🟢', 5: '🟢🟢'}
        return icons.get(obj.priority, '🟡')
    priority_indicator.short_description = 'Priority'
    
    def delivery_confidence(self, obj):
        if obj.ml_delivery_confidence:
            score = float(obj.ml_delivery_confidence)
            percentage = int(score * 100)
            return format_html('{}%', percentage)
        return '-'
    delivery_confidence.short_description = 'ML Confidence'


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = (
        'incident_number', 'title', 'incident_type', 
        'priority_badge', 'casualties', 'status', 'reported_at', 'resolved'
    )
    list_filter = ('incident_type', 'priority', 'resolved', 'reported_at')
    search_fields = ('incident_number', 'title', 'description', 'location')
    autocomplete_fields = ['reported_by', 'response_coordinator']
    filter_horizontal = ('response_team',)
    date_hierarchy = 'reported_at'
    
    fieldsets = (
        ('Incident Details', {
            'fields': (
                'incident_number', 'incident_type', 'title', 
                'description', 'location', 'coordinates'
            )
        }),
        ('Severity', {
            'fields': ('priority', 'casualties')
        }),
        ('Reporting', {
            'fields': ('reported_by', 'reported_at')
        }),
        ('Response', {
            'fields': (
                'response_coordinator', 'status', 
                'resolved', 'resolved_at'
            )
        }),
        ('AI Recommendations', {
            'fields': (
                'ai_recommended_resources', 'ai_estimated_response_time',
                'ai_similar_incidents'
            ),
            'classes': ('collapse',)
        }),
        ('Documentation', {
            'fields': ('images', 'after_action_report'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('reported_at',)
    
    def priority_badge(self, obj):
        colors = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107',
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545'
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            colors.get(obj.priority, '#gray'),
            obj.priority
        )
    priority_badge.short_description = 'Priority'


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        'user', 'action', 'model_name', 'timestamp',
        'ip_address', 'suspicious_flag'
    )
    list_filter = ('action', 'flagged_suspicious', 'timestamp')
    search_fields = ('user__service_number', 'model_name', 'object_id', 'ip_address')
    readonly_fields = ('timestamp', 'ai_anomaly_score')
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False
    
    def suspicious_flag(self, obj):
        if obj.flagged_suspicious:
            score = float(obj.ai_anomaly_score)
            percentage = int(score * 100)
            return format_html(
                '<span style="color: red; font-weight: bold;">⚠ FLAGGED ({}%)</span>',
                percentage
            )
        return format_html('<span style="color: green;">✓</span>')
    suspicious_flag.short_description = 'Security'


@admin.register(MLModel)
class MLModelAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'model_type', 'version', 'is_active',
        'performance_score', 'last_trained', 'training_data_size'
    )
    list_filter = ('model_type', 'is_active', 'deployed_at')
    search_fields = ('name', 'description', 'version')
    autocomplete_fields = ['created_by']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Model Information', {
            'fields': ('name', 'model_type', 'version', 'description')
        }),
        ('Performance Metrics', {
            'fields': ('accuracy', 'precision', 'recall', 'f1_score')
        }),
        ('Deployment', {
            'fields': ('is_active', 'deployed_at', 'last_trained', 'training_data_size')
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at',)
    
    def performance_score(self, obj):
        if obj.f1_score:
            score = float(obj.f1_score)
            if score >= 0.9:
                color = 'green'
            elif score >= 0.7:
                color = 'orange'
            else:
                color = 'red'
            percentage = int(score * 100)
            return format_html(
                '<span style="color: {}; font-weight: bold;">F1: {}%</span>',
                color, percentage
            )
        return '-'
    performance_score.short_description = 'Performance'


# Admin site customization
admin.site.site_header = "KDF Sentinel Command Center"
admin.site.site_title = "KDF Sentinel Admin"
admin.site.index_title = "Military Operations Management System"