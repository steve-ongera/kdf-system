from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator
from django.utils import timezone
from django.contrib.postgres.fields import ArrayField
import uuid


class CustomUserManager(BaseUserManager):
    def create_user(self, service_number, email, password=None, **extra_fields):
        if not service_number:
            raise ValueError('Service number is required')
        if not email:
            raise ValueError('Email is required')
        
        email = self.normalize_email(email)
        user = self.model(service_number=service_number, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, service_number, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('rank', 'GENERAL')
        return self.create_user(service_number, email, password, **extra_fields)


class KDFUser(AbstractBaseUser, PermissionsMixin):
    """Enhanced user model for KDF personnel with 2FA"""
    
    RANK_CHOICES = [
        ('PRIVATE', 'Private'),
        ('CORPORAL', 'Corporal'),
        ('SERGEANT', 'Sergeant'),
        ('LIEUTENANT', 'Lieutenant'),
        ('CAPTAIN', 'Captain'),
        ('MAJOR', 'Major'),
        ('COLONEL', 'Colonel'),
        ('BRIGADIER', 'Brigadier'),
        ('GENERAL', 'General'),
    ]
    
    BRANCH_CHOICES = [
        ('ARMY', 'Kenya Army'),
        ('NAVY', 'Kenya Navy'),
        ('AIR_FORCE', 'Kenya Air Force'),
    ]
    
    STATUS_CHOICES = [
        ('ACTIVE', 'Active Duty'),
        ('RESERVE', 'Reserve'),
        ('RETIRED', 'Retired'),
        ('SUSPENDED', 'Suspended'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service_number = models.CharField(max_length=20, unique=True, db_index=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(
        max_length=15,
        validators=[RegexValidator(regex=r'^\+254\d{9}$', message='Enter valid Kenyan phone number')],
        unique=True
    )
    
    # Personal Information
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    national_id = models.CharField(max_length=20, unique=True)
    date_of_birth = models.DateField()
    
    # Military Information
    rank = models.CharField(max_length=20, choices=RANK_CHOICES)
    branch = models.CharField(max_length=20, choices=BRANCH_CHOICES)
    unit = models.CharField(max_length=200)
    specialization = models.CharField(max_length=200, blank=True)
    enlistment_date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    
    # Security & Authentication
    is_two_factor_enabled = models.BooleanField(default=True)
    phone_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    # Biometric Data (hashed references)
    fingerprint_hash = models.CharField(max_length=256, blank=True)
    face_recognition_hash = models.CharField(max_length=256, blank=True)
    
    # System fields
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    last_updated = models.DateTimeField(auto_now=True)
    
    # Clearance Level (for access control)
    clearance_level = models.IntegerField(default=1)  # 1-5, 5 being highest
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'service_number'
    REQUIRED_FIELDS = ['email', 'phone_number', 'first_name', 'last_name']
    
    class Meta:
        db_table = 'kdf_users'
        indexes = [
            models.Index(fields=['service_number']),
            models.Index(fields=['email']),
            models.Index(fields=['status', 'branch']),
        ]
    
    def __str__(self):
        return f"{self.rank} {self.first_name} {self.last_name} ({self.service_number})"
    
    def is_account_locked(self):
        if self.account_locked_until and self.account_locked_until > timezone.now():
            return True
        return False


class TwoFactorAuth(models.Model):
    """Model for storing 2FA verification codes"""
    
    METHOD_CHOICES = [
        ('EMAIL', 'Email'),
        ('SMS', 'SMS'),
        ('AUTHENTICATOR', 'Authenticator App'),
    ]
    
    user = models.ForeignKey(KDFUser, on_delete=models.CASCADE, related_name='otp_codes')
    code = models.CharField(max_length=6)
    method = models.CharField(max_length=20, choices=METHOD_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField()
    
    class Meta:
        db_table = 'two_factor_auth'
        ordering = ['-created_at']
    
    def is_valid(self):
        return not self.is_used and self.expires_at > timezone.now()


class LoginAttempt(models.Model):
    """Track all login attempts for security monitoring"""
    
    user = models.ForeignKey(KDFUser, on_delete=models.CASCADE, related_name='login_attempts', null=True, blank=True)
    service_number = models.CharField(max_length=20)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    successful = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=200, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    location = models.CharField(max_length=200, blank=True)  # Geo-location
    
    class Meta:
        db_table = 'login_attempts'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['ip_address']),
        ]


class Mission(models.Model):
    """Mission/Operation tracking with AI threat assessment"""
    
    STATUS_CHOICES = [
        ('PLANNING', 'Planning'),
        ('APPROVED', 'Approved'),
        ('ACTIVE', 'Active'),
        ('COMPLETED', 'Completed'),
        ('ABORTED', 'Aborted'),
    ]
    
    CLASSIFICATION_CHOICES = [
        ('UNCLASSIFIED', 'Unclassified'),
        ('CONFIDENTIAL', 'Confidential'),
        ('SECRET', 'Secret'),
        ('TOP_SECRET', 'Top Secret'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    mission_code = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=300)
    description = models.TextField()
    
    # Mission Details
    classification = models.CharField(max_length=20, choices=CLASSIFICATION_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PLANNING')
    location = models.CharField(max_length=300)
    coordinates = models.CharField(max_length=100, blank=True)  # Lat,Long
    
    # Timeline
    start_date = models.DateTimeField()
    end_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Personnel
    commander = models.ForeignKey(KDFUser, on_delete=models.PROTECT, related_name='commanded_missions')
    assigned_personnel = models.ManyToManyField(KDFUser, related_name='missions', through='MissionAssignment')
    
    # AI-Generated Insights
    ai_threat_level = models.DecimalField(max_digits=3, decimal_places=2, default=0.0)  # 0-1 score
    ai_risk_factors = models.JSONField(default=dict)  # ML-generated risk analysis
    ai_recommendations = models.TextField(blank=True)
    
    # Resources
    required_personnel_count = models.IntegerField()
    allocated_budget = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    
    class Meta:
        db_table = 'missions'
        ordering = ['-created_at']
        permissions = [
            ('view_classified_missions', 'Can view classified missions'),
            ('approve_missions', 'Can approve missions'),
        ]


class MissionAssignment(models.Model):
    """Through model for mission personnel assignments"""
    
    ROLE_CHOICES = [
        ('COMMANDER', 'Commander'),
        ('OFFICER', 'Officer'),
        ('SPECIALIST', 'Specialist'),
        ('SUPPORT', 'Support'),
    ]
    
    mission = models.ForeignKey(Mission, on_delete=models.CASCADE)
    personnel = models.ForeignKey(KDFUser, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    assigned_date = models.DateTimeField(auto_now_add=True)
    briefed = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'mission_assignments'
        unique_together = ['mission', 'personnel']


class ThreatIntelligence(models.Model):
    """AI/ML-powered threat intelligence system"""
    
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    SOURCE_CHOICES = [
        ('HUMINT', 'Human Intelligence'),
        ('SIGINT', 'Signals Intelligence'),
        ('OSINT', 'Open Source Intelligence'),
        ('AI_DETECTED', 'AI System Detection'),
        ('CITIZEN_REPORT', 'Citizen Report'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=300)
    description = models.TextField()
    
    # Threat Details
    threat_type = models.CharField(max_length=100)  # Terrorism, Border Breach, etc.
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES)
    location = models.CharField(max_length=300)
    coordinates = models.CharField(max_length=100, blank=True)
    
    # AI/ML Analysis
    ai_confidence_score = models.DecimalField(max_digits=3, decimal_places=2)  # 0-1
    ai_predicted_timeline = models.CharField(max_length=200, blank=True)
    ai_related_threats = models.JSONField(default=list)  # IDs of related threats
    ml_pattern_match = models.JSONField(default=dict)  # Pattern recognition results
    
    # Status & Timeline
    verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(KDFUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_threats')
    status = models.CharField(max_length=50, default='UNDER_INVESTIGATION')
    detected_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Response
    related_mission = models.ForeignKey(Mission, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        db_table = 'threat_intelligence'
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['detected_at']),
        ]


class Equipment(models.Model):
    """Military equipment and inventory management"""
    
    CATEGORY_CHOICES = [
        ('WEAPONS', 'Weapons'),
        ('VEHICLES', 'Vehicles'),
        ('AIRCRAFT', 'Aircraft'),
        ('NAVAL', 'Naval Vessels'),
        ('COMMUNICATION', 'Communication Equipment'),
        ('MEDICAL', 'Medical Supplies'),
        ('AMMUNITION', 'Ammunition'),
        ('PROTECTIVE', 'Protective Gear'),
    ]
    
    STATUS_CHOICES = [
        ('OPERATIONAL', 'Operational'),
        ('MAINTENANCE', 'Under Maintenance'),
        ('DAMAGED', 'Damaged'),
        ('DECOMMISSIONED', 'Decommissioned'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    equipment_code = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=300)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    description = models.TextField()
    
    # Inventory
    quantity = models.IntegerField(default=1)
    unit_cost = models.DecimalField(max_digits=15, decimal_places=2)
    total_value = models.DecimalField(max_digits=15, decimal_places=2)
    
    # Status & Location
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPERATIONAL')
    current_location = models.CharField(max_length=300)
    assigned_unit = models.CharField(max_length=200, blank=True)
    assigned_to = models.ForeignKey(KDFUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_equipment')
    
    # Maintenance
    last_maintenance = models.DateField(null=True, blank=True)
    next_maintenance = models.DateField(null=True, blank=True)
    
    # ML-Predicted Maintenance
    ml_predicted_failure_date = models.DateField(null=True, blank=True)
    ml_maintenance_priority = models.IntegerField(default=0)  # 0-10 scale
    
    # Tracking
    acquired_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'equipment'
        ordering = ['category', 'name']


class SupplyChain(models.Model):
    """Supply chain and logistics with ML demand prediction"""
    
    STATUS_CHOICES = [
        ('REQUESTED', 'Requested'),
        ('APPROVED', 'Approved'),
        ('IN_TRANSIT', 'In Transit'),
        ('DELIVERED', 'Delivered'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    request_number = models.CharField(max_length=50, unique=True)
    
    # Request Details
    requesting_unit = models.CharField(max_length=200)
    requested_by = models.ForeignKey(KDFUser, on_delete=models.PROTECT, related_name='supply_requests')
    approved_by = models.ForeignKey(KDFUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_supplies')
    
    # Items
    items = models.JSONField(default=list)  # List of {equipment_id, quantity, urgency}
    
    # Status & Timeline
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='REQUESTED')
    priority = models.IntegerField(default=3)  # 1-5, 1 being highest
    requested_date = models.DateTimeField(auto_now_add=True)
    approved_date = models.DateTimeField(null=True, blank=True)
    delivery_date = models.DateTimeField(null=True, blank=True)
    expected_delivery = models.DateTimeField(null=True, blank=True)
    
    # ML Optimization
    ml_optimal_route = models.JSONField(default=dict)
    ml_estimated_cost = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    ml_delivery_confidence = models.DecimalField(max_digits=3, decimal_places=2, default=0.0)
    
    # Location
    origin = models.CharField(max_length=300)
    destination = models.CharField(max_length=300)
    current_location = models.CharField(max_length=300, blank=True)
    
    class Meta:
        db_table = 'supply_chain'
        ordering = ['-requested_date']


class Incident(models.Model):
    """Real-time incident reporting and response coordination"""
    
    TYPE_CHOICES = [
        ('SECURITY_BREACH', 'Security Breach'),
        ('BORDER_INCIDENT', 'Border Incident'),
        ('TERRORIST_ACTIVITY', 'Terrorist Activity'),
        ('CIVIL_UNREST', 'Civil Unrest'),
        ('NATURAL_DISASTER', 'Natural Disaster'),
        ('EQUIPMENT_FAILURE', 'Equipment Failure'),
        ('PERSONNEL_EMERGENCY', 'Personnel Emergency'),
    ]
    
    PRIORITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    incident_number = models.CharField(max_length=50, unique=True)
    
    # Incident Details
    incident_type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    title = models.CharField(max_length=300)
    description = models.TextField()
    location = models.CharField(max_length=300)
    coordinates = models.CharField(max_length=100, blank=True)
    
    # Severity & Priority
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES)
    casualties = models.IntegerField(default=0)
    
    # Reporting
    reported_by = models.ForeignKey(KDFUser, on_delete=models.PROTECT, related_name='reported_incidents')
    reported_at = models.DateTimeField(auto_now_add=True)
    
    # Response
    response_team = models.ManyToManyField(KDFUser, related_name='incident_responses', blank=True)
    response_coordinator = models.ForeignKey(KDFUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='coordinated_incidents')
    status = models.CharField(max_length=50, default='REPORTED')
    resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # AI-Assisted Response
    ai_recommended_resources = models.JSONField(default=dict)
    ai_estimated_response_time = models.IntegerField(null=True, blank=True)  # minutes
    ai_similar_incidents = models.JSONField(default=list)
    
    # Documentation
    images = models.JSONField(default=list)  # URLs to images
    after_action_report = models.TextField(blank=True)
    
    class Meta:
        db_table = 'incidents'
        ordering = ['-reported_at']


class AuditLog(models.Model):
    """Comprehensive audit trail for all system activities"""
    
    ACTION_CHOICES = [
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('VIEW', 'View'),
        ('EXPORT', 'Export'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('PERMISSION_CHANGE', 'Permission Change'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(KDFUser, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    model_name = models.CharField(max_length=100)
    object_id = models.CharField(max_length=100)
    changes = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Anomaly Detection
    flagged_suspicious = models.BooleanField(default=False)
    ai_anomaly_score = models.DecimalField(max_digits=3, decimal_places=2, default=0.0)
    
    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['flagged_suspicious']),
        ]


class MLModel(models.Model):
    """Track ML models used in the system"""
    
    MODEL_TYPES = [
        ('THREAT_PREDICTION', 'Threat Prediction'),
        ('ANOMALY_DETECTION', 'Anomaly Detection'),
        ('DEMAND_FORECAST', 'Demand Forecasting'),
        ('ROUTE_OPTIMIZATION', 'Route Optimization'),
        ('PATTERN_RECOGNITION', 'Pattern Recognition'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    model_type = models.CharField(max_length=30, choices=MODEL_TYPES)
    version = models.CharField(max_length=20)
    description = models.TextField()
    
    # Performance Metrics
    accuracy = models.DecimalField(max_digits=5, decimal_places=4, null=True, blank=True)
    precision = models.DecimalField(max_digits=5, decimal_places=4, null=True, blank=True)
    recall = models.DecimalField(max_digits=5, decimal_places=4, null=True, blank=True)
    f1_score = models.DecimalField(max_digits=5, decimal_places=4, null=True, blank=True)
    
    # Deployment
    is_active = models.BooleanField(default=False)
    deployed_at = models.DateTimeField(null=True, blank=True)
    last_trained = models.DateTimeField()
    training_data_size = models.IntegerField()
    
    # Metadata
    created_by = models.ForeignKey(KDFUser, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'ml_models'
        ordering = ['-created_at']