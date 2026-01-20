"""
Django management command to seed KDF database with realistic Kenyan data
Usage: python manage.py seed_data
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from datetime import timedelta, datetime
import random
import uuid
from decimal import Decimal

from sentinel.models import (
    KDFUser, TwoFactorAuth, LoginAttempt, Mission, MissionAssignment,
    ThreatIntelligence, Equipment, SupplyChain, Incident, AuditLog, MLModel
)


class Command(BaseCommand):
    help = 'Seeds the database with realistic KDF data for 2 years period'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing data before seeding',
        )

    def handle(self, *args, **options):
        if options['clear']:
            self.stdout.write(self.style.WARNING('Clearing existing data...'))
            self.clear_data()

        self.stdout.write(self.style.SUCCESS('Starting KDF data seeding...'))
        
        # Seed in order (respecting foreign key dependencies)
        users = self.seed_users()
        self.seed_login_attempts(users)
        missions = self.seed_missions(users)
        self.seed_mission_assignments(missions, users)
        self.seed_threats(users, missions)
        equipment = self.seed_equipment(users)
        self.seed_supply_chain(users, equipment)
        self.seed_incidents(users)
        self.seed_audit_logs(users)
        self.seed_ml_models(users)
        
        self.stdout.write(self.style.SUCCESS('✅ Data seeding completed successfully!'))

    def clear_data(self):
        """Clear all existing data"""
        models = [AuditLog, Incident, SupplyChain, Equipment, ThreatIntelligence, 
                  MissionAssignment, Mission, LoginAttempt, TwoFactorAuth, MLModel, KDFUser]
        for model in models:
            count = model.objects.count()
            model.objects.all().delete()
            self.stdout.write(f'  Deleted {count} {model.__name__} records')

    def seed_users(self):
        """Seed KDF personnel - 200 users"""
        self.stdout.write('Seeding KDF Users...')
        
        kenyan_first_names = [
            'James', 'John', 'Peter', 'David', 'Daniel', 'Samuel', 'Joseph', 'William',
            'Michael', 'Stephen', 'Brian', 'Kevin', 'Eric', 'Martin', 'Francis',
            'Mary', 'Jane', 'Grace', 'Faith', 'Ann', 'Lucy', 'Ruth', 'Sarah',
            'Margaret', 'Elizabeth', 'Catherine', 'Joyce', 'Rebecca', 'Esther', 'Alice'
        ]
        
        kenyan_last_names = [
            'Kimani', 'Mwangi', 'Otieno', 'Ochieng', 'Kipchoge', 'Korir', 'Wanjiru',
            'Njoroge', 'Ouma', 'Kamau', 'Mutua', 'Nyambura', 'Achieng', 'Wangari',
            'Kariuki', 'Kiplagat', 'Cheruiyot', 'Juma', 'Owino', 'Mureithi',
            'Kiprotich', 'Akinyi', 'Maina', 'Wairimu', 'Chesang', 'Adhiambo'
        ]
        
        kenyan_units = [
            '1st Battalion Kenya Rifles', '2nd Battalion Kenya Rifles',
            '3rd Battalion Kenya Rifles', '20th Parachute Battalion',
            'Armoured Brigade', 'Artillery Brigade', 'Engineer Brigade',
            'Kenya Navy - Eastern Fleet', 'Kenya Navy - Western Fleet',
            'Kenya Air Force - 82 Air Base', 'Kenya Air Force - Nanyuki Base',
            'Special Forces - Gilgil', 'Military Police', 'Signals Corps',
            '7th Infantry Brigade', '15th Kenya Rifles'
        ]
        
        ranks = ['PRIVATE', 'CORPORAL', 'SERGEANT', 'LIEUTENANT', 'CAPTAIN', 
                 'MAJOR', 'COLONEL', 'BRIGADIER', 'GENERAL']
        
        branches = ['ARMY', 'NAVY', 'AIR_FORCE']
        
        specializations = [
            'Infantry', 'Armored Warfare', 'Artillery', 'Engineering', 'Signals',
            'Intelligence', 'Special Operations', 'Aviation', 'Naval Operations',
            'Cyber Security', 'Medical', 'Logistics', 'Military Police'
        ]
        
        users = []
        
        # Create superuser/commanding officer
        superuser = KDFUser.objects.create(
            service_number='KDF001',
            email='commander@kdf.go.ke',
            phone_number='+254712000001',
            first_name='Joseph',
            last_name='Kibwana',
            national_id='12345678',
            date_of_birth=datetime(1970, 3, 15).date(),
            rank='GENERAL',
            branch='ARMY',
            unit='Defence Headquarters',
            specialization='Command',
            enlistment_date=datetime(1990, 1, 10).date(),
            status='ACTIVE',
            is_two_factor_enabled=True,
            phone_verified=True,
            email_verified=True,
            is_active=True,
            is_staff=True,
            is_superuser=True,
            clearance_level=5
        )
        superuser.set_password('KDF@2026Secure')
        superuser.save()
        users.append(superuser)
        
        # Create 199 more users
        for i in range(2, 201):
            first_name = random.choice(kenyan_first_names)
            last_name = random.choice(kenyan_last_names)
            branch = random.choice(branches)
            rank = random.choices(
                ranks,
                weights=[30, 25, 20, 10, 8, 4, 2, 0.8, 0.2]  # More lower ranks
            )[0]
            
            # Clearance based on rank
            clearance_map = {
                'PRIVATE': 1, 'CORPORAL': 1, 'SERGEANT': 2,
                'LIEUTENANT': 2, 'CAPTAIN': 3, 'MAJOR': 3,
                'COLONEL': 4, 'BRIGADIER': 4, 'GENERAL': 5
            }
            
            enlistment_year = random.randint(1995, 2023)
            birth_year = enlistment_year - random.randint(18, 25)
            
            user = KDFUser.objects.create(
                service_number=f'KDF{i:06d}',
                email=f'{first_name.lower()}.{last_name.lower()}{i}@kdf.go.ke',
                phone_number=f'+254{random.randint(700000000, 799999999)}',
                first_name=first_name,
                last_name=last_name,
                national_id=f'{random.randint(10000000, 39999999)}',
                date_of_birth=datetime(birth_year, random.randint(1, 12), random.randint(1, 28)).date(),
                rank=rank,
                branch=branch,
                unit=random.choice(kenyan_units),
                specialization=random.choice(specializations),
                enlistment_date=datetime(enlistment_year, random.randint(1, 12), random.randint(1, 28)).date(),
                status=random.choices(['ACTIVE', 'RESERVE', 'RETIRED'], weights=[85, 10, 5])[0],
                is_two_factor_enabled=True,
                phone_verified=random.choice([True, True, True, False]),
                email_verified=random.choice([True, True, True, False]),
                clearance_level=clearance_map[rank],
                is_active=True
            )
            user.set_password('Password123!')
            user.save()
            users.append(user)
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(users)} KDF users'))
        return users

    def seed_login_attempts(self, users):
        """Seed login attempts - 500 records over 2 years"""
        self.stdout.write('Seeding Login Attempts...')
        
        attempts = []
        start_date = timezone.now() - timedelta(days=730)
        
        kenyan_cities = ['Nairobi', 'Mombasa', 'Kisumu', 'Nakuru', 'Eldoret', 'Thika', 'Nyeri']
        
        for _ in range(500):
            user = random.choice(users)
            timestamp = start_date + timedelta(
                days=random.randint(0, 730),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            successful = random.choices([True, False], weights=[95, 5])[0]
            
            attempts.append(LoginAttempt(
                user=user if successful else None,
                service_number=user.service_number,
                ip_address=f'41.{random.randint(80, 90)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
                user_agent=random.choice([
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
                    'Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0'
                ]),
                successful=successful,
                failure_reason='' if successful else random.choice([
                    'Invalid password', 'Account locked', '2FA failed', 'Invalid service number'
                ]),
                timestamp=timestamp,
                location=f'{random.choice(kenyan_cities)}, Kenya'
            ))
        
        LoginAttempt.objects.bulk_create(attempts)
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(attempts)} login attempts'))

    def seed_missions(self, users):
        """Seed missions - 80 missions over 2 years"""
        self.stdout.write('Seeding Missions...')
        
        kenyan_locations = [
            'Lamu County', 'Garissa County', 'Mandera County', 'Turkana County',
            'Nairobi Metropolitan', 'Mombasa Port Area', 'Mount Kenya Region',
            'Lake Victoria Basin', 'North Eastern Province', 'Rift Valley',
            'Coastal Region', 'Somalia Border - Liboi', 'Ethiopia Border - Moyale',
            'Indian Ocean - Exclusive Economic Zone', 'Tsavo National Park'
        ]
        
        mission_types = [
            ('Border Patrol - Operation Linda Mpaka', 'Border security and surveillance'),
            ('Counter-Terrorism - Operation Linda Nchi Extension', 'Anti-terrorism operations'),
            ('Maritime Security - Operation Usalama Baharini', 'Naval patrol and piracy prevention'),
            ('Wildlife Protection - Operation Dumisha', 'Anti-poaching operations'),
            ('Disaster Response - Operation Msaada', 'Emergency and disaster relief'),
            ('Training Exercise - Cutlass Express', 'Joint military exercises'),
            ('Peace Support - Operation Utulivu', 'Internal peace keeping'),
            ('Intelligence Gathering - Operation Ulinzi', 'Reconnaissance mission'),
        ]
        
        missions = []
        start_date = timezone.now() - timedelta(days=730)
        
        commanders = [u for u in users if u.rank in ['MAJOR', 'COLONEL', 'BRIGADIER', 'GENERAL']]
        
        for i in range(1, 81):
            mission_type = random.choice(mission_types)
            start = start_date + timedelta(days=random.randint(0, 700))
            duration = random.randint(3, 90)
            
            status_weights = {
                'PLANNING': [70, 20, 5, 3, 2],
                'APPROVED': [10, 60, 20, 8, 2],
                'ACTIVE': [5, 10, 60, 20, 5],
                'COMPLETED': [2, 5, 10, 70, 13],
                'ABORTED': [1, 1, 2, 5, 91]
            }
            
            status = random.choices(
                ['PLANNING', 'APPROVED', 'ACTIVE', 'COMPLETED', 'ABORTED'],
                weights=[15, 20, 25, 35, 5]
            )[0]
            
            classification = random.choices(
                ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'],
                weights=[20, 40, 30, 10]
            )[0]
            
            missions.append(Mission(
                mission_code=f'KDF-{start.year}-{i:04d}',
                title=mission_type[0],
                description=f'{mission_type[1]}. Objective: Maintain security and stability in the region.',
                classification=classification,
                status=status,
                location=random.choice(kenyan_locations),
                coordinates=f'{random.uniform(-4.5, 4.5):.6f}, {random.uniform(33.5, 42.0):.6f}',
                start_date=start,
                end_date=start + timedelta(days=duration) if status == 'COMPLETED' else None,
                commander=random.choice(commanders),
                required_personnel_count=random.randint(10, 200),
                allocated_budget=Decimal(random.randint(500000, 50000000)),
                ai_threat_level=Decimal(random.uniform(0.1, 0.95)).quantize(Decimal('0.01')),
                ai_risk_factors={
                    'terrain_difficulty': random.choice(['low', 'medium', 'high']),
                    'enemy_presence': random.choice(['low', 'medium', 'high']),
                    'weather_conditions': random.choice(['favorable', 'challenging', 'severe']),
                    'civilian_density': random.choice(['low', 'medium', 'high'])
                },
                ai_recommendations=f'Recommended force size: {random.randint(15, 250)}. Suggested equipment: {random.choice(["armored vehicles", "air support", "naval assets", "special forces"])}.'
            ))
        
        Mission.objects.bulk_create(missions)
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(missions)} missions'))
        return Mission.objects.all()

    def seed_mission_assignments(self, missions, users):
        """Seed mission assignments - assign personnel to missions"""
        self.stdout.write('Seeding Mission Assignments...')
        
        assignments = []
        active_personnel = [u for u in users if u.status == 'ACTIVE']
        
        for mission in missions:
            # Assign 10-50 personnel per mission
            num_assignments = min(random.randint(10, 50), mission.required_personnel_count)
            assigned = random.sample(active_personnel, min(num_assignments, len(active_personnel)))
            
            for person in assigned:
                role = random.choices(
                    ['COMMANDER', 'OFFICER', 'SPECIALIST', 'SUPPORT'],
                    weights=[2, 15, 30, 53]
                )[0]
                
                assignments.append(MissionAssignment(
                    mission=mission,
                    personnel=person,
                    role=role,
                    assigned_date=mission.start_date - timedelta(days=random.randint(1, 30)),
                    briefed=random.choice([True, True, True, False])
                ))
        
        MissionAssignment.objects.bulk_create(assignments)
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(assignments)} mission assignments'))

    def seed_threats(self, users, missions):
        """Seed threat intelligence - 150 threats over 2 years"""
        self.stdout.write('Seeding Threat Intelligence...')
        
        threat_types = [
            'Terrorist Activity - Al-Shabaab', 'Border Breach Attempt', 'Arms Smuggling',
            'Cattle Rustling', 'Illegal Immigration', 'Drug Trafficking',
            'Wildlife Poaching', 'Piracy Activity', 'Cyber Attack Attempt',
            'Organized Crime', 'Extremist Recruitment', 'IED Detection'
        ]
        
        kenyan_hotspots = [
            'Lamu County', 'Garissa', 'Mandera Triangle', 'Somalia Border',
            'Eastleigh Nairobi', 'Mombasa Old Town', 'Turkana-West Pokot Border',
            'Indian Ocean Waters', 'Dadaab Refugee Camp Area', 'Boni Forest',
            'Mpeketoni Area', 'Liboi Border Post'
        ]
        
        threats = []
        start_date = timezone.now() - timedelta(days=730)
        
        verified_by = [u for u in users if u.clearance_level >= 3]
        
        for i in range(150):
            detected = start_date + timedelta(
                days=random.randint(0, 730),
                hours=random.randint(0, 23)
            )
            
            severity = random.choices(
                ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                weights=[25, 40, 25, 10]
            )[0]
            
            verified = random.choice([True, True, False])
            
            threats.append(ThreatIntelligence(
                title=f'{random.choice(threat_types)} - Threat {i+1}',
                description=f'Intelligence report indicates potential security threat. Source reliability: {random.choice(["confirmed", "probable", "possible"])}. Immediate assessment required.',
                threat_type=random.choice(threat_types),
                severity=severity,
                source=random.choice(['HUMINT', 'SIGINT', 'OSINT', 'AI_DETECTED', 'CITIZEN_REPORT']),
                location=random.choice(kenyan_hotspots),
                coordinates=f'{random.uniform(-4.5, 4.5):.6f}, {random.uniform(33.5, 42.0):.6f}',
                ai_confidence_score=Decimal(random.uniform(0.5, 0.99)).quantize(Decimal('0.01')),
                ai_predicted_timeline=random.choice(['24-48 hours', '3-7 days', '1-2 weeks', 'Immediate']),
                ai_related_threats=[str(uuid.uuid4()) for _ in range(random.randint(0, 3))],
                ml_pattern_match={
                    'similar_incidents': random.randint(0, 15),
                    'pattern_confidence': random.uniform(0.6, 0.95),
                    'historical_match': random.choice([True, False])
                },
                verified=verified,
                verified_by=random.choice(verified_by) if verified else None,
                status=random.choice(['UNDER_INVESTIGATION', 'VERIFIED', 'MONITORING', 'RESOLVED', 'FALSE_ALARM']),
                detected_at=detected,
                related_mission=random.choice(list(missions)) if random.random() > 0.7 else None
            ))
        
        ThreatIntelligence.objects.bulk_create(threats)
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(threats)} threat intelligence records'))

    def seed_equipment(self, users):
        """Seed equipment inventory - 300 items"""
        self.stdout.write('Seeding Equipment Inventory...')
        
        equipment_data = {
            'WEAPONS': [
                ('AK-47 Rifle', 45000), ('G3 Battle Rifle', 55000), ('FN FAL', 60000),
                ('M4 Carbine', 85000), ('PKM Machine Gun', 120000), ('Browning M2', 200000),
                ('RPG-7', 150000), ('Mortar 81mm', 350000)
            ],
            'VEHICLES': [
                ('Land Cruiser 4x4', 4500000), ('Ural Truck', 3200000), ('Iveco VM90', 5800000),
                ('Armored Personnel Carrier', 12000000), ('T-72 Tank', 45000000),
                ('Nyayo 1 APC', 8500000)
            ],
            'AIRCRAFT': [
                ('F-5 Fighter Jet', 350000000), ('Fennec Helicopter', 180000000),
                ('C-130 Hercules', 450000000), ('UAV Drone', 25000000)
            ],
            'NAVAL': [
                ('Patrol Boat', 85000000), ('Fast Attack Craft', 120000000)
            ],
            'COMMUNICATION': [
                ('Military Radio HF', 180000), ('Satellite Phone', 95000),
                ('Tactical Headset', 25000), ('Encrypted Laptop', 220000)
            ],
            'MEDICAL': [
                ('Field Hospital Kit', 450000), ('Trauma Kit', 35000),
                ('Ambulance Vehicle', 3500000)
            ],
            'AMMUNITION': [
                ('7.62mm Rounds (1000)', 18000), ('.50 Cal Rounds (500)', 45000),
                ('40mm Grenades (50)', 85000), ('Artillery Shell 105mm', 125000)
            ],
            'PROTECTIVE': [
                ('Body Armor Vest Level IV', 45000), ('Kevlar Helmet', 18000),
                ('NBC Suit', 95000), ('Night Vision Goggles', 280000)
            ]
        }
        
        kenyan_bases = [
            'Embakasi Garrison', 'Kahawa Barracks', 'Lanet Barracks',
            'Gilgil Base', 'Nanyuki Air Base', 'Mombasa Naval Base',
            'Mtongwe Naval Base', 'Wajir Air Base'
        ]
        
        equipment_list = []
        counter = 1
        
        for category, items in equipment_data.items():
            for item_name, unit_cost in items:
                # Create multiple instances based on category
                quantity_range = {
                    'WEAPONS': (50, 500),
                    'VEHICLES': (5, 50),
                    'AIRCRAFT': (2, 10),
                    'NAVAL': (3, 15),
                    'COMMUNICATION': (100, 1000),
                    'MEDICAL': (20, 200),
                    'AMMUNITION': (1000, 50000),
                    'PROTECTIVE': (100, 2000)
                }
                
                instances = random.randint(1, 5)  # Create 1-5 inventory records per item type
                
                for _ in range(instances):
                    quantity = random.randint(*quantity_range[category])
                    acquired_years_ago = random.randint(1, 15)  # Changed from 0 to 1
                    acquired = datetime.now().date() - timedelta(days=acquired_years_ago * 365)
                    
                    # Calculate maintenance dates safely
                    days_since_acquired = acquired_years_ago * 365
                    if days_since_acquired > 60:
                        last_maint = acquired + timedelta(days=random.randint(30, days_since_acquired - 30))
                    else:
                        last_maint = acquired + timedelta(days=30)
                    
                    next_maint = last_maint + timedelta(days=random.randint(90, 365))
                    
                    equipment_list.append(Equipment(
                        equipment_code=f'{category[:3]}-{counter:06d}',
                        name=item_name,
                        category=category,
                        description=f'Standard issue {item_name.lower()} for KDF operations.',
                        quantity=quantity,
                        unit_cost=Decimal(unit_cost),
                        total_value=Decimal(unit_cost * quantity),
                        status=random.choices(
                            ['OPERATIONAL', 'MAINTENANCE', 'DAMAGED', 'DECOMMISSIONED'],
                            weights=[75, 15, 8, 2]
                        )[0],
                        current_location=random.choice(kenyan_bases),
                        assigned_unit=random.choice([
                            '1st Battalion', '2nd Battalion', '3rd Battalion',
                            'Artillery Brigade', 'Air Force Squadron', 'Naval Fleet',
                            '', ''  # Some unassigned
                        ]),
                        assigned_to=random.choice(users) if random.random() > 0.7 else None,
                        last_maintenance=last_maint,
                        next_maintenance=next_maint,
                        ml_predicted_failure_date=next_maint + timedelta(days=random.randint(-30, 180)),
                        ml_maintenance_priority=random.randint(1, 10),
                        acquired_date=acquired
                    ))
                    counter += 1
        
        Equipment.objects.bulk_create(equipment_list)
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(equipment_list)} equipment records'))
        return Equipment.objects.all()

    def seed_supply_chain(self, users, equipment):
        """Seed supply chain - 120 requests over 2 years"""
        self.stdout.write('Seeding Supply Chain Requests...')
        
        kenyan_locations = [
            'Nairobi Central', 'Mombasa Port', 'Eldoret Depot', 'Kisumu Warehouse',
            'Nakuru Supply Center', 'Garissa Forward Base', 'Lamu Base'
        ]
        
        supply_requests = []
        start_date = timezone.now() - timedelta(days=730)
        
        officers = [u for u in users if u.rank in ['LIEUTENANT', 'CAPTAIN', 'MAJOR', 'COLONEL']]
        approvers = [u for u in users if u.rank in ['MAJOR', 'COLONEL', 'BRIGADIER', 'GENERAL']]
        
        for i in range(1, 121):
            requested = start_date + timedelta(days=random.randint(0, 730))
            status = random.choices(
                ['REQUESTED', 'APPROVED', 'IN_TRANSIT', 'DELIVERED', 'CANCELLED'],
                weights=[10, 15, 20, 50, 5]
            )[0]
            
            # Create items list
            num_items = random.randint(1, 8)
            items = []
            for _ in range(num_items):
                equip = random.choice(equipment)
                items.append({
                    'equipment_id': str(equip.id),
                    'equipment_name': equip.name,
                    'quantity': random.randint(1, 100),
                    'urgency': random.choice(['low', 'medium', 'high', 'critical'])
                })
            
            approved_date = requested + timedelta(days=random.randint(1, 7)) if status != 'REQUESTED' else None
            delivery_date = None
            if status == 'DELIVERED':
                delivery_date = approved_date + timedelta(days=random.randint(3, 30)) if approved_date else None
            
            supply_requests.append(SupplyChain(
                request_number=f'SCR-{requested.year}-{i:05d}',
                requesting_unit=random.choice([
                    '1st Battalion Kenya Rifles', '2nd Battalion', 'Artillery Brigade',
                    'Armoured Brigade', 'Special Forces', 'Naval Base Mombasa'
                ]),
                requested_by=random.choice(officers),
                approved_by=random.choice(approvers) if status != 'REQUESTED' else None,
                items=items,
                status=status,
                priority=random.randint(1, 5),
                requested_date=requested,
                approved_date=approved_date,
                delivery_date=delivery_date,
                expected_delivery=approved_date + timedelta(days=random.randint(5, 20)) if approved_date else None,
                ml_optimal_route={
                    'waypoints': random.sample(kenyan_locations, k=random.randint(2, 4)),
                    'distance_km': random.randint(50, 800),
                    'estimated_time_hours': random.randint(2, 24)
                },
                ml_estimated_cost=Decimal(random.randint(50000, 5000000)),
                ml_delivery_confidence=Decimal(random.uniform(0.7, 0.98)).quantize(Decimal('0.01')),
                origin=random.choice(kenyan_locations),
                destination=random.choice(kenyan_locations),
                current_location=random.choice(kenyan_locations) if status == 'IN_TRANSIT' else ''
            ))
        
        SupplyChain.objects.bulk_create(supply_requests)
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(supply_requests)} supply chain records'))

    def seed_incidents(self, users):
        """Seed incidents - 200 incidents over 2 years"""
        self.stdout.write('Seeding Incident Reports...')
        
        incident_scenarios = {
            'SECURITY_BREACH': [
                'Unauthorized access attempt at perimeter fence',
                'Suspicious vehicle near base entrance',
                'Unknown personnel attempting entry'
            ],
            'BORDER_INCIDENT': [
                'Illegal border crossing detected',
                'Cross-border gunfire exchange',
                'Smuggling attempt intercepted'
            ],
            'TERRORIST_ACTIVITY': [
                'IED discovered and neutralized',
                'Suspected militant movement reported',
                'Vehicle-borne threat identified'
            ],
            'CIVIL_UNREST': [
                'Protest near military installation',
                'Crowd control operation initiated',
                'Civil disturbance response'
            ],
            'EQUIPMENT_FAILURE': [
                'Vehicle breakdown during patrol',
                'Communication equipment malfunction',
                'Weapon system failure during exercise'
            ],
            'PERSONNEL_EMERGENCY': [
                'Medical emergency during training',
                'Personnel injury on duty',
                'Emergency medical evacuation required'
            ]
        }
        
        locations = [
            'Eastleigh, Nairobi', 'Garissa Town', 'Mandera Border Post',
            'Lamu County', 'Turkana Border Area', 'Mombasa Port',
            'Gilgil Training Base', 'Nanyuki Air Base', 'Somalia Border - Liboi'
        ]
        
        incidents = []
        start_date = timezone.now() - timedelta(days=730)
        
        coordinators = [u for u in users if u.rank in ['CAPTAIN', 'MAJOR', 'COLONEL']]
        
        for i in range(1, 201):
            incident_type = random.choice(list(incident_scenarios.keys()))
            reported = start_date + timedelta(
                days=random.randint(0, 730),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            resolved = random.choice([True, True, False])
            
            incidents.append(Incident(
                incident_number=f'INC-{reported.year}-{i:05d}',
                incident_type=incident_type,
                title=random.choice(incident_scenarios[incident_type]),
                description=f'Incident reported by field personnel. Immediate response initiated. Situation monitoring ongoing.',
                location=random.choice(locations),
                coordinates=f'{random.uniform(-4.5, 4.5):.6f}, {random.uniform(33.5, 42.0):.6f}',
                priority=random.choices(
                    ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                    weights=[30, 40, 20, 10]
                )[0],
                casualties=random.choices([0, 0, 0, 0, 1, 2, 3, 5], weights=[70, 10, 10, 5, 3, 1, 0.5, 0.5])[0],
                reported_by=random.choice(users),
                reported_at=reported,
                response_coordinator=random.choice(coordinators) if random.random() > 0.3 else None,
                status=random.choice(['REPORTED', 'RESPONDING', 'CONTAINED', 'RESOLVED', 'MONITORING']),
                resolved=resolved,
                resolved_at=reported + timedelta(hours=random.randint(2, 72)) if resolved else None,
                ai_recommended_resources={
                    'personnel': random.randint(5, 50),
                    'vehicles': random.randint(1, 5),
                    'medical_support': random.choice([True, False]),
                    'air_support': random.choice([True, False])
                },
                ai_estimated_response_time=random.randint(15, 240),
                ai_similar_incidents=[str(uuid.uuid4()) for _ in range(random.randint(0, 5))],
                images=[],
                after_action_report='Detailed report pending.' if not resolved else f'Incident successfully resolved. Total response time: {random.randint(30, 300)} minutes.'
            ))
        
        Incident.objects.bulk_create(incidents)
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(incidents)} incident reports'))

    def seed_audit_logs(self, users):
        """Seed audit logs - 1000 logs over 2 years"""
        self.stdout.write('Seeding Audit Logs...')
        
        actions = ['CREATE', 'UPDATE', 'DELETE', 'VIEW', 'EXPORT', 'LOGIN', 'LOGOUT', 'PERMISSION_CHANGE']
        models = ['Mission', 'ThreatIntelligence', 'Equipment', 'SupplyChain', 'Incident', 'KDFUser']
        
        logs = []
        start_date = timezone.now() - timedelta(days=730)
        
        for i in range(1000):
            timestamp = start_date + timedelta(
                days=random.randint(0, 730),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            action = random.choices(
                actions,
                weights=[15, 30, 5, 40, 3, 4, 2, 1]
            )[0]
            
            logs.append(AuditLog(
                user=random.choice(users),
                action=action,
                model_name=random.choice(models),
                object_id=str(uuid.uuid4()),
                changes={
                    'field_changed': random.choice(['status', 'location', 'priority', 'assigned_to']),
                    'old_value': random.choice(['ACTIVE', 'PENDING', 'HIGH', 'None']),
                    'new_value': random.choice(['COMPLETED', 'APPROVED', 'CRITICAL', 'Updated'])
                },
                ip_address=f'41.{random.randint(80, 90)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
                timestamp=timestamp,
                flagged_suspicious=random.choices([True, False], weights=[2, 98])[0],
                ai_anomaly_score=Decimal(random.uniform(0.0, 0.3)).quantize(Decimal('0.01'))
            ))
        
        AuditLog.objects.bulk_create(logs)
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(logs)} audit log entries'))

    def seed_ml_models(self, users):
        """Seed ML models - 6 models"""
        self.stdout.write('Seeding ML Model Records...')
        
        models_data = [
            {
                'name': 'Threat Prediction Model v2.1',
                'model_type': 'THREAT_PREDICTION',
                'version': '2.1.0',
                'description': 'Ensemble model using Random Forest and Gradient Boosting for threat prediction',
                'accuracy': Decimal('0.8745'),
                'precision': Decimal('0.8521'),
                'recall': Decimal('0.8912'),
                'f1_score': Decimal('0.8713'),
                'is_active': True,
                'training_data_size': 15420
            },
            {
                'name': 'User Anomaly Detection System',
                'model_type': 'ANOMALY_DETECTION',
                'version': '1.5.2',
                'description': 'Isolation Forest + Autoencoder for detecting suspicious user behavior',
                'accuracy': Decimal('0.9234'),
                'precision': Decimal('0.8876'),
                'recall': Decimal('0.9102'),
                'f1_score': Decimal('0.8987'),
                'is_active': True,
                'training_data_size': 28340
            },
            {
                'name': 'Supply Demand Forecaster',
                'model_type': 'DEMAND_FORECAST',
                'version': '3.0.1',
                'description': 'SARIMA + LSTM for equipment demand prediction',
                'accuracy': Decimal('0.8123'),
                'precision': Decimal('0.7956'),
                'recall': Decimal('0.8234'),
                'f1_score': Decimal('0.8093'),
                'is_active': True,
                'training_data_size': 12680
            },
            {
                'name': 'Logistics Route Optimizer',
                'model_type': 'ROUTE_OPTIMIZATION',
                'version': '2.3.0',
                'description': 'Genetic Algorithm for optimal supply chain routing',
                'accuracy': Decimal('0.9012'),
                'precision': Decimal('0.8845'),
                'recall': Decimal('0.9123'),
                'f1_score': Decimal('0.8982'),
                'is_active': True,
                'training_data_size': 8930
            },
            {
                'name': 'Threat Pattern Recognition',
                'model_type': 'PATTERN_RECOGNITION',
                'version': '1.8.5',
                'description': 'K-Means + DBSCAN clustering for identifying threat patterns',
                'accuracy': Decimal('0.7856'),
                'precision': Decimal('0.7634'),
                'recall': Decimal('0.8012'),
                'f1_score': Decimal('0.7819'),
                'is_active': True,
                'training_data_size': 19450
            },
            {
                'name': 'Legacy Threat Model',
                'model_type': 'THREAT_PREDICTION',
                'version': '1.0.0',
                'description': 'Initial threat prediction model - deprecated',
                'accuracy': Decimal('0.6523'),
                'precision': Decimal('0.6234'),
                'recall': Decimal('0.6789'),
                'f1_score': Decimal('0.6501'),
                'is_active': False,
                'training_data_size': 5230
            }
        ]
        
        ml_models = []
        tech_officers = [u for u in users if 'Cyber' in u.specialization or 'Intelligence' in u.specialization]
        if not tech_officers:
            tech_officers = [users[0]]
        
        for model_data in models_data:
            last_trained = timezone.now() - timedelta(days=random.randint(7, 90))
            deployed = last_trained + timedelta(days=random.randint(1, 5)) if model_data['is_active'] else None
            
            ml_models.append(MLModel(
                name=model_data['name'],
                model_type=model_data['model_type'],
                version=model_data['version'],
                description=model_data['description'],
                accuracy=model_data['accuracy'],
                precision=model_data['precision'],
                recall=model_data['recall'],
                f1_score=model_data['f1_score'],
                is_active=model_data['is_active'],
                deployed_at=deployed,
                last_trained=last_trained,
                training_data_size=model_data['training_data_size'],
                created_by=random.choice(tech_officers),
                created_at=timezone.now() - timedelta(days=random.randint(100, 700))
            ))
        
        MLModel.objects.bulk_create(ml_models)
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(ml_models)} ML model records'))