from django.core.management.base import BaseCommand
from django.utils import timezone
from sentinel.models import KDFUser


class Command(BaseCommand):
    help = "Seed initial KDF admin (General) user"

    def handle(self, *args, **options):
        service_number = "KDF-GEN-0001"
        email = "admin@kdf.go.ke"

        # Check if admin already exists
        if KDFUser.objects.filter(service_number=service_number).exists():
            self.stdout.write(
                self.style.WARNING("Admin user already exists. Skipping creation.")
            )
            return

        admin_user = KDFUser.objects.create_superuser(
            service_number=service_number,
            email=email,
            password="password123",  # CHANGE AFTER FIRST LOGIN
            phone_number="+254700000000",
            first_name="SYSTEM",
            last_name="ADMIN",
            national_id="00000000",
            date_of_birth="1970-01-01",
            rank="GENERAL",
            branch="ARMY",
            unit="DEFENCE HEADQUARTERS",
            specialization="SYSTEM ADMINISTRATION",
            enlistment_date="1990-01-01",
            status="ACTIVE",
            clearance_level=5,
            is_two_factor_enabled=True,
            phone_verified=True,
            email_verified=True,
            is_active=True,
            is_staff=True,
            is_superuser=True,
            date_joined=timezone.now(),
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"✅ KDF Admin user created successfully: {admin_user.service_number}"
            )
        )
