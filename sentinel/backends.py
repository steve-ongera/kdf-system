"""
Custom Authentication Backend for KDF SENTINEL
File: sentinel/backends.py
"""

from django.contrib.auth.backends import BaseBackend
from .models import KDFUser


class ServiceNumberBackend(BaseBackend):
    """
    Authenticate using service_number instead of username
    """
    
    def authenticate(self, request, service_number=None, password=None, **kwargs):
        try:
            user = KDFUser.objects.get(service_number=service_number)
            if user.check_password(password):
                return user
        except KDFUser.DoesNotExist:
            return None
        return None
    
    def get_user(self, user_id):
        try:
            return KDFUser.objects.get(pk=user_id)
        except KDFUser.DoesNotExist:
            return None