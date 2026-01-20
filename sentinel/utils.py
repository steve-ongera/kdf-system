"""
Utility functions for KDF SENTINEL system
File: sentinel/utils.py
"""

from django.conf import settings
from django.core.mail import send_mail


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_user_agent(request):
    """Get user agent from request"""
    return request.META.get('HTTP_USER_AGENT', 'Unknown')


def send_otp_sms(phone_number, otp_code):
    """
    Send OTP via SMS using Africa's Talking or Twilio
    For development, just print to console
    """
    if settings.DEBUG:
        # Development mode - print to console
        print(f"\n{'='*50}")
        print(f"📱 SMS OTP to {phone_number}")
        print(f"Code: {otp_code}")
        print(f"{'='*50}\n")
        return True

    # Production - use actual SMS gateway here
    try:
        # Example with Africa's Talking
        # from africastalking import SMS
        # sms = SMS()
        # response = sms.send(
        #     f"Your KDF SENTINEL OTP is: {otp_code}. Valid for 10 minutes.",
        #     [phone_number]
        # )
        return True
    except Exception as e:
        print(f"SMS Error: {e}")
        return False


def send_otp_email(email, otp_code):
    """
    Send OTP via Email
    For development, prints to console
    """
    if settings.DEBUG:
        print(f"\n{'='*50}")
        print(f"📧 Email OTP to {email}")
        print(f"Code: {otp_code}")
        print(f"{'='*50}\n")
        return True

    # Production - send actual email
    try:
        send_mail(
            subject='KDF SENTINEL - Login Verification Code',
            message=f'Your verification code is: {otp_code}\n\nThis code will expire in 10 minutes.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Email Error: {e}")
        return False


def send_otp(phone_number=None, email=None, otp_code=None):
    """
    Unified function to send OTP via SMS and Email
    """
    sms_result = False
    email_result = False

    if phone_number:
        sms_result = send_otp_sms(phone_number, otp_code)
    
    if email:
        email_result = send_otp_email(email, otp_code)

    return sms_result, email_result
