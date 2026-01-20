"""
URL Configuration for KDF SENTINEL
File: sentinel/urls.py
"""

from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('', views.login_view, name='login'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
    path('resend-otp/', views.resend_otp_view, name='resend_otp'),
    
    # Dashboard Router
    path('dashboard/', views.dashboard_router, name='dashboard_router'),
    
    # Role-Based Dashboards
    path('dashboard/command/', views.command_dashboard, name='command_dashboard'),
    path('dashboard/operations/', views.operations_dashboard, name='operations_dashboard'),
    path('dashboard/tactical/', views.tactical_dashboard, name='tactical_dashboard'),
    path('dashboard/personnel/', views.personnel_dashboard, name='personnel_dashboard'),
]