from django.urls import path,include
from django.contrib.auth.decorators import login_required
from . import views

urlpatterns = [
    path('', views.Home, name='home'),
    path('accounts/', include('allauth.urls')),
    path('register/', views.RegisterView, name='register'),
    path('accounts/profile/', views.google_view, name='google'),
    path('set-username/', views.SetUsernameAfterGoogle, name='set-username'),
    path('check-username/', views.check_username, name='check-username'),
    path('check-password-strength/', views.check_password_strength_view, name='check-password-strength'),
    path('login/', views.LoginView, name='login'),
    path('setup_2fa/', views.setup_2fa, name='setup_2fa'),
    path('verify_2fa/', views.verify_2fa, name='verify_2fa'),
    path('admin-dashboard/', login_required(views.admin_dashboard), name='admin_dashboard'), 
    path('client-dashboard/', login_required(views.client_dashboard), name='client_dashboard'),
    path('user-dashboard/', login_required(views.user_dashboard), name='user_dashboard'),
    path('forgot-password/', views.ForgotPassword, name='forgot-password'),
    path('password-reset-sent/<str:reset_id>/', views.PasswordResetSent, name='password-reset-sent'),
    path('reset-password/<str:reset_id>/', views.ResetPassword, name='reset-password'),
    path('ajax-logout/', views.ajax_logout, name='ajax_logout'),
    path('logout/', views.LogoutView, name='logout'),
]

    
    #sorted according to wotkflow 18-12-2024
   
    