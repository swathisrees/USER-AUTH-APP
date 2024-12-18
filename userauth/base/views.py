from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.signals import user_logged_in
from django.views.decorators.http import require_POST
from social_django.models import UserSocialAuth
from django.contrib.auth import get_user_model
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from django.http import JsonResponse
from django.http import HttpResponse
from django.dispatch import receiver
from django.contrib import messages
from django.utils import timezone
from .models import UserTwoFactor
from django.conf import settings
from django.urls import reverse
from io import BytesIO
from .models import *
import requests
import hashlib
import base64
import qrcode
import pyotp
import io
import re
ALLOWED_ROLES = ['ADMIN', 'CLIENT', 'USER']

@login_required
def Home(request):
    try:
        user_profile = request.user.userprofile
        
        # If user hasn't completed initial setup
        if not user_profile.has_set_initial_details:
            return redirect('set-username')
            
        # Use the utility function for redirection
        return get_role_redirect(user_profile.role)
        
    except UserProfile.DoesNotExist:
        return redirect('set-username')

def RegisterView(request):

    if request.method == "POST":
        username = request.POST.get('username').lower()
        email = request.POST.get('email').lower()
        password = request.POST.get('password')
        role = request.POST.get('role')

        user_data_has_error = False
        
        if User.objects.filter(username=username).exists():
            user_data_has_error = True
            messages.error(request, "Username already exists")

        if User.objects.filter(email=email).exists():
            user_data_has_error = True
            messages.error(request, "Email already exists")

       # Check password strength for final submission
        password_check = check_password_strength(password)
        if password_check['strength'] != 'strong':
            messages.error(request, password_check['feedback'])
            return render(request, 'reset_password.html')

        if user_data_has_error:
            return redirect('register')
        
        else:
            new_user = User.objects.create_user(
                email=email, 
                username=username,
                password=password,
                
            )

            UserProfile.objects.create(
                user=new_user,
                role=role
            )
            
        messages.success(request, "Account created successfully. Please login.")
        return redirect('login')

    return render(request, 'register.html')

def google_view(request):
    try:
        user_profile = request.user.userprofile
        
        # If user has already set up their profile, redirect to appropriate dashboard
        if user_profile.has_set_initial_details:
            return get_role_redirect(user_profile.role)
            
        # Get username suggestion from Google data
        social_auth = request.user.social_auth.get(provider='google-oauth2')
        suggested_username = social_auth.extra_data.get('given_name', '')
        if not suggested_username:
            suggested_username = social_auth.extra_data.get('name', '').split()[0]
        if not suggested_username:
            suggested_username = request.user.email.split('@')[0]
            
        context = {
            'suggested_username': suggested_username,
            'username_exists': User.objects.filter(username=suggested_username).exists()
        }
        
        return render(request, 'set_username.html', context)
        
    except UserProfile.DoesNotExist:
        # Create profile if it doesn't exist
        UserProfile.objects.create(user=request.user)
        return redirect('set-username')

@receiver(user_logged_in)
def google_login_handler(sender, request, user, **kwargs):
    try:
        # Check if this is a Google login
        social_auth = user.social_auth.filter(provider='google-oauth2').first()
        if social_auth:
            user_profile, created = UserProfile.objects.get_or_create(user=user)
            
            # Get Google data
            google_data = social_auth.extra_data
            first_name = google_data.get('given_name', '')
            
            # If user hasn't set initial details
            if not user_profile.has_set_initial_details:
                # Set first name from Google data if available
                if first_name:
                    user.first_name = first_name
                    user.save()
                return redirect('set-username')
            
            # For subsequent logins, redirect based on role
            return get_role_redirect(user_profile.role)
                
    except Exception as e:
        print(f"Error in google login handler: {str(e)}")
    
    return None

@login_required
def SetUsernameAfterGoogle(request):
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    # If setup already completed, redirect to appropriate dashboard
    if user_profile.has_set_initial_details:
        return get_role_redirect(user_profile.role)

    if request.method == "POST":
        username = request.POST.get('username').lower()
        role = request.POST.get('role')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if not all([username, role, password]):
            messages.error(request, "All fields are required")
            return redirect('set-username')

        if role not in ALLOWED_ROLES:
            messages.error(request, f"Invalid role selected: {role}")
            return redirect('set-username')
        
        if password != confirm_password:
            messages.error(request, "Passwords do not match")
            return redirect('set-username')
            
        password_check = check_password_strength(password)
        if password_check['strength'] != 'strong':
            messages.error(request, password_check['feedback'])
            return render(request, 'reset_password.html')

        try:
            # Check if username is unique
            if User.objects.filter(username=username).exclude(id=request.user.id).exists():
                messages.error(request, "Username already taken")
                return redirect('set-username')
            
            # Update user details
            request.user.username = username
            request.user.set_password(password)
            request.user.save()
            
            # Update profile
            user_profile.role = role
            user_profile.has_set_initial_details = True
            user_profile.is_google_account = True
            user_profile.manual_password_set = True
            user_profile.save()

            # Re-authenticate user
            user = authenticate(username=username, password=password)
            if user:
                login(request, user)

            messages.success(request, 'Profile setup completed successfully!')
            return get_role_redirect(role)
            
        except ValidationError as e:
            messages.error(request, str(e))
            return redirect('set-username')

    # For GET request - prepare the suggested username
    try:
        social_auth = request.user.social_auth.get(provider='google-oauth2')
        suggested_username = social_auth.extra_data.get('given_name', '')
        
        # If no given_name, try full name
        if not suggested_username:
            suggested_username = social_auth.extra_data.get('name', '').split()[0]
            
    except:
        # Fallback to email prefix only if no Google data available
        suggested_username = request.user.email.split('@')[0]

    context = {
        'suggested_username': suggested_username,
        'username_exists': User.objects.filter(username=suggested_username).exists()
    }
    return render(request, 'set_username.html', context)

@require_http_methods(["POST"])
def check_username(request):
    username = request.POST.get('username')
    User = get_user_model()
    
    # Basic validation
    if len(username) < 3:
        return JsonResponse({
            'available': False,
            'message': 'Username must be at least 3 characters long'
        })
        
    # Check if username exists
    is_available = not User.objects.filter(username=username).exists()
    
    return JsonResponse({
        'available': is_available,
        'message': 'Username is available' if is_available else 'Username is already taken'
    })

def check_password_strength(password):
    """Helper function to check password strength and enforce all requirements"""
    conditions = [
        {
            'check': lambda p: bool(re.search(r"[A-Z]", p)),
            'message': "Password should contain at least one uppercase letter"
        },
        {
            'check': lambda p: bool(re.search(r"[a-z]", p)),
            'message': "Password should contain at least one lowercase letter"
        },
        {
            'check': lambda p: bool(re.search(r"\d", p)),
            'message': "Password should contain at least one number"
        },
        {
            'check': lambda p: bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", p)),
            'message': "Password should contain at least one special character"
        },
        {
            'check': lambda p: len(p) >= 8,
            'message': "Password should be at least 8 characters long"
        }
    ]
    
    # Get all unmet conditions
    unmet_conditions = [
        condition['message'] 
        for condition in conditions 
        if not condition['check'](password)
    ]
    
    # Count how many conditions are met
    score = len(conditions) - len(unmet_conditions)
    
    # Get all feedback messages
    feedback_messages = unmet_conditions.copy()
    
    # Initialize breach warning
    breach_warning = None
    
    # Check for data breaches
    try:
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            count = next((int(count) for h, count in hashes if h == suffix), 0)
            
            if count > 0:
                breach_warning = f"Warning: This password has been exposed in {count} data breaches"
    except:
        pass
    
    # Determine password strength based only on conditions
    if score == len(conditions):  # All conditions met
        strength = 'strong'
    elif score >= len(conditions) - 1:  # At most one condition not met
        strength = 'medium'
    else:
        strength = 'weak'
    
    # Get the first feedback message if any exist
    primary_feedback = feedback_messages[0] if feedback_messages else breach_warning
    
    return {
        'score': score,
        'strength': strength,
        'feedback': primary_feedback,  # Primary feedback or breach warning
        'all_feedback': feedback_messages,  # Only requirement-related feedback
        'breach_warning': breach_warning,  # Separate breach warning
        'is_valid': strength == 'strong'  # Valid if all requirements are met, regardless of breaches
    }

@require_http_methods(["POST"])
def check_password_strength_view(request):
    """API endpoint to check password strength"""
    if request.method == "POST":
        password = request.POST.get('password', '')
        result = check_password_strength(password)
        return JsonResponse(result)
    return JsonResponse({'error': 'Invalid request method'}, status=400)

def LoginView(request):
    if request.method == "POST":
        username = request.POST.get("username").lower()
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is  None:
            try:
                user_obj = User.objects.get(email__iexact=username)
                user = authenticate(request, username=user_obj.username, password=password)
            except User.DoesNotExist:
                pass

        if user is not None:
            login(request, user)
            # Check if the user needs to set a username
            if not user.username:
                return redirect('set-username')
            return redirect('setup_2fa')
            
        else:
            messages.error(request, "Invalid login credentials")
            return redirect('login')
    return render(request, 'login.html')

@login_required
def setup_2fa(request):
    """Setup two-factor authentication for the user"""
    # Check if 2FA is already set up
    user_2fa, created = UserTwoFactor.objects.get_or_create(user=request.user)
    
    if not user_2fa.secret_key:
        # Generate a new secret key if not exists
        user_2fa.secret_key = pyotp.random_base32()[:16]
        user_2fa.save()
    
    # Generate QR code
    totp = pyotp.TOTP(user_2fa.secret_key)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(user_2fa.generate_totp_uri())
    qr.make(fit=True)
    
    # Create an in-memory image
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return render(request, 'setup_2fa.html', {
        'qr_code': qr_code_base64,
        'secret_key': user_2fa.secret_key
    })

@login_required
def verify_2fa(request):
    """Verify two-factor authentication code"""
    if request.method == 'POST':
        otp_code = request.POST.get('otp_code', '')
        
        try:
            user_2fa = UserTwoFactor.objects.get(user=request.user)
            
            # Verify the OTP
            totp = pyotp.TOTP(user_2fa.secret_key)
            if totp.verify(otp_code):
                # Enable 2FA for the user
                user_2fa.is_2fa_enabled = True
                user_2fa.save()
                
                messages.success(request, '2FA successfully enabled!')
                return redirect('home')
            else:
                messages.error(request, 'Invalid authentication code. Please try again.')
                # Generate new secret key and QR code on invalid attempt
                user_2fa.secret_key = pyotp.random_base32()[:16]  # Generate shorter key
                user_2fa.save()
                
                # Generate new QR code
                totp = pyotp.TOTP(user_2fa.secret_key)
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(user_2fa.generate_totp_uri())
                qr.make(fit=True)
                
                # Create QR code image
                img = qr.make_image(fill_color="black", back_color="white")
                buffered = io.BytesIO()
                img.save(buffered, format="PNG")
                qr_code_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
                
                return render(request, 'setup_2fa.html', {
                    'qr_code': qr_code_base64,
                    'secret_key': user_2fa.secret_key
                })
                
        except UserTwoFactor.DoesNotExist:
            messages.error(request, 'Two-factor authentication setup not found.')
            return redirect('setup_2fa')
    
    return render(request, 'verify_2fa.html')

def get_role_redirect(role):
    """Utility function to get redirect URL based on user role"""
    role_redirects = {
        'ADMIN': 'admin_dashboard',
        'CLIENT': 'client_dashboard',
        'USER': 'user_dashboard'
    }
    return redirect(role_redirects.get(role, 'set-username'))

@login_required
def admin_dashboard(request):
    return render(request, 'admin_dashboard.html')

@login_required
def client_dashboard(request):
    return render(request, 'client_dashboard.html')

@login_required
def user_dashboard(request):
    return render(request, 'user_dashboard.html')

def ForgotPassword(request):

    if request.method == "POST":
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)

            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            password_reset_url = reverse('reset-password', kwargs={'reset_id': new_password_reset.reset_id})

            full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'

            email_body = f'Reset your password using the link below:\n\n\n{full_password_reset_url}'
        
            email_message = EmailMessage(
                'Reset your password', # email subject
                email_body,
                settings.EMAIL_HOST_USER, # email sender
                [email] # email  receiver 
            )

            email_message.fail_silently = True
            email_message.send()

            return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)

        except User.DoesNotExist:
            messages.error(request, f"No user with email '{email}' found")
            return redirect('forgot-password')

    return render(request, 'forgot_password.html')

def PasswordResetSent(request, reset_id):

    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'password_reset_sent.html')
    else:
        # redirect to forgot password page if code does not exist
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

def ResetPassword(request, reset_id):
    try:
        password_reset_id = PasswordReset.objects.get(reset_id=reset_id)

        expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=10)
        if timezone.now() > expiration_time:
            password_reset_id.delete()
            messages.error(request, 'Reset link has expired')
            return redirect('forgot-password')

        if request.method == "POST":
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            # Check if passwords match
            if password != confirm_password:
                messages.error(request, 'Passwords do not match')
                return render(request, 'reset_password.html')

            # Check password strength
            password_check = check_password_strength(password)
            if password_check['strength'] != 'strong':
                messages.error(request, password_check['feedback'])
                return render(request, 'reset_password.html')
            
            # Save new password
            user = password_reset_id.user
            user.set_password(password)
            user.save()

            password_reset_id.delete()
            messages.success(request, 'Password reset successful. Please log in.')
            return redirect('login')

    except PasswordReset.DoesNotExist:
        messages.error(request, 'Invalid reset ID')
        return redirect('forgot-password')

    return render(request, 'reset_password.html')
@require_POST
def ajax_logout(request):
    """Handle AJAX logout requests"""
    try:
        logout(request)
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

def LogoutView(request):
    logout(request)
    return redirect('login')



#sorted according to wotkflow 18-12-2024