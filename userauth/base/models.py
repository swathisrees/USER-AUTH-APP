from django.contrib.auth.models import User
from django.db import models
import pyotp
import uuid

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=[
        ('USER', 'User'),
        ('ADMIN', 'Admin'),
        ('CLIENT', 'Client')
    ])
    google_id = models.CharField(max_length=255, null=True, blank=True)
    is_google_account = models.BooleanField(default=False)
    has_set_initial_details = models.BooleanField(default=False)  # Track if first-time setup is done
    manual_password_set = models.BooleanField(default=False)  # Track if manual password is set

class UserTwoFactor(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    secret_key = models.CharField(max_length=32)
    is_2fa_enabled = models.BooleanField(default=False)

    def generate_totp_uri(self):
        """Generate TOTP URI for QR code"""
        return pyotp.totp.TOTP(self.secret_key).provisioning_uri(
            name=self.user.username, 
            issuer_name='USERAUTH'
        )

class PasswordReset(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    reset_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_when = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Password reset for {self.user.username} at {self.created_when}"



#sorted according to wotkflow 18-12-2024