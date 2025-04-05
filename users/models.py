from django.db import models
import uuid
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.conf import settings

class Website(models.Model):
    name = models.CharField(max_length=300, null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name

class ActiveObjectsQuerySet(models.QuerySet):
    def active(self):
        return self.filter(is_active=True)

class CustomAccountManager(BaseUserManager):
    def create_user(self, email, password, user_name=None, **other_fields):
        if not email:
            raise ValueError(_('You must provide an email address'))
        if not password:
            raise ValueError(_('You must provide a password')) 

        email = self.normalize_email(email)

        if not user_name:
            user_name = self.generate_unique_username()

        user = self.model(email=email, user_name=user_name, **other_fields)
        user.set_password(password)  # تأكد من تعيين الباسورد
        user.save()

        Profile.objects.create(user=user)

        return user
    
    def create_superuser(self, email, password, user_name=None, **other_fields):
        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_superuser', True)

        if other_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True'))
        if other_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True'))

        return self.create_user(email, user_name=user_name, password=password, **other_fields)
    
    def generate_unique_username(self):
        while True:
            user_name = f"user_{uuid.uuid4().hex[:8]}"
            if not User.objects.filter(user_name=user_name).exists():
                return user_name


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(_('email address'), unique=True)
    user_name = models.CharField(max_length=150, unique=True, blank=True, null=True)
    start_date = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    
    objects = CustomAccountManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.user_name if self.user_name else self.email
    
class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    profile_id = models.CharField(max_length=20, unique=True, blank=True, null=True) 
    full_name = models.CharField(max_length=500, blank=False, null=False) 
    bio = models.TextField(blank=True, null=True)
    avatar = models.ImageField(blank=True, null=True)
    devices = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    is_private = models.BooleanField(default=False)
    is_logged_in = models.BooleanField(default=False)
    current_session_key = models.CharField(max_length=40, blank=True, null=True)
    
    objects = models.Manager()
    active_objects = ActiveObjectsQuerySet.as_manager()

    def save(self, *args, **kwargs):
        if not self.profile_id:
            self.profile_id = f"profile_{uuid.uuid4().hex[:8]}"  
        super().save(*args, **kwargs)

    def __str__(self):
        return self.full_name if self.full_name else self.user.user_name if self.user.user_name else self.user.email