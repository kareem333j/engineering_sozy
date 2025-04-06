from django.contrib.sessions.models import Session
from .models import Profile

def force_logout_user(user):
    try:
        profile = Profile.objects.get(user=user)
        profile.is_logged_in = False
        profile.current_session_key = None
        profile.save()
    except Profile.DoesNotExist:
        pass
