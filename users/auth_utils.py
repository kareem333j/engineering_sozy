from django.contrib.sessions.models import Session
from .models import Profile

def force_logout_user(user):
    try:
        profile = Profile.objects.get(user=user)
        profile.is_logged_in = False
        profile.current_session_key = None
        profile.save()
        
        # حذف الجلسة إذا كانت موجودة
        if profile.current_session_key:
            try:
                Session.objects.get(session_key=profile.current_session_key).delete()
            except Session.DoesNotExist:
                pass
    except Profile.DoesNotExist:
        pass