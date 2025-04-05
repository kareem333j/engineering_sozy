from django.contrib.sessions.models import Session
from .models import Profile
from django.utils import timezone
from datetime import timedelta

class SingleSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                profile = Profile.objects.get(user=request.user)
                if profile.is_logged_in and profile.current_session_key:
                    try:
                        session = Session.objects.get(session_key=profile.current_session_key)
                        if session.expire_date < timezone.now():
                            profile.is_logged_in = False
                            profile.current_session_key = None
                            profile.save()
                    except Session.DoesNotExist:
                        profile.is_logged_in = False
                        profile.current_session_key = None
                        profile.save()
            except Profile.DoesNotExist:
                pass

        response = self.get_response(request)
        return response