from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Profile, User
import logging

logger = logging.getLogger(__name__)

def force_logout_user(user_id):
    try:
        profile = Profile.objects.get(user__id=user_id)
        if profile.is_logged_in:
            profile.is_logged_in = False
            profile.current_session_key = None
            profile.save()
            logger.info(f"User {user_id} automatically logged out due to token expiry")
            return True
    except Profile.DoesNotExist:
        logger.warning(f"Profile not found for user {user_id}")
    except Exception as e:
        logger.error(f"Error in force_logout_user: {str(e)}")
    return False

def check_and_handle_expired_token(request):
    refresh_token = request.COOKIES.get('refresh_token')
    if refresh_token:
        try:
            token = RefreshToken(refresh_token)
            if token.payload.get('exp') < int(timezone.now().timestamp()):
                user_id = token.payload.get('user_id')
                if user_id:
                    return force_logout_user(user_id)
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
    return False