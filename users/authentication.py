import logging
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.conf import settings
from django.shortcuts import get_object_or_404
from .models import Profile
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from .auth_utils import force_logout_user
from .models import User

logger = logging.getLogger(__name__)

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        cookie_name = settings.SIMPLE_JWT['AUTH_COOKIE']
        access_token = request.COOKIES.get(cookie_name)
        
        if not access_token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith(('Bearer ', 'JWT ')):
                access_token = auth_header.split(' ')[1]
        
        if not access_token:
            # إذا لم يكن هناك access token، نتحقق من وجود refresh token
            refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            if refresh_token:
                try:
                    token = RefreshToken(refresh_token)
                    if token.payload.get('exp') < int(timezone.now().timestamp()):
                        # إذا كان الـ refresh token منتهي الصلاحية
                        user_id = token.payload.get('user_id')
                        if user_id:
                            force_logout_user(User.objects.get(id=user_id))
                except (InvalidToken, TokenError):
                    pass
            return None

        try:
            validated_token = AccessToken(access_token)
            user = self.get_user(validated_token)
            
            if not user.is_active:
                raise AuthenticationFailed("User account is disabled")
                
            profile = get_object_or_404(Profile, user=user)
            if not profile.is_logged_in:
                raise AuthenticationFailed("User is not logged in")
                
            if hasattr(profile, 'current_session_key'):
                if profile.current_session_key != request.session.session_key:
                    raise AuthenticationFailed("Session mismatch detected")
            
            return (user, validated_token)
            
        except (InvalidToken, TokenError) as e:
            logger.warning(f"Invalid token: {str(e)}")
            try:
                refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
                if refresh_token:
                    try:
                        token = RefreshToken(refresh_token)
                        user_id = token.payload.get('user_id')
                        if user_id:
                            force_logout_user(User.objects.get(id=user_id))
                    except Exception:
                        pass
            except Exception as inner_e:
                logger.warning(f"Failed to auto-logout using refresh token: {str(inner_e)}")
            raise AuthenticationFailed("Invalid or expired token")
        except Profile.DoesNotExist:
            logger.error(f"Profile not found for user {user.id}")
            raise AuthenticationFailed("User profile not found")
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}", exc_info=True)
            raise AuthenticationFailed("Authentication failed")