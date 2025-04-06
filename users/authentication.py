import logging
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.conf import settings
from django.shortcuts import get_object_or_404
from .models import Profile
from django.utils import timezone

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
            # إذا لم يكن هناك token، نتحقق من وجود refresh token
            refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            if refresh_token:
                try:
                    # إذا كان هناك refresh token منتهي الصلاحية، نقوم بتسجيل الخروج
                    token = AccessToken(refresh_token)
                    user = self.get_user(token)
                    profile = get_object_or_404(Profile, user=user)
                    profile.is_logged_in = False
                    profile.current_session_key = None
                    profile.save()
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
            # عند فشل المصادقة، نقوم بتسجيل الخروج
            try:
                refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
                if refresh_token:
                    token = AccessToken(refresh_token)
                    user = self.get_user(token)
                    profile = get_object_or_404(Profile, user=user)
                    profile.is_logged_in = False
                    profile.current_session_key = None
                    profile.save()
            except Exception:
                pass
            raise AuthenticationFailed("Invalid or expired token")
        except Profile.DoesNotExist:
            logger.error(f"Profile not found for user {user.id}")
            raise AuthenticationFailed("User profile not found")
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}", exc_info=True)
            raise AuthenticationFailed("Authentication failed")