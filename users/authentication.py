import logging
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.conf import settings
from django.shortcuts import get_object_or_404
from .models import Profile

logger = logging.getLogger(__name__)

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # 1. الحصول على الـ token من الكوكي
        cookie_name = settings.SIMPLE_JWT['AUTH_COOKIE']
        access_token = request.COOKIES.get(cookie_name)
        
        # 2. Fallback للـ header إذا لم يوجد في الكوكي
        if not access_token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith(('Bearer ', 'JWT ')):
                access_token = auth_header.split(' ')[1]
        
        if not access_token:
            return None

        try:
            # 3. التحقق من صحة الـ token
            validated_token = AccessToken(access_token)
            user = self.get_user(validated_token)
            
            # 4. التحقق من أن المستخدم مفعل
            if not user.is_active:
                raise AuthenticationFailed("User account is disabled")
                
            # 5. التحقق من حالة المستخدم في البروفايل
            profile = get_object_or_404(Profile, user=user)
            if not profile.is_logged_in:
                raise AuthenticationFailed("User is not logged in")
                
            # 6. التحقق من تطابق الجلسة (اختياري)
            if hasattr(profile, 'current_session_key'):
                if profile.current_session_key != request.session.session_key:
                    raise AuthenticationFailed("Session mismatch detected")
            
            return (user, validated_token)
            
        except (InvalidToken, TokenError) as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise AuthenticationFailed("Invalid or expired token")
        except Profile.DoesNotExist:
            logger.error(f"Profile not found for user {user.id}")
            raise AuthenticationFailed("User profile not found")
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}", exc_info=True)
            raise AuthenticationFailed("Authentication failed")