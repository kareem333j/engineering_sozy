import logging
import jwt
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.settings import api_settings

from .models import Profile, User
from .auth_utils import force_logout_user

logger = logging.getLogger(__name__)

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        cookie_name = settings.SIMPLE_JWT['AUTH_COOKIE']
        access_token = request.COOKIES.get(cookie_name)

        if not access_token:
            # جرّب تاخد التوكن من الهيدر لو مش موجود في الكوكيز
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith(('Bearer ', 'JWT ')):
                access_token = auth_header.split(' ')[1]

        if not access_token:
            # لو مفيش access token، شيك على refresh token
            refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            if refresh_token:
                try:
                    payload = jwt.decode(
                        refresh_token,
                        settings.SECRET_KEY,
                        algorithms=[api_settings.ALGORITHM],
                        options={"verify_exp": False}
                    )
                    if payload.get("exp", 0) < int(timezone.now().timestamp()):
                        user_id = payload.get("user_id")
                        if user_id:
                            force_logout_user(User.objects.get(id=user_id))
                except Exception as e:
                    logger.warning(f"Failed to decode expired refresh token: {str(e)}")
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
                        payload = jwt.decode(
                            refresh_token,
                            settings.SECRET_KEY,
                            algorithms=[api_settings.ALGORITHM],
                            options={"verify_exp": False}
                        )
                        if payload.get("exp", 0) < int(timezone.now().timestamp()):
                            user_id = payload.get("user_id")
                            if user_id:
                                force_logout_user(User.objects.get(id=user_id))
                    except Exception as e:
                        logger.warning(f"Failed to decode expired refresh token: {str(e)}")
            except Exception as inner_e:
                logger.warning(f"Failed to auto-logout using refresh token: {str(inner_e)}")
            raise AuthenticationFailed("Invalid or expired token")

        except Profile.DoesNotExist:
            logger.error(f"Profile not found for user {user.id}")
            raise AuthenticationFailed("User profile not found")

        except Exception as e:
            logger.error(f"Authentication error: {str(e)}", exc_info=True)
            raise AuthenticationFailed("Authentication failed")
