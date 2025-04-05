from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        access_token = request.COOKIES.get("access_token")  

        if not access_token:
            return None 

        try:
            validated_token = AccessToken(access_token) 
        except Exception:
            raise AuthenticationFailed("Invalid or expired token.")

        return self.get_user(validated_token), validated_token
