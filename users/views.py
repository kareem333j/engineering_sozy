from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView
from django.utils.timezone import now
import datetime
from .serializers import *
from .authentication import CookieJWTAuthentication
from .models import Profile
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate
from rest_framework import generics
from .models import User
from api.views import IsStaffOrSuperUser
from rest_framework.parsers import MultiPartParser, FormParser, FileUploadParser
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = User.objects.get(email=email)
            profile = Profile.objects.get(user=user)

            if profile.is_logged_in:
                logger.warning(f"User {user.id} attempted login while already logged in")
                return Response(
                    {"error": "هذا الحساب قيد الاستخدام حالياً من شخص آخر، لا يمكنك استخدامه."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        except (User.DoesNotExist, Profile.DoesNotExist):
            pass  

        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            access_token = response.data["access"]
            refresh_token = response.data["refresh"]

            user = authenticate(request, email=email, password=password)

            if user is not None:
                profile = get_object_or_404(Profile, user=user)
                profile.is_logged_in = True
                profile.current_session_key = request.session.session_key
                profile.save()

                new_device = get_device_info(request)
                devices = profile.devices
                if new_device not in devices:
                    devices.append(new_device)
                    profile.devices = devices
                    profile.save()

            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                value=access_token,
                httponly=True,
                secure=True,
                samesite="None",
                path="/",
                expires=now() + datetime.timedelta(minutes=10),
            )

            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite="None",
                path="/",
                expires=now() + datetime.timedelta(days=7),
            )

            response.data.pop("access")
            response.data.pop("refresh")

            logger.info(f"User {user.id} logged in successfully")

        return response


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])

        if not refresh_token:
            logger.warning("Refresh token not found in cookies")
            return Response(
                {"error": "No refresh token found"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )

        request.data["refresh"] = refresh_token
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            access_token = response.data.get("access")
            if access_token:
                response.set_cookie(
                    key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                    value=access_token,
                    httponly=True,
                    secure=True,
                    samesite="None",
                    path="/",
                    expires=now() + datetime.timedelta(minutes=10),
                )
                logger.info("Token refreshed successfully")

        return response


class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            # 1. Blacklist the refresh token
            refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            if refresh_token:
                try:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                    logger.info("Refresh token blacklisted successfully")
                except Exception as e:
                    logger.warning(f"Failed to blacklist token: {str(e)}")

            # 2. Update user profile
            auth = CookieJWTAuthentication()
            user_auth_tuple = auth.authenticate(request)
            if user_auth_tuple:
                user, _ = user_auth_tuple
                profile = get_object_or_404(Profile, user=user)
                profile.is_logged_in = False
                profile.current_session_key = None
                profile.save()
                logger.info(f"User {user.id} logged out successfully")

            # 3. Clear cookies
            response = Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_200_OK,
            )
            response.delete_cookie(
                settings.SIMPLE_JWT['AUTH_COOKIE'],
                path="/",
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
            )
            response.delete_cookie(
                settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                path="/",
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
            )

            return response

        except Exception as e:
            logger.error(f"Logout error: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred during logout"},
                status=status.HTTP_400_BAD_REQUEST
            )


class CheckAuthView(APIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            profile = get_object_or_404(Profile, user=user)
            profile_data = ProfileSerializer(profile, context={"request": request}).data

            logger.info(f"Authentication check for user {user.id}")
            
            return Response({
                "authenticated": True,
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "is_superuser": user.is_superuser,
                    "is_staff": user.is_staff,
                    "profile": profile_data,
                },
            })
        except Exception as e:
            logger.error(f"CheckAuth error: {str(e)}", exc_info=True)
            return Response(
                {"authenticated": False}, 
                status=status.HTTP_401_UNAUTHORIZED
            )




class CheckAuthView(APIView):
    def get(self, request):
        auth = CookieJWTAuthentication()
        user_auth_tuple = auth.authenticate(request)

        if user_auth_tuple is None:
            return Response(
                {"authenticated": False}, status=status.HTTP_401_UNAUTHORIZED
            )

        user, _ = user_auth_tuple
        profile = get_object_or_404(Profile, user=user)
        profile_data = ProfileSerializer(profile, context={"request": request}).data

        return Response(
            {
                "authenticated": True,
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "is_superuser": user.is_superuser,
                    "is_staff": user.is_staff,
                    "profile": profile_data,
                },
            }
        )


class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializerForMe
    queryset = Profile.objects.all()
    lookup_field = "profile_id"
    
class UpdateUserData(generics.UpdateAPIView):
    queryset = Profile.objects.all()
    serializer_class = UpdateUserProfileSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'profile_id'

    def get_queryset(self):
        return Profile.objects.filter(user=self.request.user)
    
class UpdateUserAvatar(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializerForUpdate
    queryset = Profile.objects.all()
    parser_classes = [MultiPartParser, FormParser]
    lookup_field = "profile_id"
    
    def update(self, request, *args, **kwargs):
        current_user_profile = request.user.profile  
        profile = self.get_object()
        
        if current_user_profile != profile:
            return Response(
                {"error": "You are not allowed to update this profile."},
                status=status.HTTP_403_FORBIDDEN,
            )
            
        return super().update(request, *args, **kwargs)
        
class UpdateUserPermissions(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated, IsStaffOrSuperUser]
    serializer_class = UserPermissionsSerializer
    lookup_field = 'profile_id'
    queryset = Profile.objects.select_related('user').all()

class DeleteUser(APIView):
    def delete(self, request, profile_id):
        profile = get_object_or_404(Profile, profile_id=profile_id)
        user = profile.user
        user.delete()
        return Response({'detail': 'تم حذف المستخدم بنجاح.'}, status=status.HTTP_204_NO_CONTENT)

# get device information
def get_device_info(request):
    user_agent = request.headers.get(
        "User-Agent", "Unknown Device"
    )
    ip = request.META.get("REMOTE_ADDR", "Unknown IP") 

    return {
        "ip": ip,
        "user_agent": user_agent,
        "last_login": str(now()),
    }



# users for admin users 
class UsersList(generics.ListAPIView):
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    serializer_class = UserSerializerForAdmin
    queryset = User.objects.all()
    
    def get_queryset(self):
        return User.objects.filter(profile__is_private = False)