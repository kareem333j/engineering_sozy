from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.utils.timezone import now
from datetime import timedelta
from .serializers import (
    RegisterSerializer,
    ProfileSerializer,
    ProfileSerializerForMe,
    UpdateUserProfileSerializer,
    ProfileSerializerForUpdate,
    UserPermissionsSerializer,
    UserSerializerForAdmin
)
from .authentication import CookieJWTAuthentication
from .models import Profile, User
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate
from rest_framework import generics
from api.views import IsStaffOrSuperUser
from rest_framework.parsers import MultiPartParser, FormParser


def set_jwt_cookie(response, token_type, token_value, expires_in):
    """Helper function to set JWT cookies consistently"""
    response.set_cookie(
        key=f"{token_type}_token",
        value=token_value,
        httponly=True,
        secure=True,
        samesite="None",
        path="/",
        expires=now() + expires_in,
        max_age=int(expires_in.total_seconds())
    )
    return response


class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = User.objects.get(email=email)
            profile = Profile.objects.get(user=user)

            if profile.is_logged_in:
                return Response(
                    {"error": "هذا الحساب قيد الاستخدام حالياً من شخص آخر، لا يمكنك استخدامه."},
                    status=status.HTTP_403_FORBIDDEN
                )

        except (User.DoesNotExist, Profile.DoesNotExist):
            pass

        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            access_token = response.data.get("access")
            refresh_token = response.data.get("refresh")

            user = authenticate(request, email=email, password=password)

            if user is not None:
                profile = get_object_or_404(Profile, user=user)
                profile.is_logged_in = True
                profile.current_session_key = request.session.session_key
                
                new_device = self.get_device_info(request)
                devices = profile.devices
                if new_device not in devices:
                    devices.append(new_device)
                    profile.devices = devices
                
                profile.save()

            response = set_jwt_cookie(response, "access", access_token, timedelta(minutes=10))
            response = set_jwt_cookie(response, "refresh", refresh_token, timedelta(days=7))

            response.data.pop("access", None)
            response.data.pop("refresh", None)

        return response

    def get_device_info(self, request):
        """Extract device information from request"""
        return {
            "ip": request.META.get("REMOTE_ADDR", "Unknown IP"),
            "user_agent": request.headers.get("User-Agent", "Unknown Device"),
            "last_login": str(now())
        }


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get("refresh_token")

        if not refresh_token:
            return Response(
                {"error": "No refresh token found"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        try:
            RefreshToken(refresh_token).verify()
        except Exception as e:
            return Response(
                {"error": "Invalid refresh token: " + str(e)},
                status=status.HTTP_401_UNAUTHORIZED
            )

        request.data["refresh"] = refresh_token
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200 and "access" in response.data:
            response = set_jwt_cookie(
                response,
                "access",
                response.data["access"],
                timedelta(minutes=10)
            )
            response.data.pop("access")

        return response


class CustomUserCreate(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "User created successfully!"},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BlacklistTokenUpdateView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            refresh_token = request.COOKIES.get("refresh_token")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token not found"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            token = RefreshToken(refresh_token)
            token.blacklist()

            auth = CookieJWTAuthentication()
            user_auth_tuple = auth.authenticate(request)
            if user_auth_tuple is not None:
                user, _ = user_auth_tuple
                profile = get_object_or_404(Profile, user=user)
                profile.is_logged_in = False
                profile.current_session_key = None
                profile.save()

            response = Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_205_RESET_CONTENT
            )
            response.delete_cookie("access_token", path="/", samesite="None")
            response.delete_cookie("refresh_token", path="/", samesite="None")

            return response
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        auth = CookieJWTAuthentication()
        user_auth_tuple = auth.authenticate(request)
        if user_auth_tuple is not None:
            user, _ = user_auth_tuple
            profile = get_object_or_404(Profile, user=user)
            profile.is_logged_in = False
            profile.current_session_key = None
            profile.save()

        response = Response(
            {"message": "Logged out successfully"},
            status=status.HTTP_205_RESET_CONTENT
        )
        response.delete_cookie("access_token", path="/", samesite="None")
        response.delete_cookie("refresh_token", path="/", samesite="None")
        return response


class CheckAuthView(APIView):
    def get(self, request):
        auth = CookieJWTAuthentication()
        user_auth_tuple = auth.authenticate(request)

        if user_auth_tuple is None:
            return Response(
                {"authenticated": False},
                status=status.HTTP_401_UNAUTHORIZED
            )

        user, _ = user_auth_tuple
        profile = get_object_or_404(Profile, user=user)
        return Response({
            "authenticated": True,
            "user": {
                "id": user.id,
                "email": user.email,
                "is_superuser": user.is_superuser,
                "is_staff": user.is_staff,
                "profile": ProfileSerializer(profile, context={"request": request}).data
            }
        })


class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializerForMe
    queryset = Profile.objects.all()
    lookup_field = "profile_id"


class UpdateUserData(generics.UpdateAPIView):
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
        profile = self.get_object()
        if request.user.profile != profile:
            return Response(
                {"error": "You are not allowed to update this profile."},
                status=status.HTTP_403_FORBIDDEN
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
        profile.user.delete()
        return Response(
            {'detail': 'تم حذف المستخدم بنجاح.'},
            status=status.HTTP_204_NO_CONTENT
        )


class UsersList(generics.ListAPIView):
    permission_classes = [IsAuthenticated, IsStaffOrSuperUser]
    serializer_class = UserSerializerForAdmin

    def get_queryset(self):
        return User.objects.filter(profile__is_private=False)