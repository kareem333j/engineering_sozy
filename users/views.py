from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.utils.timezone import now
from django.utils import timezone
import datetime
from .serializers import *
from rest_framework_simplejwt.views import TokenRefreshView
from .authentication import CookieJWTAuthentication
from .models import Profile
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate
from rest_framework import generics
from .models import User
from api.views import IsStaffOrSuperUser
from rest_framework.parsers import MultiPartParser, FormParser, FileUploadParser
from django.conf import settings
import json
import logging
from rest_framework.parsers import JSONParser
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from io import BytesIO
from .auth_utils import force_logout_user
import jwt
from rest_framework_simplejwt.settings import api_settings



class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = User.objects.get(email=email)
            profile = Profile.objects.get(user=user)

            if profile.is_logged_in:
                return Response(
                    {
                        "error": "هذا الحساب قيد الاستخدام حالياً من شخص آخر، لا يمكنك استخدامه."
                    },
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
                key="access_token",
                value=access_token,
                httponly=True,
                secure=True,
                samesite="None",
                path="/",
                expires=now() + datetime.timedelta(minutes=10),
            )

            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite="None",
                path="/",
                expires=now() + datetime.timedelta(days=7),
            )

            response.data.pop("access")
            response.data.pop("refresh")

        return response


logger = logging.getLogger(__name__)

class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get("refresh_token")

        if not refresh_token:
            logger.warning("Refresh token not found in cookies.")
            return Response(
                {"error": "Refresh token not found"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )

        try:
            # تحقق من صلاحية الـ refresh token قبل استخدامه
            token = RefreshToken(refresh_token)
            if token.payload.get('exp') < int(timezone.now().timestamp()):
                raise TokenError("Refresh token expired")

            data = {"refresh": refresh_token}
            stream = BytesIO(json.dumps(data).encode("utf-8"))
            parser = JSONParser()
            parsed_data = parser.parse(stream)
            request._full_data = parsed_data

            response = super().post(request, *args, **kwargs)

            if response.status_code == 200:
                access_token = response.data.get("access")
                if access_token:
                    response.set_cookie(
                        key="access_token",
                        value=access_token,
                        httponly=True,
                        secure=True,
                        samesite="None",
                        path="/",
                        expires=now() + datetime.timedelta(minutes=10),
                    )
                    response.data.pop("access", None)

            return response

        except (TokenError, InvalidToken) as e:
            logger.error(f"Refresh token error: {str(e)}")
            
            try:
                # token = RefreshToken(refresh_token)
                # user_id = token.payload.get('user_id')
                # print("Refresh token::::::::::", token)
                # print("user_id::::::::::", user_id)
                try:
                    payload = jwt.decode(
                        refresh_token,
                        settings.SECRET_KEY,
                        algorithms=[api_settings.ALGORITHM],
                        options={"verify_exp": False}  # نفك التوكن حتى لو منتهي
                    )
                    user_id = payload.get("user_id")
                    if user_id:
                        force_logout_user(User.objects.get(id=user_id))
                except Exception as decode_error:
                    logger.error(f"Couldn't decode token payload: {decode_error}")

                if user_id:
                    force_logout_user(User.objects.get(id=user_id))
            except Exception as e:
                logger.error(f"Error updating user status: {str(e)}")

            response = Response(
                {"error": "Refresh token expired or invalid, please login again."},
                status=status.HTTP_400_BAD_REQUEST,
            )
            response.delete_cookie(
                settings.SIMPLE_JWT["AUTH_COOKIE"],
                path="/",
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )
            response.delete_cookie(
                settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
                path="/",
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )
            return response

        except Exception as e:
            logger.error(f"Error during token refresh: {str(e)}", exc_info=True)
            try:
                token = RefreshToken(refresh_token)
                user_id = token.payload.get('user_id')
                if user_id:
                    force_logout_user(User.objects.get(id=user_id))
            except Exception as e:
                logger.error(f"Error updating user status: {str(e)}")
            
            response = Response(
                {"error": "An error occurred during token refresh"},
                status=status.HTTP_400_BAD_REQUEST,
            )
            response.delete_cookie(
                settings.SIMPLE_JWT["AUTH_COOKIE"],
                path="/",
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )
            response.delete_cookie(
                settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
                path="/",
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )
            return response



class CustomUserCreate(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        reg_serializer = RegisterSerializer(data=request.data)
        if reg_serializer.is_valid():
            new_user = reg_serializer.save()
            if new_user:
                return Response(
                    {"message": "User created successfully!"},
                    status=status.HTTP_201_CREATED,
                )
        return Response(reg_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BlacklistTokenUpdateView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            refresh_token = request.COOKIES.get("refresh_token")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token not found"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            token = RefreshToken(refresh_token)
            token.blacklist()

            auth = CookieJWTAuthentication()
            user_auth_tuple = auth.authenticate(request)
            if user_auth_tuple:
                user, _ = user_auth_tuple
                profile = get_object_or_404(Profile, user=user)
                profile.is_logged_in = False
                profile.current_session_key = None
                profile.save()

            response = Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_205_RESET_CONTENT,
            )
            response.delete_cookie(
                settings.SIMPLE_JWT["AUTH_COOKIE"],
                path="/",
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )
            response.delete_cookie(
                settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
                path="/",
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )


            return response
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)



class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            refresh_token = request.COOKIES.get("refresh_token")
            if refresh_token:
                try:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                except Exception:
                    pass

            # 2. Logout user from server session
            auth = CookieJWTAuthentication()
            user_auth_tuple = auth.authenticate(request)
            if user_auth_tuple:
                user, _ = user_auth_tuple
                profile = get_object_or_404(Profile, user=user)
                profile.is_logged_in = False
                profile.current_session_key = None
                profile.save()

            # 3. Clear cookies
            response = Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_200_OK,
            )
            response.delete_cookie(
                settings.SIMPLE_JWT["AUTH_COOKIE"],
                path="/",
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )
            response.delete_cookie(
                settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
                path="/",
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )

            return response

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class CheckAuthView(APIView):
    def get(self, request):
        auth = CookieJWTAuthentication()
        try:
            user_auth_tuple = auth.authenticate(request)
            
            if user_auth_tuple is None:
                refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
                if refresh_token:
                    try:
                        token = RefreshToken(refresh_token)
                        if token.payload.get('exp') < int(timezone.now().timestamp()):
                            user_id = token.payload.get('user_id')
                            if user_id:
                                force_logout_user(User.objects.get(id=user_id))
                    except Exception:
                        pass
                
                return Response(
                    {"authenticated": False}, 
                    status=status.HTTP_401_UNAUTHORIZED
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
        except Exception as e:
            logger.error(f"Error in CheckAuthView: {str(e)}")
            return Response(
                {"authenticated": False, "error": str(e)}, 
                status=status.HTTP_401_UNAUTHORIZED
            )

# class CheckAuthView(APIView):
#     def get(self, request):
#         auth = CookieJWTAuthentication()
#         user_auth_tuple = auth.authenticate(request)

#         if user_auth_tuple is None:
#             return Response(
#                 {"authenticated": False}, status=status.HTTP_401_UNAUTHORIZED
#             )

#         user, _ = user_auth_tuple
#         profile = get_object_or_404(Profile, user=user)
#         profile_data = ProfileSerializer(profile, context={"request": request}).data

#         return Response(
#             {
#                 "authenticated": True,
#                 "user": {
#                     "id": user.id,
#                     "email": user.email,
#                     "is_superuser": user.is_superuser,
#                     "is_staff": user.is_staff,
#                     "profile": profile_data,
#                 },
#             }
#         )


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
    
class SearchUsersList(generics.ListAPIView):
    permission_classes = [IsAuthenticated, IsStaffOrSuperUser]
    serializer_class = UserSerializerForAdmin

    def get_queryset(self):
        value = self.request.query_params.get('value', '').strip()
        queryset = User.objects.filter(profile__is_private=False)

        if value:
            queryset = queryset.filter(
                Q(profile__full_name__icontains=value) |
                Q(email__icontains=value) |
                Q(profile__profile_id__icontains=value)
            )

        return queryset
    
    
# reset passwords to all users from admin
class AdminResetUserPassword(APIView):
    permission_classes = [IsAuthenticated, IsStaffOrSuperUser]

    def post(self, request, profile_id):
        target_profile = get_object_or_404(Profile, profile_id=profile_id)
        target_user = target_profile.user

        if request.user.is_staff and not request.user.is_superuser and target_user.is_superuser:
            return Response({"error": "لا يمكنك تغيير كلمة مرور مدير النظام."},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = AdminResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            new_password = serializer.validated_data['password']
            target_user.set_password(new_password)
            target_user.save()
            return Response({"message": "تم تغيير كلمة المرور بنجاح."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)