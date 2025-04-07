from django.urls import path
from .views import *
from rest_framework_simplejwt.views import TokenRefreshView

app_name = "users"

urlpatterns = [
    path("token/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"), 
    path("token/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh"),
    
    # user
    path('profile/<str:profile_id>/', UserProfileView.as_view(), name='user-profile'),
    path('profile/<str:profile_id>/update/', UpdateUserData.as_view(), name='user-profile-update'),
    path('profile/<str:profile_id>/permissions/update/', UpdateUserPermissions.as_view(), name='user-update-permissions'),
    path('profile/<str:profile_id>/change-avatar/', UpdateUserAvatar.as_view(), name='user-profile-update-avatar'),
    path('profile/<str:profile_id>/delete/', DeleteUser   .as_view(), name='delete-user'),
    
    # admin
    path("all", UsersList.as_view(), name="all_users"),
    path("all/search/", SearchUsersList.as_view(), name="search_users"),

    # auth
    path("register/", CustomUserCreate.as_view(), name="create_user"),
    path("admin/reset-password/<str:profile_id>/", AdminResetUserPassword.as_view(), name="admin-reset-password"),
    path("logout/blacklist/", BlacklistTokenUpdateView.as_view(), name="blacklist"),
    path("logout/", LogoutView.as_view(), name="logout"), 
    path("check-auth/", CheckAuthView.as_view(), name="check_auth"),
]
