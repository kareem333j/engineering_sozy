from django.urls import path
from .views import *

urlpatterns = [
    path('', home, name='home'),
    
    # course
    path('courses_list', CoursesList.as_view(), name='courses_list'),
    path('courses_list/options', CoursesListOptions.as_view(), name='courses_list_options'),
    path('courses_list/<str:course_title>/videos', VideosList.as_view(), name='videos_list'),
    
    # video
    path('video/<str:pk>', RetrieveVideo.as_view(), name='retrieve_video'),
    path('video/<str:pk>/recommendations', RecommendedVideosAPIView.as_view(), name='video_recommendations'),
    path('video/<str:video_id>/like', ToggleVideoLikeView.as_view(), name='video-like-toggle'),
    path('video/<str:video_id>/views', IncreaseVideoViews.as_view(), name='video_views'),
    path('video/<str:pk>/comments', VideoCommentsView.as_view(), name='video_comments'),
    path('videos/<int:video_id>/comments/', CreateCommentView.as_view(), name='create-comment'),
    path('comments/<int:comment_id>/replies/', CreateReplyView.as_view(), name='create-reply'),
    path('comments/<int:pk>/delete', DeleteComment.as_view(), name='delete_comment'),
    path('comment/<int:comment_id>/like', ToggleCommentLikeView.as_view(), name='comment-like-toggle'),
    
    # admin
    # admin -> course
    path('admin/courses_list', CoursesListAdmin.as_view(), name='courses_list_admin'),
    path('admin/courses_list/options', CoursesListAdminOptions.as_view(), name='courses_list_options_admin'),
    path('admin/courses/add', AddCourse.as_view(), name='add_course'),
    path('admin/courses/course/<int:pk>', RetrieveUpdateDestroyCourse.as_view(), name='get_course'),
    path('admin/courses/course/<int:pk>/edit', RetrieveUpdateDestroyCourse.as_view(), name='edit_course'),
    path('admin/courses/course/<int:pk>/delete', RetrieveUpdateDestroyCourse.as_view(), name='delete_course'),
    # admin -> subscription
    path('admin/courses/subscriptions/', SubscriptionsList.as_view(),name='subscriptions'),
    path('admin/courses/subscriptions/allUsers', getAllUsersForAddSubscription.as_view(),name='subscriptions_users'),
    path('admin/courses/subscriptions/allCourses', getAllCoursesForAddSubscription.as_view(),name='subscriptions_courses'),
    path('admin/courses/subscriptions/add/', AddSubscription.as_view(),name='add-subscription'),
    path('admin/courses/subscriptions/<int:pk>/update/', SubscriptionActivationUpdate.as_view(),name='subscription-activation'),
    path('admin/courses/subscriptions/<int:pk>/delete/', SubscriptionDelete.as_view(),name='delete-subscription'),
    
    # admin -> video
    path('admin/video/add', AddVideo.as_view(), name='add_video'),
    path('admin/video/<str:pk>/edit', UpdateVideo.as_view(), name='update_video'),
    path('admin/video/<str:pk>/delete', DeleteVideo.as_view(), name='delete_video'),
]