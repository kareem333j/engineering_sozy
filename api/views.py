from django.shortcuts import render, get_object_or_404
from rest_framework import generics
from .models import *
from .serializers import *
from rest_framework.permissions import BasePermission, AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status,mixins
from rest_framework.exceptions import PermissionDenied
from django.db.models import Count
from itertools import chain
from rest_framework.parsers import MultiPartParser, FormParser, FileUploadParser


# custom permissions
class IsSubscribed(BasePermission):
    def has_permission(self, request, view, obj):
        message = "you are not subscribed to this course"
        if request.user.is_authenticated:
            user = request.user
            print(user)
            course_subscription = get_object_or_404(
                SubscribeCourse, user=user, course=obj
            )
            return course_subscription.is_active or user.is_staff
        return False

class IsStaffOrSuperUser(BasePermission):
    message = "You don't have permission to perform this action."
    def has_permission(self, request, view):
        if not request.user or not (request.user.is_staff or request.user.is_superuser):
            raise PermissionDenied(self.message) 
        return True

# views
def home(request):
    return render(request, "home.html")


class CoursesList(generics.ListAPIView):
    serializer_class = CourseSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user.profile
        return Course.active_objects.active().filter(
            subscriber__user=user, subscriber__is_active=True
        )
        
class CoursesListOptions(generics.ListAPIView):
    serializer_class = CourseSerializerOptions
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user.profile
        return Course.active_objects.active().filter(
            subscriber__user=user, subscriber__is_active=True
        )
        
class VideosList(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = VideoSerializer
    lookup_field = "course_title"
    
    def get_queryset(self):
        user = self.request.user.profile
        course_pk = self.kwargs["course_title"]
        if user.user.is_superuser or user.user.is_staff:
            try:
                course = Course.objects.get(
                    title=course_pk,
                )
            except Course.DoesNotExist:
                if course_pk.isdigit():
                    try:
                        course = Course.objects.get(
                            id=course_pk,
                        )
                    except Course.DoesNotExist:
                        return Video.objects.none()
                else:
                    return Video.objects.none()
                
            return Video.objects.all().filter(course=course)
        else:
            try:
                course = Course.active_objects.get(
                    title=course_pk,
                    subscriber__user=user,
                    subscriber__is_active=True
                )
            except Course.DoesNotExist:
                if course_pk.isdigit():
                    try:
                        course = Course.active_objects.get(
                            id=course_pk,
                            subscriber__user=user,
                            subscriber__is_active=True
                        )
                    except Course.DoesNotExist:
                        return Video.active_objects.none()
                else:
                    return Video.active_objects.none()
                
            return Video.active_objects.active().filter(course=course)


class RetrieveVideo(generics.RetrieveAPIView):
    serializer_class = VideoSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        user = self.request.user.profile
        video_id = self.kwargs["pk"]
        
        if self.request.user.is_superuser or self.request.user.is_staff :
            video = get_object_or_404(Video, id=video_id)
        else:
            video = get_object_or_404(Video, id=video_id, is_active=True)
            course = video.course

            is_subscribed = SubscribeCourse.objects.filter(
                user=user, course=course, is_active=True
            ).exists()

            if not is_subscribed:
                raise PermissionDenied("ليس لديك الصلاحية لمشاهدة هذا الفيديو.")
        

        return video
    
class ToggleVideoLikeView(generics.UpdateAPIView):
    def update(self, request, *args, **kwargs):
        user = request.user.profile  
        video = get_object_or_404(Video, id=self.kwargs['video_id'])

        like, created = VideoLike.objects.get_or_create(user=user, video=video)

        if not created:
            like.delete() 
            return Response({'message': 'Like removed', 'likes_count': video.likes.count()}, status=status.HTTP_200_OK)

        return Response({'message': 'Like added', 'likes_count': video.likes.count()}, status=status.HTTP_201_CREATED)



class IncreaseVideoViews(generics.UpdateAPIView):
    queryset = VideoViews.objects.all()

    def update(self, request, *args, **kwargs):
        video_id = self.kwargs.get("video_id")
        video = get_object_or_404(Video, id=video_id)
        video_views, created = VideoViews.objects.get_or_create(video=video)

        client_ip = get_client_ip(request)
        
        if client_ip and client_ip not in video_views.views:
            video_views.views.append(client_ip)
            video_views.save()
        
        print(client_ip, video_views.views)

        return Response(
            {
                "message": "views updated successfully.!",
                "total_views": len(video_views.views),
            },
            status=status.HTTP_200_OK,
        )


# comments
class VideoCommentsView(generics.ListAPIView):
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        video_id = self.kwargs["pk"]
        video = get_object_or_404(Video, id=video_id)
        return VideoComment.active_objects.active().filter(
            video=video, parent__isnull=True   # parent__isnull = True -> return parent comments only not child comments
        )


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR", "0.0.0.0")
    return ip


class ToggleCommentLikeView(generics.UpdateAPIView):
    def update(self, request, *args, **kwargs):
        user = request.user.profile 
        comment = get_object_or_404(VideoComment, id=self.kwargs['comment_id'])

        like, created = CommentLike.objects.get_or_create(user=user, comment=comment)

        if not created:
            like.delete()
            return Response({'message': 'Like removed', 'likes_count': comment.likes.count()}, status=status.HTTP_200_OK)

        return Response({'message': 'Like added', 'likes_count': comment.likes.count()}, status=status.HTTP_201_CREATED)
                
class DeleteComment(generics.DestroyAPIView):
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]
    queryset = VideoComment.objects.all()

    def destroy(self, request, *args, **kwargs):
        user = request.user.profile 
        
        if user:
            comment = get_object_or_404(VideoComment, user=user, id=kwargs.get('pk'))
            return super().destroy(request, *args, **kwargs)
    
# create comments
class CreateCommentView(mixins.CreateModelMixin, generics.GenericAPIView):
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        video = get_object_or_404(Video, id=self.kwargs.get('video_id'))
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            serializer.save(user=request.user.profile, video=video)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class CreateReplyView(mixins.CreateModelMixin, generics.GenericAPIView):
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        parent_comment = get_object_or_404(VideoComment, id=self.kwargs.get('comment_id'), is_active=True)
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            serializer.save(user=request.user.profile, video=parent_comment.video, parent=parent_comment)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
    
# video recommendations
class RecommendedVideosAPIView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = RecommendedVideoSerializer

    def get_queryset(self):
        user = self.request.user.profile
        video_id = self.kwargs.get('pk')
        current_video = Video.active_objects.get(id=video_id)
        course = current_video.course

        # videos from current video's course (exclude) current video
        same_course_videos = Video.active_objects.filter(course=course).exclude(id=current_video.id)
        
        # videos from current video's course that have more likes
        popular_videos = same_course_videos.annotate(
            likes_count=Count('likes', distinct=True),  
            views_count=Count('views', distinct=True)  
        ).order_by('-likes_count', '-views_count')

        
        # videos from another courses that user subscribe in it
        subscribed_courses = SubscribeCourse.objects.filter(user=user, is_active=True).values_list('course', flat=True)
        other_course_videos = Video.active_objects.filter(course__in=subscribed_courses).exclude(course=course)
        
        # فيديوهات تفاعل معها طلاب لهم اهتمامات مشابهة
        liked_videos = VideoLike.objects.filter(user=user).values_list('video', flat=True)
        similar_users = VideoLike.objects.filter(video__in=liked_videos).exclude(user=user).values_list('user', flat=True)
        similar_videos = VideoLike.objects.filter(user__in=similar_users).values_list('video', flat=True)
        recommended_videos = Video.active_objects.filter(id__in=similar_videos).exclude(id=current_video.id)
        
        # collect all recommendations and remove duplicates
        final_recommendations = list(set(chain(same_course_videos, popular_videos, other_course_videos, recommended_videos)))[:20]

        
        return final_recommendations
    
    
# admin view
# admin -> course
class CoursesListAdmin(generics.ListAPIView):
    serializer_class = CourseSerializerAdmin
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    queryset = Course.objects.all()

class CoursesListAdminOptions(generics.ListAPIView):
    serializer_class = CourseSerializerOptions
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    queryset = Course.objects.all()
    
class AddCourse(generics.CreateAPIView):
    serializer_class = CourseSerializerAdmin
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    queryset = Course

class RetrieveUpdateDestroyCourse(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CourseSerializerAdmin
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    queryset = Course.objects.all()

# admin -> video
class AddVideo(generics.CreateAPIView):
    serializer_class = VideoSerializer
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    parser_classes = [MultiPartParser, FormParser]
    
    def create(self, request, *args, **kwargs):
        user = self.request.user.profile
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            video = serializer.save(author=user)
            if video:
                VideoViews.objects.create(video=video)
            else:
                video.delete()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
    
class UpdateVideo(generics.UpdateAPIView):
    serializer_class = VideoSerializer
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    parser_classes = [MultiPartParser, FormParser]
    queryset = Video.objects.all()
    
class DeleteVideo(generics.DestroyAPIView):
    serializer_class = VideoSerializer
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    queryset = Video.objects.all()
    
    
    
# admin -> subscription
class SubscriptionsList(generics.ListAPIView):
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    serializer_class = SubscribeSerializerAdmin
    queryset = SubscribeCourse.objects.all()
    
class SubscriptionActivationUpdate(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    serializer_class = SubscriptionActivationSerializer
    queryset = SubscribeCourse
    
class SubscriptionDelete(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    queryset = SubscribeCourse
    
class AddSubscription(generics.CreateAPIView):
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    serializer_class = AddSubscribeSerializerAdmin
    queryset = SubscribeCourse.objects.all()
    
class getAllUsersForAddSubscription(generics.ListAPIView):
    permission_classes = [IsAuthenticated, IsStaffOrSuperUser]
    serializer_class = ProfileSerializerSpecific
    queryset = Profile.objects.filter(user__is_superuser=False, user__is_staff=False)
    
class getAllCoursesForAddSubscription(generics.ListAPIView):
    permission_classes = [IsAuthenticated, IsStaffOrSuperUser]
    serializer_class = CourseSerializerOptions
    queryset = Course.objects.all()