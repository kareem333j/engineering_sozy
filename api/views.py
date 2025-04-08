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
from django.db.models import Q


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
            video=video, parent__isnull=True 
        )


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR", "0.0.0.0")
    return ip


class ToggleCommentLikeView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    def update(self, request, *args, **kwargs):
        user = request.user.profile
        comment = get_object_or_404(VideoComment, id=self.kwargs['comment_id'])

        existing_like = CommentLike.objects.filter(user=user, comment=comment).first()

        if existing_like:
            existing_like.delete()
            message = 'Like removed'
        else:
            CommentLike.objects.create(user=user, comment=comment)
            message = 'Like added'

        likes_count = comment.likes.count()

        return Response({'message': message, 'likes_count': likes_count}, status=status.HTTP_200_OK)

                
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
        if self.request.user.is_superuser or self.request.user.is_staff:
            current_video = Video.objects.get(id=video_id)
            course = current_video.course
            same_course_videos = Video.objects.filter(course=course)
            final_recommendations = same_course_videos.order_by('priority')
            
            return final_recommendations
        else:
            current_video = Video.active_objects.active().get(id=video_id)
            course = current_video.course
            same_course_videos = Video.active_objects.active().filter(course=course)
            final_recommendations = same_course_videos.order_by('priority')
            
            return final_recommendations
    
    
# admin view
# admin -> course
class CoursesListAdmin(generics.ListAPIView):
    serializer_class = CourseSerializerAdmin
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    queryset = Course.objects.all()
    
class SearchCoursesForAdmin(generics.ListAPIView):
    serializer_class = CourseSerializerAdmin
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    def get_queryset(self):
        value = self.request.query_params.get('value', '').strip()
        if not value:
            return Course.objects.all()
        
        return Course.objects.filter(
            Q(title__icontains=value)
        )

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
    
    def create(self, request, *args, **kwargs):
        user = self.request.user.profile
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            priority = serializer.validated_data.get('priority')
            course = serializer.validated_data.get('course')

            course_videos = Video.objects.filter(course=course)
            max_priority = course_videos.aggregate(models.Max('priority'))['priority__max'] or 0

            if priority > max_priority + 1:
                serializer.validated_data['priority'] = max_priority + 1
                priority = max_priority + 1

            existing_video = course_videos.filter(priority=priority).first()
            if existing_video:
                existing_video.priority = max_priority + 1
                existing_video.save()

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
    permission_classes = [IsAuthenticated, IsStaffOrSuperUser]
    queryset = Video.objects.all()

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        old_priority = instance.priority
        old_course = instance.course

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            new_priority = serializer.validated_data.get('priority', old_priority)
            new_course = serializer.validated_data.get('course', old_course)

            course_videos = Video.objects.filter(course=new_course).exclude(id=instance.id)
            max_priority = course_videos.aggregate(models.Max('priority'))['priority__max'] or 0

            # ✅ لو الأولوية أكبر من max الحالي، نحطها في الآخر
            if new_priority > max_priority + 1:
                serializer.validated_data['priority'] = max_priority + 1
                new_priority = max_priority + 1

            # ✅ لو فيه فيديو بنفس الأولوية، نعمل swap
            if (new_priority != old_priority) or (new_course != old_course):
                conflicting_video = course_videos.filter(priority=new_priority).first()

                if conflicting_video:
                    conflicting_video.priority = old_priority
                    conflicting_video.save()

            video = serializer.save()

            return Response(VideoSerializer(video, context=self.get_serializer_context()).data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    
class DeleteVideo(generics.DestroyAPIView):
    serializer_class = VideoSerializer
    permission_classes = [IsAuthenticated, IsStaffOrSuperUser]
    queryset = Video.objects.all()

    def perform_destroy(self, instance):
        course = instance.course
        deleted_priority = instance.priority
        instance.delete()

        videos_to_shift = Video.objects.filter(
            course=course,
            priority__gt=deleted_priority
        ).order_by('priority')

        for video in videos_to_shift:
            video.priority -= 1
            video.save()

    
class SwapVideoPriorityView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated, IsStaffOrSuperUser]  

    def post(self, request, *args, **kwargs):
        video_id = kwargs.get('pk')
        direction = request.data.get('direction')  

        if direction not in ['up', 'down']:
            return Response({'detail': 'Invalid direction.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            video = Video.objects.get(id=video_id)
        except Video.DoesNotExist:
            return Response({'detail': 'Video not found'}, status=status.HTTP_404_NOT_FOUND)

        current_priority = video.priority
        target_priority = current_priority - 1 if direction == 'up' else current_priority + 1

        try:
            swap_video = Video.objects.get(course=video.course, priority=target_priority)
        except Video.DoesNotExist:
            return Response({'detail': 'No video to swap with'}, status=status.HTTP_400_BAD_REQUEST)

        video.priority, swap_video.priority = swap_video.priority, video.priority
        video.save()
        swap_video.save()

        return Response({'detail': 'Swapped successfully'}, status=status.HTTP_200_OK) 
    
    
    
# admin -> subscription
class SubscriptionsList(generics.ListAPIView):
    permission_classes = [IsAuthenticated,IsStaffOrSuperUser]
    serializer_class = SubscribeSerializerAdmin
    queryset = SubscribeCourse.objects.all()

class SearchSubscriptions(generics.ListAPIView):
    permission_classes = [IsAuthenticated, IsStaffOrSuperUser]
    serializer_class = SubscribeSerializerAdmin

    def get_queryset(self):
        value = self.request.query_params.get('value', '').strip()
        if not value:
            return SubscribeCourse.objects.all()
        
        return SubscribeCourse.objects.filter(
            Q(user__full_name__icontains=value) |
            Q(user__user__email__icontains=value) |
            Q(user__profile_id__icontains=value)
        )
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