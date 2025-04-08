from rest_framework import serializers
from .models import *
from users.serializers import ProfileSerializerSpecific

class VideoViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = VideoViews
        fields = ('views',)

class VideoSerializer(serializers.ModelSerializer):
    author = ProfileSerializerSpecific(read_only=True)
    more_info = VideoViewSerializer(source='views',read_only=True)
    likes_count = serializers.SerializerMethodField()
    is_liked_by_user = serializers.SerializerMethodField()
    course_title = serializers.CharField(source='course.title',read_only=True)
    cover = serializers.SerializerMethodField()
    
    class Meta:
        model = Video
        fields = ['id','course', 'title', 'priority','course_title', 'description', 'embed_code','is_active', 'cover', 'created_dt','update_dt','author','more_info','likes_count','is_liked_by_user']
        
    def get_likes_count(self, obj):
        return obj.likes.count()
    
    def get_is_liked_by_user(self, obj):
        request = self.context.get('request', None)
        if request and request.user.is_authenticated:
            return obj.likes.filter(user=request.user.profile).exists()
        return False
    
    def get_cover(self, obj):
        request = self.context.get("request")
        if obj.cover:  
            return request.build_absolute_uri(obj.cover.url) if request else obj.cover.url
        return None 

class RecommendedVideoSerializer(serializers.ModelSerializer):
    author = serializers.CharField(source='author.full_name',read_only=True)
    course_name = serializers.CharField(source='course.title',read_only=True)
    more_info = VideoViewSerializer(source='views', read_only=True)
    likes_count = serializers.SerializerMethodField()
    cover = serializers.SerializerMethodField()
    
    class Meta:
        model = Video
        fields = ['id', 'title', 'priority', 'description', 'cover','course_name', 'created_dt', 'author', 'more_info', 'likes_count']
        
    def get_likes_count(self, obj):
        return obj.likes.count()
    
    def get_cover(self, obj):
        request = self.context.get("request")
        if obj.cover:  
            return request.build_absolute_uri(obj.cover.url) if request else obj.cover.url
        return None 

class CourseSerializer(serializers.ModelSerializer):
    videos = serializers.SerializerMethodField()

    class Meta:
        model = Course
        fields = ('id', 'title','cover', 'description', 'created_dt', 'update_dt','videos')
        
    def get_videos(self, obj):
        active_videos = obj.videos.filter(is_active=True) 
        return VideoSerializer(active_videos, many=True,context=self.context).data

class SubscribeSerializer(serializers.ModelSerializer):
    user = ProfileSerializerSpecific(read_only=True)
    class Meta:
        model = SubscribeCourse
        fields = ('id', 'user','course', 'is_active', 'created_dt')
        
class SubscribeSerializerAdmin(serializers.ModelSerializer):
    user = ProfileSerializerSpecific(read_only=True)
    course = serializers.CharField(source='course.title',read_only=True)
    email = serializers.CharField(source='user.user.email',read_only=True)
    class Meta:
        model = SubscribeCourse
        fields = ('id', 'email','user','course', 'is_active', 'created_dt')
        
class AddSubscribeSerializerAdmin(serializers.ModelSerializer):
    profile_id = serializers.CharField(write_only=True)
    class Meta:
        model = SubscribeCourse
        fields = ('profile_id','course', 'is_active')
        
    def create(self, validated_data):
        profile_id = validated_data.pop('profile_id')
        course = validated_data.get('course')
        try:
            profile = Profile.objects.get(profile_id=profile_id)
        except Profile.DoesNotExist:
            raise serializers.ValidationError({'profile_id': 'البروفايل غير موجود'})
        
        if SubscribeCourse.objects.filter(user=profile, course=course).exists():
            raise serializers.ValidationError({'detail': 'المستخدم مشترك بالفعل في هذا الكورس.'})

        subscription = SubscribeCourse.objects.create(user=profile, **validated_data)
        return subscription

class CourseSerializerAdmin(serializers.ModelSerializer):
    videos = VideoSerializer(many=True, read_only=True)
    subscribers = SubscribeSerializer(source='subscriber',many=True, read_only=True)
    
    class Meta:
        model = Course
        fields = ('id', 'title','is_active','cover', 'description', 'created_dt', 'update_dt','videos','subscribers')

 
class CourseSerializerOptions(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = ('id', 'title','description', 'created_dt', 'update_dt')


# comment serializers
class ReplySerializer(serializers.ModelSerializer):
    author = ProfileSerializerSpecific(source='user',read_only=True)
    replies = serializers.SerializerMethodField()
    total_replies = serializers.SerializerMethodField()
    likes_count = serializers.SerializerMethodField()  
    is_liked_by_user = serializers.SerializerMethodField()

    class Meta:
        model = VideoComment
        fields = ['id', 'author', 'content', 'created_dt','replies','total_replies','likes_count','is_liked_by_user']
        
    def get_replies(self, obj):
        replies = obj.replies.filter(is_active=True)
        return ReplySerializer(replies, many=True, context=self.context).data
    
    def get_total_replies(self, obj):
        def count_replies(comment):
            replies = comment.replies.filter(is_active=True)
            total = replies.count()
            for reply in replies:
                total += count_replies(reply)
            return total

        return count_replies(obj)
    
    def get_likes_count(self, obj):
        return obj.likes.count()  # ✅ إرجاع عدد اللايكات

    def get_is_liked_by_user(self, obj):
        request = self.context.get('request', None)
        if request and request.user.is_authenticated:
            return obj.likes.filter(user=request.user.profile).exists()
        return False

class CommentSerializer(serializers.ModelSerializer):
    # user_name = serializers.CharField(source="user.user.user_name", read_only=True)
    
    author = ProfileSerializerSpecific(source='user',read_only=True)
    replies = ReplySerializer(many=True, read_only=True)
    total_comments = serializers.SerializerMethodField()
    total_replies = serializers.SerializerMethodField()
    likes_count = serializers.SerializerMethodField()  
    is_liked_by_user = serializers.SerializerMethodField()

    class Meta:
        model = VideoComment
        fields = ['id', 'author', 'content', 'created_dt', 'replies','total_comments','total_replies','likes_count','is_liked_by_user']
        
    def get_total_comments(self, obj):
        return VideoComment.objects.filter(video=obj.video).count()
    
    def get_replies_count(self, obj):
        return obj.replies.filter(is_active=True).count()
    
    def get_total_replies(self, obj):
        def count_replies(comment):
            replies = comment.replies.filter(is_active=True)
            total = replies.count()
            for reply in replies:
                total += count_replies(reply)
            return total

        return count_replies(obj)
    
    def get_likes_count(self, obj):
        return obj.likes.distinct().count() 

    def get_is_liked_by_user(self, obj):
        request = self.context.get('request', None)
        if request and request.user.is_authenticated:
            return obj.likes.filter(user=request.user.profile).exists()
        return False
    

class CreateCommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = VideoComment
        fields = ('user','video','content','parent')
        
class SubscriptionActivationSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscribeCourse
        fields = ('is_active',)