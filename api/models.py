from django.db import models
from users.models import Profile

class ActiveObjectsQuerySet(models.QuerySet):
    def active(self):
        return self.filter(is_active=True)

class Course(models.Model):
    class ActiveCourses(models.Manager):
        def get_queryset(self):
            return super().get_queryset().filter(is_active=True)
    
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    cover = models.ImageField(upload_to='courses/covers/', blank=True, null=True)
    created_dt = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    update_dt = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    objects = models.Manager()
    active_objects = ActiveObjectsQuerySet.as_manager()
    
    def __str__(self):
        return self.title

class Video(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='videos')
    embed_code = models.TextField(blank=False, null=False)
    cover = models.ImageField(upload_to='courses/videos/covers/', blank=True, null=True)
    created_dt = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    update_dt = models.DateTimeField(auto_now=True, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    author = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='author')
    
    objects = models.Manager()
    active_objects = ActiveObjectsQuerySet.as_manager()
    
    def __str__(self):
        return self.title
    
class VideoLike(models.Model):
    video = models.ForeignKey(Video, on_delete=models.CASCADE, related_name='likes')
    user = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='user_video_likes')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('video', 'user')  # لمنع المستخدم من الإعجاب بنفس الفيديو أكثر من مرة

    def __str__(self):
        return f"{self.user.full_name} liked {self.video.title}"

class VideoViews(models.Model):
    video = models.OneToOneField(Video, on_delete=models.CASCADE, related_name='views')
    views = models.JSONField(default=list,blank=True)
    
    def __str__(self):
        return self.video.title

class VideoComment(models.Model):
    video = models.ForeignKey(Video, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='user_comment')
    content = models.TextField(blank=False, null=False)
    parent = models.ForeignKey(
        'self', on_delete=models.CASCADE, related_name='replies', null=True, blank=True
    )
    is_active = models.BooleanField(default=True)
    created_dt = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    update_dt = models.DateTimeField(auto_now=True, null=True, blank=True)
    
    objects = models.Manager()
    active_objects = ActiveObjectsQuerySet.as_manager()
    
    class Meta:
        ordering = ['likes','-created_dt']
    def __str__(self):
        if self.parent:
            return f'{self.content} Reply by ({self.user.user.user_name if self.user.user.user_name else self.user.user.email}) on comment ({self.parent.id})'
        return f'{self.content} comment user ({self.user.user.user_name if self.user.user.user_name else self.user.user.email}) on video ({self.video.title})'

class CommentLike(models.Model):
    user = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name="comment_likes")
    comment = models.ForeignKey(VideoComment, on_delete=models.CASCADE, related_name="likes")
    created_dt = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'comment')
        ordering = ['-created_dt']

    def __str__(self):
        return f"{self.user} liked comment {self.comment.id}"
    

class SubscribeCourse(models.Model):
    user = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='subscribed_user')
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='subscriber')
    is_active = models.BooleanField(default=True)
    created_dt = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    
    objects = models.Manager()
    active_objects = ActiveObjectsQuerySet.as_manager()
    
    def __str__(self):
        return f'{self.user.user.user_name if self.user.user.user_name else self.user.user.email} subscribed to {self.course.title}'


class Notification(models.Model):
    user = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='user_notification')
    content = models.TextField(blank=True, null=True)
    created_dt = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    seen = models.BooleanField(default=False)
    
    objects = models.Manager()
    active_objects = ActiveObjectsQuerySet.as_manager()
    
    def __str__(self):
        return f'{self.user.user.user_name if self.user.user.user_name else self.user.user.email} notification'