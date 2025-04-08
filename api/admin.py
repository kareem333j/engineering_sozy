from django.contrib import admin
from .models import *

admin.site.register(Course)
admin.site.register(Video)
admin.site.register(VideoComment)
admin.site.register(VideoViews)
admin.site.register(VideoLike)
admin.site.register(SubscribeCourse)
admin.site.register(Notification)
admin.site.register(CommentLike)
