# Generated by Django 5.2 on 2025-04-05 15:40

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('api', '0001_initial'),
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='commentlike',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='comment_likes', to='users.profile'),
        ),
        migrations.AddField(
            model_name='notification',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_notification', to='users.profile'),
        ),
        migrations.AddField(
            model_name='subscribecourse',
            name='course',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='subscriber', to='api.course'),
        ),
        migrations.AddField(
            model_name='subscribecourse',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='subscribed_user', to='users.profile'),
        ),
        migrations.AddField(
            model_name='video',
            name='author',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='author', to='users.profile'),
        ),
        migrations.AddField(
            model_name='video',
            name='course',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='videos', to='api.course'),
        ),
        migrations.AddField(
            model_name='videocomment',
            name='parent',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='replies', to='api.videocomment'),
        ),
        migrations.AddField(
            model_name='videocomment',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_comment', to='users.profile'),
        ),
        migrations.AddField(
            model_name='videocomment',
            name='video',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='comments', to='api.video'),
        ),
        migrations.AddField(
            model_name='commentlike',
            name='comment',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='likes', to='api.videocomment'),
        ),
        migrations.AddField(
            model_name='videolike',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_video_likes', to='users.profile'),
        ),
        migrations.AddField(
            model_name='videolike',
            name='video',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='likes', to='api.video'),
        ),
        migrations.AddField(
            model_name='videoviews',
            name='video',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='views', to='api.video'),
        ),
        migrations.AlterUniqueTogether(
            name='commentlike',
            unique_together={('user', 'comment')},
        ),
        migrations.AlterUniqueTogether(
            name='videolike',
            unique_together={('video', 'user')},
        ),
    ]
