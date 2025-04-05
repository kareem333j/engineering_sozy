from rest_framework import serializers
from .models import User,Profile
from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from api.models import Course


class UserAllData(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email','user_name','start_date','is_superuser','is_staff','last_login')    
    
# used now
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    full_name = serializers.CharField(required=True, max_length=500) #

    class Meta:
        model = User
        fields = ('id','email','full_name','password', 'password2') #
        extra_kwargs = {'password2': {'write_only': True}}

    def validate_email(self, value):
        print('gggg')
        if User.objects.filter(email=value).exists():
            print('gggg')
            raise serializers.ValidationError("البريد الإلكتروني هذا مستخدم من قبل")
        return value
    
    def validate(self, attrs):
        attrs = super().validate(attrs)
        if attrs['password'] != attrs.pop('password2'):
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        full_name = validated_data.pop('full_name')
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'] 
        )

        user.save()
        user.profile.full_name = full_name
        user.profile.save()
        return user
    
    
class ProfileSerializer(serializers.ModelSerializer):
    avatar = serializers.SerializerMethodField()
    is_superuser = serializers.CharField(source='user.is_superuser',read_only=True)
    is_staff = serializers.CharField(source='user.is_staff',read_only=True)
    email = serializers.CharField(source='user.email',read_only=True)
    start_date = serializers.CharField(source='user.start_date',read_only=True)
    last_login = serializers.CharField(source='user.last_login',read_only=True)
    
    class Meta:
        model = Profile
        fields = ['profile_id','full_name', 'bio','email', 'avatar', 'devices','start_date', 'last_login','is_active', 'is_private','is_superuser','is_staff']
    
    def get_avatar(self, obj):
        request = self.context.get("request")
        if obj.avatar:  
            return request.build_absolute_uri(obj.avatar.url) if request else obj.avatar.url
        return None 
    
class CourseSerializerForProfile(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = ['id', 'title']
    
class ProfileSerializerForMe(serializers.ModelSerializer):
    avatar = serializers.SerializerMethodField()
    is_superuser = serializers.CharField(source='user.is_superuser',read_only=True)
    is_staff = serializers.CharField(source='user.is_staff',read_only=True)
    email = serializers.CharField(source='user.email',read_only=True)
    start_date = serializers.CharField(source='user.start_date',read_only=True)
    last_login = serializers.CharField(source='user.last_login',read_only=True)
    subscribed_courses = serializers.SerializerMethodField()
    
    class Meta:
        model = Profile
        fields = [
            'profile_id', 'full_name', 'bio', 'email', 'avatar', 'devices',
            'start_date', 'last_login', 'is_active', 'is_private',
            'is_superuser', 'is_staff', 'subscribed_courses'
        ]    
    def get_avatar(self, obj):
        request = self.context.get("request")
        if obj.avatar:  
            return request.build_absolute_uri(obj.avatar.url) if request else obj.avatar.url
        return None 
    
    def get_subscribed_courses(self, obj):
        active_subs = obj.subscribed_user.filter(is_active=True).select_related('course')
        courses = [sub.course for sub in active_subs]
        return CourseSerializerForProfile(courses, many=True, context=self.context).data
    
class ProfileSerializerForUpdate(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['avatar',]

class UserPermissionsSerializer(serializers.ModelSerializer):
    is_staff = serializers.BooleanField(source='user.is_staff')
    is_superuser = serializers.BooleanField(source='user.is_superuser')

    class Meta:
        model = Profile
        fields = ['is_active', 'is_staff', 'is_superuser']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        user = instance.user
        if 'is_staff' in user_data:
            user.is_staff = user_data['is_staff']
        if 'is_superuser' in user_data:
            user.is_superuser = user_data['is_superuser']
        
        user.save()
        instance.is_active = validated_data.get('is_active', instance.is_active)
        instance.save()

        return instance

        
class UpdateUserProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email')

    class Meta:
        model = Profile
        fields = ['full_name', 'bio', 'email']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        email = user_data.get('email')

        if email:
            instance.user.email = email
            instance.user.save()

        return super().update(instance, validated_data)
        
class ProfileSerializerSpecific(serializers.ModelSerializer):
    avatar = serializers.SerializerMethodField()
    
    class Meta:
        model = Profile
        fields = ['profile_id', 'avatar','is_private', 'full_name']
        
    def get_avatar(self, obj):
        request = self.context.get("request")
        if obj.avatar:  
            return request.build_absolute_uri(obj.avatar.url) if request else obj.avatar.url
        return None 
    
    
# users for admin
class ProfileSerializerForAdmin(serializers.ModelSerializer):
    avatar = serializers.SerializerMethodField()
    
    class Meta:
        model = Profile
        fields = ['profile_id','full_name', 'bio', 'avatar', 'devices', 'is_active','is_logged_in']
        
    def get_avatar(self, obj):
        request = self.context.get("request")
        if obj.avatar:  
            return request.build_absolute_uri(obj.avatar.url) if request else obj.avatar.url
        return None 
        
class UserSerializerForAdmin(serializers.ModelSerializer):
    profile = ProfileSerializerForAdmin(read_only=True)
    class Meta:
        model = User
        fields = ('email','user_name', 'start_date','is_superuser','is_staff','last_login','profile')