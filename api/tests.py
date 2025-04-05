from django.test import TestCase
import cloudinary
import cloudinary.uploader

print("تهيئة Cloudinary...")
cloudinary.config( 
  cloud_name = 'drri0et21',
  api_key = '435676498228376',
  api_secret = 'CanY83y8alvsrNNMn29YtF21hlU',
  secure = True
)

print("جرب رفع ملف اختبار...")
try:
    result = cloudinary.uploader.upload(
        "https://res.cloudinary.com/demo/image/upload/fiverr.png.jpg",
        folder="test_connection"
    )
    print("تم الرفع بنجاح! الرابط:", result['url'])
except Exception as e:
    print("فشل الرفع:", str(e))