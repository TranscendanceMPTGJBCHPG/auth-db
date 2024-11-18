from django.urls import path
from .views import oauth_login, verify_2fa

urlpatterns = [
    path('oauth/', oauth_login, name='oauth'),
    path('2fa/', verify_2fa, name='2fa'),
]
