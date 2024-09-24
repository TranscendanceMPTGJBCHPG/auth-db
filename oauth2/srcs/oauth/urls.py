from django.urls import path
from .views import oauth_login

urlpatterns = [
    path('oauth/', oauth_login, name='oauth'),
]
