from django.urls import path
from .views import oauth_login, verify_2fa, reset, authfortytwo, gettoken, getaitoken, getgametoken, verify_token

urlpatterns = [
    path('authfortytwo/', authfortytwo, name='authfortytwo'),
    path('oauth/', oauth_login, name='oauth'),
    path('reset/', reset, name='reset'),
    path('2fa/', verify_2fa, name='2fa'),
    path('gettoken/', gettoken, name='gettoken'),
    path('getaitoken/', getaitoken, name='getaitoken'),
    path('getgametoken/', getgametoken, name='getgametoken'),
    path('verify_token/', verify_token, name='verify_token'),
]
