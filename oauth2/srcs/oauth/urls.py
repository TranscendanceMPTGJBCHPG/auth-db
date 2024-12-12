from django.urls import path
from .auth_views import oauth_login, verify_2fa, authfortytwo
from .get_token_views import gettoken, get_guest_token
from .user_data_views import get_user_win_counter, get_user_goal_counter, increment_user_win_counter, increment_user_goal_counter, reset

urlpatterns = [
    ############################ AUTH ###########################
    path('oauth/', oauth_login, name='oauth'),
    path('authfortytwo/', authfortytwo, name='authfortytwo'),
    path('2fa/', verify_2fa, name='2fa'),
    ######################### GET TOKEN #########################
    path('gettoken/', gettoken, name='gettoken'),
    path('getguesttoken/', get_guest_token, name='getguesttoken'),
    ######################### USER DATA #########################
    path('getuserwincounter/', get_user_win_counter, name='getuserwincounter'),
    path('getusergoalcounter/', get_user_goal_counter, name='getusergoalcounter'),
    path('incrementuserwincounter/', increment_user_win_counter, name='incrementuserwincounter'),
    path('incrementusergoalcounter/', increment_user_goal_counter, name='incrementusergoalcounter'),
    path('reset/', reset, name='reset')
]
