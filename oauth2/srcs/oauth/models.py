from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    totp_secret = models.CharField(max_length=32)
    first_login_done = models.BooleanField(default=False)
    win_counter = models.IntegerField(default=0)
    goal_counter = models.IntegerField(default=0)

    class Meta:
        app_label = 'oauth'