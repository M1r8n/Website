from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser

class Groups(models.Model):
    groupName = models.CharField(max_length=100)

class Users(AbstractUser):
    username=models.CharField(max_length=30, unique=True)
    mail = models.CharField(max_length=100)
    group=models.ForeignKey(Groups,null=True, on_delete=models.SET_NULL)
    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'mail'
    REQUIRED_FIELDS = ['mail']
    is_authenticated=True

    def check_password(self, raw_password):
        if self.password==raw_password:
            return True
        return False

class Activity(models.Model):
    activityName=models.CharField(max_length=50)


class BlockedUser(models.Model):
    user=models.ForeignKey(Users,on_delete=models.CASCADE)
    time=models.DateTimeField(default=timezone.now)

class UserIP(models.Model):
    user=models.ForeignKey(Users,on_delete=models.CASCADE)
    addresIP=models.CharField(max_length=16)


class Logs(models.Model):
    user=models.ForeignKey(Users,on_delete=models.CASCADE)
    time=models.DateTimeField(default=timezone.now)
    acivity=models.ForeignKey(Activity,on_delete=models.PROTECT)
    addresIP=models.ForeignKey(UserIP,on_delete=models.PROTECT)


class PasswordArchive(models.Model):
    user=models.ForeignKey(Users,on_delete=models.CASCADE)
    password = models.CharField(max_length=300)
    date = models.DateTimeField(default=timezone.now)