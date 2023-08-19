from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser,BaseUserManager
from django.contrib.auth.hashers import make_password
import argon2

class Groups(models.Model):
    groupName = models.CharField(max_length=100)

class UserMenager(BaseUserManager):
    def create_user(self, password=None):
        user = self.model()

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, password):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(password=password)
        user.is_admin = True
        user.save(using=self._db)
        return user

class Users(AbstractUser):
    username=models.CharField(max_length=30, unique=True)
    email = models.CharField(max_length=100, unique=True)
    group=models.ForeignKey(Groups,null=True, on_delete=models.SET_NULL)
    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['email']
    is_active = models.BooleanField(default=True)

    objects = UserMenager()

    def check_password(self, raw_password):
        ph = argon2.PasswordHasher()
        try:
            if ph.verify(self.password[6:],raw_password):
                if ph.check_needs_rehash(self.password[6:]):
                    self.set_password(raw_password)
                    self.save()
                return True
        except argon2.exceptions.VerificationError:
            return False
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