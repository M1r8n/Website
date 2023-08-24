from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser,BaseUserManager,EmptyManager
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from sendgrid import Content

from .settings import SENDGRID_API_KEY
from django.utils.http import urlsafe_base64_encode
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail,To,Email
import argon2

class Groups(models.Model):
    groupName = models.CharField(max_length=100)

class UserMenager(BaseUserManager):
    def create_user(self, password=None):
        user = self.model()

        user.set_password(password)
        user.save(using=self._db)
        user.counter=0
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
    counter=models.IntegerField(default=0)
    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['email']
    is_active = models.BooleanField(default=True)
    password_change_date=models.DateTimeField(default=timezone.now)

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

    def resetpassword(self, request):
        uid = urlsafe_base64_encode(force_bytes(self.pk))  # .decode('utf-8')
        token = default_token_generator.make_token(self)
        domain = "127.0.0.1:8000"
        to_email = To(self.email)
        from_email = Email("psiproject@o2.pl")
        subject = "Password Recovery from website"
        content = Content("text/plain", f"You are receiving this email because of your reset password request.\n"
                                        f"Please go to this page and choose a new password:\n"
                                        f"http://{domain}/accounts/reset_password_confirm/{uid}/{token}")
        print(content.get())
        message = Mail(from_email, to_email, subject, content)
        sg = SendGridAPIClient(api_key=SENDGRID_API_KEY)
        sg.client.mail.send.post(request_body=message.get())

class Activity(models.Model):
    activityName=models.CharField(max_length=50)
    objects=models.Manager()

class BlockedUser(models.Model):
    user=models.ForeignKey(Users,on_delete=models.CASCADE)
    time=models.DateTimeField(default=timezone.now)

    objects=models.Manager()

class UserIP(models.Model):
    user=models.ForeignKey(Users,on_delete=models.CASCADE)
    addresIP=models.CharField(max_length=16)

#TODO add back addresIP to logs
class Logs(models.Model):
    user=models.ForeignKey(Users,on_delete=models.CASCADE, related_name='logs')
    time=models.DateTimeField(default=timezone.now)
    acivity=models.ForeignKey(Activity,on_delete=models.PROTECT, related_name="activty_lookup")
    #addresIP=models.ForeignKey(UserIP,on_delete=models.PROTECT)

    objects=models.Manager()

class PasswordArchive(models.Model):
    user=models.ForeignKey(Users,on_delete=models.CASCADE)
    password = models.CharField(max_length=300)
    date = models.DateTimeField(default=timezone.now)
    USERNAME_FIELD='user'
    objects = models.Manager()

