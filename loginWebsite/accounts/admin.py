from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Logs,Activity
# Register your models here.

admin.site.register(Logs)
admin.site.register(Activity)