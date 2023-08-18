from django.urls import path

from .views import index, userpage

urlpatterns = [
    path("", index, name='index'),
    path("userpage/",userpage, name="userpage")
]