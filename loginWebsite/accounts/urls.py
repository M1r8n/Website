from django.urls import path
from .views import signup, userlogin,userlogout
urlpatterns = [
    path('signup/',signup, name='signup'),
    path('login/',userlogin,name='login'),
    path('logout/',userlogout,name='logout')
]
