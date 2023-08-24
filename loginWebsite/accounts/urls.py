from django.urls import path,re_path
from .views import signup, userlogin,userlogout,resetpassword,resetsent,passwordconfirm,resetfailure

urlpatterns = [
    path('signup/',signup, name='signup'),
    path('login/',userlogin,name='login'),
    path('logout/',userlogout,name='logout'),
    path('resetpassword/',resetpassword,name="resetpsw"),
    path('resetsent/',resetsent,name='resetsent'),
    re_path(r'^reset_password_confirm/(?P<uidb64>[0-9A-Za-z]+)/(?P<token>.+)',passwordconfirm, name='passwordconfirm'),
    path('reset_password_confirm/',passwordconfirm,name='asd'),
    path('resetfail/',resetfailure,name='resetsentfailure')
]
