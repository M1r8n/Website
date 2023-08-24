from django.shortcuts import render, redirect
from .forms import UserForm, LoginForm, PasswordResetForm, PasswordResetForm2,UserPasswordHistory
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from .models import Users,Logs,Activity
from django.utils.http import urlsafe_base64_decode
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
from .forms import PasswordAlreadyUsedError
from .models import BlockedUser
from django.utils import timezone
from datetime import timedelta
def signup(request):
    if request.user.is_authenticated:
        return redirect('userpage')
    if request.method == 'POST':
        formUser=UserForm(request.POST)
        if formUser.is_valid():
            formUser.save()
            return redirect('index')
        else:
            context = {
                'form': formUser,
            }
    else:
        context = {
            'form': UserForm(),
        }
    return render(request ,'signup.html',context)

def userlogin(request):
    if request.user.is_authenticated:
        return redirect('userpage')
    context = {
        'form': LoginForm(),
    }
    if request.method=='POST':
        form=LoginForm(request.POST)
        if form.is_valid():
            try:
                user=Users.objects.get(username=form.cleaned_data["username"])
                blockedUser=BlockedUser.objects.get(user=user)
            except (Users.DoesNotExist, BlockedUser.DoesNotExist):
                pass
            else:
                if blockedUser.time + timedelta(minutes=1) > timezone.now():
                    messages.error(request,"User is blocked temporarily, try again later")
                    return render(request,'login.html', context)
                else:
                    blockedUser.delete()
            if user.password_change_date<timezone.now():
                    messages.error(request,"Password expired use forgot password to reset password")
                    return render(request,'login.html', context)
            user : Users = authenticate(request,username=form.cleaned_data["username"], password=form.cleaned_data["password"])
            if user is not None:
                user.counter = 0
                user.save()
                login(request, user)
                log = Logs(acivity=Activity.objects.get(activityName="userloggedin"),user=user)
                log.save()
                if user.password_change_date-timedelta(days=5)<timezone.now():
                    wynik=user.password_change_date-timezone.now()
                    messages.error(request,f"Zresetuj swoje hasło, bedzie wazne jeszcze przez {wynik.days} dni {wynik.seconds//3600} godziny")
                #if data hasła przeterminowana to przekeruj do re
                querry = Activity.objects.all()
                return redirect('userpage')
            else:
                try:
                    usercheck :Users = Users.objects.get(username=form.cleaned_data["username"])
                    if usercheck is not None:
                        usercheck.counter+=1
                        if usercheck.counter>3:
                            usercheck.counter=0
                            blocked = BlockedUser(user=usercheck)
                            blocked.save()
                        usercheck.save()
                except Users.DoesNotExist:
                    pass
                messages.error(request,"Incorrect password or username")
        else:
            context = {
                'form': form,
            }
    return render(request,'login.html', context)

@login_required
def userlogout(request):
    log = Logs(acivity=Activity.objects.get(activityName="userloggedout"), user=request.user)
    log.save()
    logout(request)
    return redirect('index')

def resetsent(request):
    return render(request,'passwordresetdone.html',{})
def resetfailure(request):
    return render(request,'resetsendfail.html',{})
def resetpassword(request):
    if request.user.is_authenticated:
        return redirect('asd')
    if request.method == "POST":
        form=PasswordResetForm(request.POST)
        if form.is_valid():
            try:
                user=Users.objects.get(email=form.cleaned_data["email"])
                user.resetpassword(request)
                log = Logs(acivity=Activity.objects.get(activityName="uservalidationlinkrequest"), user=user)
                log.save()
            except Users.DoesNotExist:
                pass
            except Exception as e:
                return redirect('resetsentfailure')
            return redirect('resetsent')
    return render(request,'passwordresetform.html', {'form': PasswordResetForm()})

#TODO zablokowanie cofania z linku
def passwordconfirm(request,uidb64=None,token=None,*args, **kwargs):
    if request.user.is_authenticated:
        user=request.user
        tokenFlag=True
    else:
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = Users.objects.get(pk=uid)
            tokenFlag=default_token_generator.check_token(user, token)
        except (TypeError, ValueError, OverflowError, Users.DoesNotExist):
            user = None
            tokenFlag=None

    if request.method=='POST':
        form=PasswordResetForm2(request.POST)
        form2=UserPasswordHistory(user,request.POST)
        try:
            if form.is_valid() and form2.is_valid():
                if user is not None and tokenFlag:
                        user.set_password(form.cleaned_data['password'])
                        user.password_change_date=timezone.now()+timedelta(days=30)
                        user.save()
                        log = Logs(acivity=Activity.objects.get(activityName="userpasswordreset"), user=user)
                        log.save()
                        messages.success(request, 'Your password has been modified')
                        return redirect('login')
                else:
                    if tokenFlag is not None:
                        messages.error(request, 'Your password has not been modified, token expired')
        except PasswordAlreadyUsedError:
            messages.error(request, 'Your password has already been used')
    return render(request,'passwordresetconfirm.html', {'form': PasswordResetForm2(), 'validlink': True})
