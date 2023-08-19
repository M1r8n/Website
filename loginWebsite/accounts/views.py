from django.shortcuts import render, redirect
from .forms import UserForm, LoginForm, PasswordResetForm, PasswordResetForm2
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from .models import Users
from django.utils.http import urlsafe_base64_decode
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator


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
            user = authenticate(request,username=form.cleaned_data["username"], password=form.cleaned_data["password"])
            if user is not None:
                login(request, user)
                return redirect('userpage')
            else:
                raise ValueError("Incorrect username and/or password")
        else:
            context = {
                'form': form,
            }
    return render(request,'login.html', context)

#TODO logowanie wywolania wylogowania
@login_required
def userlogout(request):
    logout(request)
    return redirect('index')

def resetsent(request):
    return render(request,'passwordresetdone.html',{})
def resetfailure(request):
    return render(request,'resetsendfail.html',{})
#TODO logowanie wywolania
def resetpassword(request):
    if request.method == "POST":
        form=PasswordResetForm(request.POST)
        if form.is_valid():
            try:
                user=Users.objects.get(email=form.cleaned_data["email"])
                user.resetpassword(request)
            except Users.DoesNotExist:
                pass
            except Exception as e:
                return redirect('resetsentfailure')
            return redirect('resetsent')
    return render(request,'passwordresetform.html', {'form': PasswordResetForm()})

#TODO dodanie do historii haseł, sprawdzanie w historii haseł, dodanie do logów informacji
def passwordconfirm(request,uidb64=None,token=None,*args, **kwargs):
    if request.method=='POST':
        form=PasswordResetForm2(request.POST)
        if form.is_valid():
            try:
                uid = urlsafe_base64_decode(uidb64)
                user = Users.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, Users.DoesNotExist):
                user = None
            if user is not None and default_token_generator.check_token(user, token):
                    user.set_password(form.cleaned_data['password'])
                    user.save()
                    messages.success(request, 'Your password has been modified')
                    return redirect('login')
            else:
                messages.error(request, 'Your password has not been modified')
    return render(request,'passwordresetconfirm.html', {'form': PasswordResetForm2(), 'validlink': True})

#TODO blokowanie logowania po n probach
#TODO reset hasła po okreslonym czasie
