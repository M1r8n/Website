from django.shortcuts import render, redirect
from .forms import UserForm, LoginForm, PasswordResetForm
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from .models import Users


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

@login_required
def userlogout(request):
    logout(request)
    return redirect('index')

def resetpassword(request):
    if request.method == "POST":
        form=PasswordResetForm(request.POST)
        if form.is_valid():
            user=Users.objects.get(email=form.cleaned_data["email"])

    return render(request,'passwordresetform.html', {'form': PasswordResetForm()})
