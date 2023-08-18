from django.shortcuts import render, redirect
from .forms import UserForm, LoginForm
from django.contrib.auth import authenticate,login,logout

def signup(request):
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
            context = {
                'form': form,
            }
    return render(request,'login.html', context)

def userlogout(request):
    logout(request)
    return redirect('index')