from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required

def index(request):
    if request.user.is_authenticated:
        return redirect("userpage")
    return render(request,'index.html')

#TODO dodanie wyswietlania tabeli logow uzytkownika,
#TODO dodanie przypomnienia zmiany hasła
@login_required(login_url='login')
def userpage(request):
    return render(request,'userpage.html')
