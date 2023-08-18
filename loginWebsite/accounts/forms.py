
from .models import Users
from django.forms import ModelForm, CharField, PasswordInput, ValidationError, Form
import re

class UserForm(ModelForm):
    password2=CharField(widget=PasswordInput)
    class Meta:
        model = Users
        fields = ["username", "mail", "password","password2"]
        widgets = {
            'password': PasswordInput(),
        }

    def clean(self):
        super(UserForm,self).clean()
        username=self.cleaned_data.get("username")
        mail=self.cleaned_data.get("mail")

        if len(username)<3:
            raise ValidationError("User name too short.")
        if len(username)>30:
            raise ValidationError("User name too long.")
        pat = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
        if not re.fullmatch(pat,mail):
            raise ValidationError("Incorect email form.")
        psw1 = self.cleaned_data.get("password")
        psw2 = self.cleaned_data.get("password2")
        pat = re.compile(r'[A-Za-z0-9@#$%^&+=]{8,}')
        if not re.fullmatch(pat, psw1):
            raise ValidationError("Password needs at least 8 sings")
        if psw1 != psw2:
            raise ValidationError("Passwords are different.")
        return self.cleaned_data

class LoginForm(Form):
    username=CharField(max_length=30,required=True, label='username')
    password=CharField(max_length=100,required=True, label='password')
    class Meta:
        model = Users
        fields = ["username", "password"]
        widgets = {
            'password': PasswordInput(),
        }

    def clean(self):
        cleaned_data = super().clean()
        log=cleaned_data["username"]
        psw=cleaned_data["password"]
        if log=="":
            raise ValidationError("No username given")
        if psw=="":
            raise ValidationError("No password given.")
        return cleaned_data
