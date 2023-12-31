from django.contrib.auth import authenticate

from .models import Users, PasswordArchive
from django.forms import ModelForm, CharField, PasswordInput, ValidationError, Form
import re
import argon2
class UserForm(ModelForm):
    password2=CharField(widget=PasswordInput)
    class Meta:
        model = Users
        fields = ["username", "email", "password","password2"]
        widgets = {
            'password': PasswordInput(),
        }
    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(UserForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password"])
        print(user)
        passwordarchive = PasswordArchive()
        passwordarchive.user=user
        passwordarchive.password = user.password
        if commit:
            user.save()
            passwordarchive.save()
        return user
    def clean(self):
        super(UserForm,self).clean()
        username=self.cleaned_data.get("username")
        email=self.cleaned_data.get("email")

        if len(username)<3:
            raise ValidationError("User name too short.")
        if len(username)>30:
            raise ValidationError("User name too long.")
        pat = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
        if not re.fullmatch(pat, email):
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
    password=CharField(max_length=100,required=True, label='password', widget=PasswordInput)
    class Meta:
        model = Users
        fields = ["username", "password"]

    def clean(self):
        cleaned_data = super().clean()
        log=cleaned_data["username"]
        psw=cleaned_data["password"]
        if log=="":
            raise ValidationError("No username given")
        if psw=="":
            raise ValidationError("No password given.")
        try:
            user = Users.objects.get(username=log)
        except Users.DoesNotExist:
            raise ValidationError("User doesn't exist.")
        return cleaned_data


class PasswordResetForm(Form):
    email=CharField(max_length=30, required=True, label='email')

    class Meta:
        model = Users
        fields = ['email']

    def clean(self):
        cleaned_data=super().clean()
        if cleaned_data["email"] =="":
            raise ValidationError("No email given")
        pat = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
        if not re.fullmatch(pat, cleaned_data["email"]):
            raise ValidationError("Incorect email form.")
        return cleaned_data

class PasswordResetForm2(Form):
    password = CharField(widget=PasswordInput,label='password')
    password2 = CharField(widget=PasswordInput, label='confirm password')
    class Meta:
        model=Users
        fields=['password','password2']
    def clean(self):
        super(PasswordResetForm2,self).clean()
        psw1 = self.cleaned_data.get("password")
        psw2 = self.cleaned_data.get("password2")
        pat = re.compile(r'[A-Za-z0-9@#$%^&+=]{8,}')
        if not re.fullmatch(pat, psw1):
            raise ValidationError("Password needs at least 8 sings")
        if psw1 != psw2:
            raise ValidationError("Passwords are different.")

        return self.cleaned_data
class PasswordAlreadyUsedError(Exception):
    pass
class UserPasswordHistory(Form):
    password = CharField(widget=PasswordInput, label='password')
    password2 = CharField(widget=PasswordInput, label='confirm password')
    class Meta:
        model=PasswordArchive
        fields = ['password', 'password2']


    def __init__(self,user=None, *args,**kwargs):
        super().__init__(*args,**kwargs)
        self.user: Users = user

    def clean(self):
        cleaned_data = super(UserPasswordHistory, self).clean()
        entry = PasswordArchive(user=self.user,password=self.user.password)
        entry.save()
        try:
            query = PasswordArchive.objects.filter(user=self.user)
            if query.count() > 20:
                record = PasswordArchive.objects.earliest('date')
                record.delete()
        except PasswordArchive.DoesNotExist:
            pass
        else:
            ph = argon2.PasswordHasher()
            for element in query:
                try:
                    if ph.verify(element.password[6:],cleaned_data["password"]):
                        print("haslo bylo juz uzyte2")
                        raise PasswordAlreadyUsedError
                except argon2.exceptions.VerifyMismatchError:
                    pass
        return cleaned_data
