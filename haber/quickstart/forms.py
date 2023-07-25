from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from .models import *


# Create your forms here.

class NewUserForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def save(self, commit=True):
        user = super(NewUserForm, self).save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user


class NewsletterForm(forms.ModelForm):
    class Meta:
        model = Newsletter
        fields = [
            'email'
        ]


class CreateCategoryForm(forms.ModelForm):
    class Meta:
        model = Categorise
        fields = [
            'title',
        ]


class CreatePostForm(forms.ModelForm):
    class Meta:
        model = Haber
        fields = [
            'title',
            'content',
            'category_slug',
            'image',
            'show_status',
        ]


class CreateCommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = [
            "user_name",
            "title",
            "text",
            "post_id",
            "show_status"
        ]
