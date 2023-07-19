from django.contrib.auth import login
from django.contrib.auth.forms import AuthenticationForm
from django.db.models import TextField
from django.db.models.functions import Cast, TruncSecond
from django.forms import DateTimeField, CharField
from django.shortcuts import render, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token

from .forms import NewUserForm, NewsletterForm
from .models import Newsletter


# Create your views here.
@csrf_exempt
def authentication_request(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                get_token = Token.objects.get(user=user)
                return JsonResponse({'status': 200, 'message': "", "token": get_token.key})
            else:
                return JsonResponse({'status':201, "message": "invalid_credentials"})
        else:
            return JsonResponse({'status':201, "message": "invalid_credentials"})
    if request.method == "GET":
        if request.user.is_authenticated:
            get_token = Token.objects.get(user=request.user)
            return JsonResponse({'status': 200, 'message': "", "token": get_token.key})
        else:
            return JsonResponse({'status': 201, "message": "not_authenticated"});


@csrf_exempt
def register_request(request):
    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            get_token = Token.objects.get(user=user)
            return JsonResponse({'status': 200, 'message': "success", "token": get_token.key})
        return JsonResponse({'status': 201, 'message': "invalid_credentials"})
    return JsonResponse({'status': 404, 'message': "invalid_method"})


@csrf_exempt
def logout_request(request):
    logout(request)
    return JsonResponse({'status': 200, 'message': "success"})


@csrf_exempt
def newsletter_subscribe(request):
    if request.method == "POST":
        form = NewsletterForm(request.POST)
        if form.is_valid():
            form.save()
            return JsonResponse({'status': 200, 'message': "success"})
        else:
            user_email = form['email'].value()
            listing = Newsletter.objects.filter(email=user_email)
            if listing:
                queryset = listing.values(get_datetime=Cast('join_date', TextField())).first()
                return JsonResponse({'status': 200, 'message': "already_subscribe", "subscribe_date": queryset['get_datetime']})
        return JsonResponse({'status': 201, 'message': "invalid_credentials"})
    return JsonResponse({'status': 404, 'message': "invalid_method"})


@csrf_exempt
def newsletter_unsubscribe(request):
    if request.method == "POST":
        form = NewsletterForm(request.POST)
        user_email = form['email'].value()
        listing = Newsletter.objects.filter(email=user_email)
        if listing:
            listing.delete()
            return JsonResponse({'status': 200, 'message': "success"})
        return JsonResponse({'status': 201, 'message': "invalid_credentials"})
    return JsonResponse({'status': 404, 'message': "invalid_method"})