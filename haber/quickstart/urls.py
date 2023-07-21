"""
URL configuration for haber project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.decorators.csrf import csrf_exempt

from . import views

urlpatterns = [
    re_path(r'^authenticate$', views.authentication_request, name="authenticate"),
    re_path(r'^authenticate/register$', views.register_request, name="register"),
    re_path(r'^authenticate/logout', views.logout_request, name="logout"),

    re_path(r'^newsletter/subscribe', views.newsletter_subscribe, name="newsletter_subscribe"),
    re_path(r'^newsletter/unsubscribe', views.newsletter_unsubscribe, name="newsletter_unsubscribe"),

    re_path(r'^category/create', views.category_create, name="category_create"),
    re_path(r'^category/delete', views.category_delete, name="category_delete"),
    re_path(r'^category/list', views.category_list, name="category_list"),

    re_path(r'^post/create', views.post_create, name="post_create"),
    re_path(r'^post/delete', views.post_delete, name="post_delete"),
    re_path(r'^post/list', views.post_list, name="post_list"),
    re_path(r'^post/detail', views.post_detail, name="post_detail"),
    re_path(r'^post/update', views.post_update, name="post_update"),
    re_path(r'^post/status/update', views.post_update_status, name="post_update_status"),
]
