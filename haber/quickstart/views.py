import math

import jwt
from django.contrib.auth.forms import AuthenticationForm
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.db.models import TextField, Q, F
from django.contrib.auth import login, authenticate, logout
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
JWT_authenticator = JWTAuthentication()


from .forms import *
from .models import *

JWT_SECRET_KEY = "SECRET123"


def authenticated_perm(request, r_type=False):
    auth_status, auth_user = check_auth(request)
    if auth_status:
        if auth_user.is_superuser:
            if r_type:
                return auth_status, auth_user
            return True
    if r_type:
        return False, {}
    return False


def check_auth(request):
    try:
        raw_token = request.headers.get('Authorization')
        decoded = jwt.decode(raw_token.replace("Bearer ", ""), JWT_SECRET_KEY, algorithms=["HS256"])
        user = User.objects.get(id=int(decoded.get("user_id")))
        if user:
            return True, user
        else:
            return False, {}
    except:
        return False, {}


def generate_auth_token(user):
    encoded = jwt.encode({'user_id': user.id}, JWT_SECRET_KEY, algorithm="HS256")
    return {
        'acsess': encoded
    }


def get_user_from_id(user_id):
    try:
        user = User.objects.get(id=user_id)
        if user:
            return True, user
        else:
            return False, {}
    except:
        return False, {}


def get_post_with_page(posts, page_max, page):
    paginator = Paginator(posts, page_max)  # Show 5 contacts per page
    try:
        return_categories = paginator.page(page)
    except PageNotAnInteger:
        return_categories = paginator.page(1)
    except EmptyPage:
        return_categories = paginator.page(paginator.num_pages)
    return return_categories


def get_post_total_page(posts, page_max):
    posts_len = len(posts)
    page_max = int(page_max)
    if page_max <= 1:
        page_max = 1
    add_amount = 0
    if (posts_len % page_max) > 0:
        add_amount = 1
    return math.floor(posts_len / page_max) + add_amount


def get_category_from_slug(category_slug):
    try:
        listing = Categorise.objects.get(slug=category_slug)
        if listing:
            return True, listing
    except:
        return False, {}
    return False, {}

def get_post_from_id(post_id):
    try:
        listing = Haber.objects.get(id=post_id)
        if listing:
            return True, listing
    except:
        return False, {}
    return False, {}

def get_comment_from_id(comment_id):
    try:
        listing = Comment.objects.get(id=comment_id)
        if listing:
            return True, listing
    except:
        return False, {}
    return False, {}


def post_return_model(list_post_item, author_name = "", category_info = {"id":0}):
    if category_info.get("id") == 0:
        category_info = {
            "id": 0,
            "slug": "",
            "title": ""
        }
    image_url = ""
    if list_post_item.image and list_post_item.image.url:
        image_url = list_post_item.image.url
    return {
        "id": list_post_item.id,
        "title": list_post_item.title,
        "image": image_url,
        "slug": list_post_item.slug,
        "content": list_post_item.content,
        "category": category_info,
        "publishing_date": list_post_item.publishing_date,
        "view_counter": list_post_item.view_counter,
        "category_slug": list_post_item.category_slug,
        "author": author_name,
        "show_status": list_post_item.show_status
    }


def comment_return_model(list_comment_item, post_info = {"id":0}):
    return {
        "id": list_comment_item.id,
        "user_name": list_comment_item.user_name,
        "title": list_comment_item.title,
        "text": list_comment_item.text,
        "publishing_date": list_comment_item.publishing_date,
        "post_id": list_comment_item.post_id,
        "show_status": list_comment_item.show_status
    }

def build_default_category_info(r_category, d_info=""):
    c_status, c_info = r_category
    category_info = {
        "slug": d_info
    }
    if c_status:
        category_info = {
            "id": c_info.id,
            "title": c_info.title,
            "slug": c_info.slug
        }
    return category_info

def build_default_post_info(r_post, d_info=0):
    c_status, c_info = r_post
    return_info = {
        "id": 0
    }
    if c_status:
        return_info = post_return_model(c_info)
    return return_info


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
                get_token = generate_auth_token(user)
                return JsonResponse({
                    'success': True,
                    'status': 200,
                    'message': 'success',
                    'token': get_token,
                    "is_super": user.is_superuser,
                    "username": user.username,
                    "user_firstname": user.first_name,
                    "user_lastname": user.last_name,
                    "user_email": user.email,
                    "user_lastlogin": user.last_login
                })
            else:
                return JsonResponse({'success': False, 'status': 400, 'message': 'invalid_credentials'})
        else:
            return JsonResponse({'success': False, 'status': 400, 'message': 'invalid_credentials'})
    if request.method == "GET":
        auth_response = check_auth(request)
        try:
            f_status, auth_user = auth_response
            if f_status:
                return JsonResponse({
                    'success': True,
                    'status': 200,
                    'message': 'success',
                    "is_super": auth_user.is_superuser,
                    "username": auth_user.username,
                    "user_firstname": auth_user.first_name,
                    "user_lastname": auth_user.last_name,
                    "user_email": auth_user.email,
                    "user_lastlogin": auth_user.last_login
                })
            else:
                return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'});
        except:
            return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'});
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def category_create(request):
    if request.method == "POST":
        c_status, c_user = check_auth(request)
        if c_status:
            form = CreateCategoryForm(request.POST)
            if form.is_valid():
                form = form.save()
                return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'category_slug': form.slug})
            return JsonResponse({'success': False, 'status': 400, 'message': 'invalid_credentials'})
        return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def category_delete(request):
    if request.method == "POST":
        c_status, c_user = check_auth(request)
        if c_status:
            if request.POST["slug"]:
                listing = Categorise.objects.filter(slug=request.POST["slug"])
                if listing:
                    listing.delete()
                    return JsonResponse({'success': True, 'status': 200, 'message': 'success'})
            return JsonResponse({'success': False, 'status': 400, 'message': 'not_found'})
        return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def category_list(request):
    if request.method == "GET":
        return_categories = []
        listing = Categorise.objects.all()
        for list_item in listing:
            return_categories.append({'id': list_item.id, 'title': list_item.title, 'slug': list_item.slug})
        return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'categories': return_categories})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def post_create(request):
    if request.method == "POST":
        auth_status, auth_user = check_auth(request)
        if auth_status:
            form = CreatePostForm(request.POST or None, request.FILES or None)
            if form.is_valid():
                form = form.save(commit=False)
                category_info = build_default_category_info(get_category_from_slug(form.category_slug), form.category_slug)
                if category_info.get("id"):
                    category_slug = form.category_slug
                    form.user_id = auth_user.id
                    form.save()

                    author_name = request.user.username

                    try:
                        listing = Haber.objects.get(slug=form.slug)
                        if listing:
                            append_item = post_return_model(listing, author_name, category_info)
                            return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'post': append_item})
                    except:
                        ()
                    category_info = build_default_category_info(get_category_from_slug(category_slug), category_slug)
                    append_item = post_return_model(form, author_name, category_info)
                    return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'post': append_item})
                return JsonResponse({'success': False, 'status': 401, 'message': 'category_not_found'})
            return JsonResponse({'success': False, 'status': 400, 'message': 'invalid_credentials'})
        return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def post_delete(request):
    if request.method == "POST":
        auth_status, auth_user = check_auth(request)
        if auth_status:
            if request.POST.get("slug"):
                listing = Haber.objects.filter(slug=request.POST.get("slug"))
                if listing:
                    listing.delete()
                    return JsonResponse({'success': True, 'status': 200, 'message': 'success'})
            return JsonResponse({'success': False, 'status': 400, 'message': 'not_found'})
        return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def post_list(request):
    if request.method == "GET":
        return_posts = []


        query_category = request.GET.get('c')
        category_error = False

        auth_status, auth_user = check_auth(request)
        if auth_status:
            listing = Haber.objects.all()
        else:
            listing = Haber.objects.filter(show_status=True)
        if query_category:
            c_status, c_info = get_category_from_slug(query_category);
            if c_status:
                if auth_status:
                    listing = Haber.objects.filter(category_slug=query_category)
                else:
                    listing = Haber.objects.filter(show_status=True, category_slug=query_category)
            else:
                category_error = True

        query = request.GET.get('q')
        if query:
            if auth_status:
                listing = listing.filter(
                    Q(title__icontains=query) |
                    Q(slug__icontains=query) |
                    Q(content__icontains=query) |
                    Q(category_slug__icontains=query)
                ).distinct()
            else:
                listing = listing.filter(
                    Q(title__icontains=query) |
                    Q(slug__icontains=query) |
                    Q(content__icontains=query) |
                    Q(category_slug__icontains=query) |
                    Q(show_status=True)
                ).distinct()

        page_max = 5
        if request.GET.get("page_max") is not None:
            page_max = request.GET.get("page_max")
        listing_page = get_post_with_page(listing, page_max, request.GET.get('page'))

        for list_post_item in listing_page:
            author_name = ""
            get_status, user_info = get_user_from_id(list_post_item.user_id)
            if get_status:
                author_name = user_info.username

            category_info = build_default_category_info(get_category_from_slug(list_post_item.category_slug), list_post_item.category_slug)
            append_item = post_return_model(list_post_item, author_name, category_info)
            return_posts.append(append_item)
        if category_error:
            return JsonResponse({'success': False, 'status': 401, 'message': 'wrong_category'})
        else:
            return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'total_page': get_post_total_page(listing, page_max), 'posts': return_posts})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def post_detail(request):
    if request.method == "GET":
        r_slug = request.GET.get("slug")
        r_id = request.GET.get("id")
        if r_slug or r_id:
            try:
                if r_id:
                    listing = Haber.objects.get(id=r_id)
                elif r_slug:
                    listing = Haber.objects.get(slug=r_slug)
                if listing:
                    Haber.objects.filter(pk=listing.pk).update(view_counter=F('view_counter') + 1)
                    post_is_superuser = False
                    auth_status, auth_user = check_auth(request)
                    if auth_status:
                        post_is_superuser = True
                    if listing.show_status or post_is_superuser:
                        listing.view_counter += 1

                        author_name = ""
                        get_status, user_info = get_user_from_id(listing.user_id)
                        if get_status:
                            author_name = user_info.username

                        category_info = build_default_category_info(get_category_from_slug(listing.category_slug), listing.category_slug)
                        append_item = post_return_model(listing, author_name, category_info)

                    return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'data': append_item  })
            except:
                return JsonResponse({'success': False, 'status': 400, 'message': 'not_found'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def post_update(request):
    if request.method == "POST":
        auth_status, auth_user = check_auth(request)
        if auth_status:
            r_slug = request.GET.get("slug")
            r_id = request.GET.get("id")
            if r_slug or r_id:
                try:
                    if r_id:
                        listing = Haber.objects.get(id=r_id)
                    elif r_slug:
                        listing = Haber.objects.get(slug=r_slug)
                    if listing:
                        form = CreatePostForm(request.POST or None, request.FILES or None, instance=listing)
                        if form.is_valid():
                            listing = form.save(commit=False)
                            if (listing.category_slug != ""):
                                form.save()
                                author_name = ""
                                get_status, user_info = get_user_from_id(listing.user_id)
                                if get_status:
                                    author_name = user_info.username

                                category_info = build_default_category_info(get_category_from_slug(listing.category_slug), listing.category_slug)
                                append_item = post_return_model(listing, author_name, category_info)

                                return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'data': append_item})
                            else:
                                return JsonResponse({'success': False, 'status': 401, 'message': 'category_not_found'})
                except:
                    return JsonResponse({'success': False, 'status': 400, 'message': 'not_found'})
            return JsonResponse({'success': False, 'status': 400, 'message': 'not_found'})
        return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def post_update_status(request):
    if request.method == "POST":
        auth_status, auth_user = check_auth(request)
        if auth_status:
            r_slug = request.GET.get("slug")
            r_id = request.GET.get("id")
            if r_slug or r_id:
                try:
                    if r_id:
                        listing = Haber.objects.get(id=r_id)
                    elif r_slug:
                        listing = Haber.objects.get(slug=r_slug)
                    if listing:
                        update_status = False
                        if request.POST.get("show_status") == "true" or request.POST.get("show_status") == "True" or request.POST.get("show_status") == True:
                            update_status = True
                        listing.show_status = update_status
                        Haber.objects.filter(id=listing.pk).update(show_status=update_status)
                        author_name = ""
                        get_status, user_info = get_user_from_id(listing.user_id)
                        if get_status:
                            author_name = user_info.username

                        category_info = build_default_category_info(get_category_from_slug(listing.category_slug), listing.category_slug)
                        append_item = post_return_model(listing, author_name, category_info)

                        return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'data': append_item})
                except:
                    return JsonResponse({'success': False, 'status': 400, 'message': 'not_found'})
            return JsonResponse({'success': False, 'status': 400, 'message': 'not_found'})
        return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def register_request(request):
    if request.method == "POST":
        if authenticated_perm(request):
            form = NewUserForm(request.POST)
            if form.is_valid():
                user = form.save()
                login(request, user)
                get_token = Token.objects.get(user=user)
                return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'token': get_token.key})
        return JsonResponse({'success': False, 'status': 401, 'message': 'invalid_credentials'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def logout_request(request):
    logout(request)
    return JsonResponse({'success': True, 'status': 200, 'message': 'success'})


@csrf_exempt
def newsletter_subscribe(request):
    if request.method == "POST":
        form = NewsletterForm(request.POST)
        if form.is_valid():
            form.save()
            return JsonResponse({'success': True, 'status': 200, 'message': "success"})
        else:
            user_email = form['email'].value()
            listing = Newsletter.objects.filter(email=user_email)
            if listing:
                queryset = listing.values(get_datetime=Cast('join_date', TextField())).first()
                return JsonResponse(
                    {'success': True, 'status': 200, 'message': 'already_subscribe',
                     'subscribe_date': queryset['get_datetime']})
        return JsonResponse({'success': False, 'status': 401, 'message': 'invalid_credentials'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def newsletter_unsubscribe(request):
    if request.method == "POST":
        form = NewsletterForm(request.POST)
        user_email = form['email'].value()
        listing = Newsletter.objects.filter(email=user_email)
        if listing:
            listing.delete()
            return JsonResponse({'success': True, 'status': 200, 'message': "success"})
        return JsonResponse({'success': False, 'status': 401, 'message': "invalid_credentials"})
    return JsonResponse({'success': False, 'status': 404, 'message': "invalid_method"})


@csrf_exempt
def comment_create(request):
    if request.method == "POST":
        form = CreateCommentForm(request.POST or None)
        if form.is_valid():
            form = form.save(commit=False)
            post_info = build_default_post_info(get_post_from_id(form.post_id), form.post_id)
            if post_info.get("id") != 0:
                form.save()
                try:
                    listing = Comment.objects.get(id=form.id)
                    if listing:
                        append_item = comment_return_model(listing)
                        return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'post': append_item})
                except:
                    ()
                append_item = comment_return_model(form)
                return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'post': append_item})
            return JsonResponse({'success': False, 'status': 401, 'message': 'post_not_found'})
        return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def comment_delete(request):
    if request.method == "DELETE":
        auth_status, auth_user = check_auth(request)
        if auth_status:
            if request.GET.get("comment_id"):
                listing = Comment.objects.filter(id=request.GET.get("comment_id"))
                if listing:
                    listing.delete()
                    return JsonResponse({'success': True, 'status': 200, 'message': 'success'})
            return JsonResponse({'success': False, 'status': 400, 'message': 'not_found'})
        return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def comment_list(request):
    if request.method == "GET":
        return_posts = []

        query_post = request.GET.get('post_id')

        auth_status, auth_user = check_auth(request)
        if auth_status:
            if query_post:
                listing = Comment.objects.filter(post_id=query_post)
            else:
                listing = Comment.objects.all()
        else:
            if query_post:
                listing = Comment.objects.filter(show_status=True, post_id=query_post)
            else:
                listing = Comment.objects.filter(show_status=True)

        page_max = 5
        if request.GET.get("page_max") is not None:
            page_max = request.GET.get("page_max")
        listing_page = get_post_with_page(listing, page_max, request.GET.get('page'))

        for list_post_item in listing_page:
            append_item = comment_return_model(list_post_item)
            return_posts.append(append_item)
        return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'total_page': get_post_total_page(listing, page_max), 'posts': return_posts})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def comment_detail(request):
    return ""


@csrf_exempt
def comment_update(request):
    if request.method == "POST":
        auth_status, auth_user = check_auth(request)
        if auth_status:
            r_id = request.GET.get("id")
            if r_id:
                try:
                    listing = Comment.objects.get(id=r_id)
                    if listing:
                        form = CreateCommentForm(request.POST or None, instance=listing)
                        if form.is_valid():
                            listing = form.save(commit=False)
                            if listing.post_id != 0:
                                form.save()

                                append_item = comment_return_model(listing)

                                return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'data': append_item})
                            else:
                                return JsonResponse({'success': False, 'status': 401, 'message': 'category_not_found'})
                except:
                    return JsonResponse({'success': False, 'status': 400, 'message': 'anot_found'})
            return JsonResponse({'success': False, 'status': 400, 'message': 'not_found'})
        return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})


@csrf_exempt
def comment_update_status(request):
    if request.method == "POST":
        auth_status, auth_user = check_auth(request)
        if auth_status:
            r_id = request.GET.get("id")
            if r_id:
                try:
                    listing = Comment.objects.get(id=r_id)
                    if listing:
                        update_status = False
                        if request.POST.get("show_status") == "true" or request.POST.get("show_status") == "True" or request.POST.get("show_status") == True:
                            update_status = True
                        listing.show_status = update_status
                        Comment.objects.filter(id=listing.pk).update(show_status=update_status)

                        append_item = comment_return_model(listing)

                        return JsonResponse({'success': True, 'status': 200, 'message': 'success', 'data': append_item})
                except:
                    return JsonResponse({'success': False, 'status': 400, 'message': 'not_found'})
            return JsonResponse({'success': False, 'status': 400, 'message': 'not_found'})
        return JsonResponse({'success': False, 'status': 403, 'message': 'not_authenticated'})
    return JsonResponse({'success': False, 'status': 404, 'message': 'invalid_method'})
