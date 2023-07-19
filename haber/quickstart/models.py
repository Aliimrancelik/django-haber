from django.conf import settings
from django.db import models
from django.db.models.functions import Cast, TruncSecond
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.forms import DateTimeField, CharField
from django.urls import reverse
from django.utils.text import slugify
from ckeditor.fields import RichTextField
from rest_framework.authtoken.models import Token


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


# Create your models here.
class Haber(models.Model):
    slug = models.SlugField(unique=True, editable=False, max_length=130)
    title = models.CharField(max_length=120, verbose_name="Başlık")
    content = RichTextField(verbose_name="İçerik")
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    publishing_date = models.DateTimeField(verbose_name="Yayımlanma Tarihi", auto_now_add=True)
    view_counter = models.IntegerField(editable=False, default=0)
    category = models.ForeignKey('quickstart.Categorise', verbose_name="Kategori", on_delete=models.CASCADE,
                                 related_name="haber")

    def get_unique_slug(self):
        slug = slugify(self.title.replace('ı', 'i'))
        unique_slug = slug
        counter = 1
        while Haber.objects.filter(slug=unique_slug).exists():
            unique_slug = '{}-{}'.format(slug, counter)
            counter += 1
        return unique_slug

    def save(self, *args, **kwargs):
        self.slug = self.get_unique_slug()
        return super(Haber, self).save(*args, **kwargs)

    class Meta:
        ordering = ['-publishing_date', 'id']


class Categorise(models.Model):
    slug = models.SlugField(unique=True, editable=False, max_length=130)
    title = models.CharField(max_length=120, verbose_name="Başlık")

    def get_unique_slug(self):
        slug = slugify(self.title.replace('ı', 'i'))
        unique_slug = slug
        counter = 1
        while Categorise.objects.filter(slug=unique_slug).exists():
            unique_slug = '{}-{}'.format(slug, counter)
            counter += 1
        return unique_slug

    def save(self, *args, **kwargs):
        self.slug = self.get_unique_slug()
        return super(Categorise, self).save(*args, **kwargs)


class Comment(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    text = models.CharField(max_length=250, verbose_name="Yorum")
    publishing_date = models.DateTimeField(verbose_name="Yayımlanma Tarihi", auto_now_add=True)

    def save(self, *args, **kwargs):
        return super(Categorise, self).save(*args, **kwargs)


class Newsletter(models.Model):
    email = models.EmailField(unique=True)
    join_date = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        return super(Newsletter, self).save(*args, **kwargs)

