# Generated by Django 4.2.3 on 2023-07-19 11:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('quickstart', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='haber',
            name='user',
        ),
        migrations.AddField(
            model_name='haber',
            name='user_id',
            field=models.IntegerField(default=0, editable=False),
        ),
    ]
