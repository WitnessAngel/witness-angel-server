# Generated by Django 2.2.24 on 2021-11-23 15:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('watrustee', '0002_authenticatorpublickey'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authenticatoruser',
            name='username',
            field=models.CharField(max_length=128, unique=True, verbose_name='keychain uuid'),
        ),
    ]