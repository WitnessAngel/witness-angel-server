# Generated by Django 2.2.24 on 2021-11-24 11:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('watrustee', '0004_auto_20211124_0953'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authenticatoruser',
            name='username',
            field=models.UUIDField(unique=True, verbose_name='keychain uid'),
        ),
    ]
