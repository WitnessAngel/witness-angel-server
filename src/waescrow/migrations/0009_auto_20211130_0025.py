# Generated by Django 2.2.24 on 2021-11-29 23:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('waescrow', '0008_auto_20211129_2327'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authenticatoruser',
            name='description',
            field=models.CharField(max_length=100, unique=True, verbose_name='Identity/role of the key guardian'),
        ),
        migrations.AlterField(
            model_name='authenticatoruser',
            name='username',
            field=models.UUIDField(null=True, verbose_name='keychain uid'),
        ),
    ]